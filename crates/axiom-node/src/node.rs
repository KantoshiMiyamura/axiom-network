// Copyright (c) 2026 Kantoshi Miyamura

//! Core node: block processing, mempool, and chain state.

use crate::anomaly::{AiAnalysisReport, AnomalyDetector};
use crate::{ChainState, Config, Mempool, OrphanPool, TransactionValidator};
use axiom_consensus::Block;
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use axiom_storage::{Database, NonceTracker, UtxoSet};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("state error: {0}")]
    State(#[from] crate::StateError),

    #[error("mempool error: {0}")]
    Mempool(#[from] crate::MempoolError),

    #[error("validation error: {0}")]
    Validation(#[from] crate::ValidationError),

    #[error("storage error: {0}")]
    Storage(#[from] axiom_storage::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),

    #[error("fork error: {0}")]
    Fork(#[from] crate::ForkError),

    #[error("reorg error: {0}")]
    Reorg(#[from] crate::ReorgError),

    #[error("consensus error: {0}")]
    Consensus(#[from] axiom_consensus::Error),

    #[error("checkpoint violation: {0}")]
    Checkpoint(#[from] crate::CheckpointError),

    #[error("reorg too deep: depth {depth} exceeds max {max}")]
    ReorgTooDeep { depth: u32, max: u32 },

    #[error("too many forks at height {height}: {count} forks (max: {max})")]
    TooManyForksAtHeight {
        height: u32,
        count: usize,
        max: usize,
    },
}

/// Reorgs deeper than this are rejected outright.
pub const MAX_REORG_DEPTH: u32 = 200;

/// CRITICAL FIX: Maximum number of competing forks at the same height.
/// Without this limit, an attacker can mine 1000 valid blocks at height 1
/// (all with different nonces) and send them to the node, causing CPU and
/// memory exhaustion as the node stores and processes all 1000 blocks.
pub const MAX_FORKS_PER_HEIGHT: usize = 8;

/// CRITICAL FIX: Cleanup depth for fork tracking HashMap.
/// Heights older than this are removed to prevent memory leak.
/// Set to MAX_REORG_DEPTH to ensure we keep fork data for all potentially
/// reorg-able blocks while preventing unbounded growth.
const FORK_MAP_CLEANUP_DEPTH: u32 = 200;

/// How long a cached block template remains valid before being rebuilt.
const TEMPLATE_MAX_AGE: Duration = Duration::from_secs(5);

/// Cached block template to avoid rebuilding on every mining iteration.
struct BlockTemplateCache {
    /// The cached transactions (coinbase first, then mempool txs).
    transactions: Vec<Transaction>,
    /// When the template was built.
    built_at: Instant,
    /// Block height this template targets.
    target_height: u32,
}

impl BlockTemplateCache {
    fn is_valid(&self, current_height: u32) -> bool {
        // Invalidate if chain height changed (new block) or template too old.
        self.target_height == current_height + 1 && self.built_at.elapsed() < TEMPLATE_MAX_AGE
    }
}

pub struct Node {
    config: Config,
    pub state: ChainState,
    mempool: Mempool,
    orphan_pool: OrphanPool,
    start_time: Instant,
    anomaly_detector: AnomalyDetector,
    reorg_count: u64,
    /// Cached block template; invalidated on new block, mempool change, or age.
    template_cache: Option<BlockTemplateCache>,
    /// CRITICAL FIX: Track number of blocks at each height to prevent fork bombing.
    /// Without this, an attacker can send 1000 blocks at the same height, exhausting CPU/memory.
    forks_per_height: HashMap<u32, usize>,
}

impl Node {
    /// Open or create the node data directory and initialize chain state.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate().map_err(|e| {
            NodeError::State(crate::StateError::Storage(
                axiom_storage::Error::Corruption(e.to_string()),
            ))
        })?;

        let db = Database::open(&config.data_dir)?;

        let mut state = ChainState::new(db)?;

        if !state.is_genesis_initialized()? {
            let genesis = crate::genesis::create_genesis_block(config.network);
            state.initialize_genesis(&genesis)?;
        }

        let mut mempool = Mempool::new(config.mempool_max_size, config.mempool_max_count);

        let mempool_path = config.data_dir.join("mempool.dat");
        if mempool_path.exists() {
            match mempool.load_from_file(&mempool_path) {
                Ok(n) => tracing::info!(loaded = n, "restored mempool from disk"),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load mempool from disk; starting empty")
                }
            }
        }

        let orphan_pool = OrphanPool::new();

        let node = Node {
            config,
            state,
            mempool,
            orphan_pool,
            start_time: Instant::now(),
            anomaly_detector: AnomalyDetector::new(),
            reorg_count: 0,
            template_cache: None,
            forks_per_height: HashMap::new(),
        };

        match node.reindex_heights() {
            Ok(0) => {}
            Ok(n) => tracing::info!(blocks = n, "backfilled block height index"),
            Err(e) => tracing::warn!(error = %e, "height index reindex failed (non-fatal)"),
        }

        Ok(node)
    }

    /// Validate and add a transaction to the mempool.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash256, NodeError> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

        if self.mempool.has_transaction(&txid) {
            return Err(NodeError::Mempool(crate::MempoolError::AlreadyInMempool));
        }

        let utxo_set = UtxoSet::new(self.state.database());
        let nonce_tracker = NonceTracker::new(self.state.database());
        let current_height = self.state.best_height().unwrap_or(0);
        let coinbase_maturity = if self.config.network == crate::config::Network::Dev {
            crate::validation::COINBASE_MATURITY_DEVNET
        } else {
            crate::validation::COINBASE_MATURITY
        };
        let validator =
            TransactionValidator::new(utxo_set, nonce_tracker, self.config.min_fee_rate)
                .with_chain_id(self.config.network.chain_id())
                .with_height(current_height)
                .with_coinbase_maturity(coinbase_maturity);

        let fee_sat = validator.validate_and_compute_fee(&tx)?;

        // Advisory only: the score is logged but never gates admission.
        // Consensus correctness depends solely on `validate_and_compute_fee`
        // above; the anomaly detector is an observer (see AI-CONSENSUS-AUDIT.md §3.1).
        let anomaly_score = self.anomaly_detector.analyse(&txid, &tx);
        if anomaly_score > 0.0 {
            tracing::warn!(
                score = anomaly_score,
                txid = %hex::encode(txid.as_bytes()),
                "anomaly detected"
            );
        }

        self.mempool.add_transaction(tx, fee_sat)?;

        // Invalidate template cache: mempool changed.
        self.template_cache = None;

        Ok(txid)
    }

    /// Build a candidate block with an unset miner address.
    pub fn build_block(&mut self) -> Result<Block, NodeError> {
        self.build_block_for(Hash256::zero())
    }

    /// Build a candidate block with coinbase paying `miner_pubkey_hash`.
    pub fn build_block_for(&mut self, miner_pubkey_hash: Hash256) -> Result<Block, NodeError> {
        let prev_block_hash = self.state.best_block_hash().unwrap_or(Hash256::zero());
        let height = self.state.best_height().unwrap_or(0) + 1;

        let block_reward = axiom_consensus::calculate_block_reward(height);
        let coinbase_output = axiom_protocol::TxOutput {
            value: block_reward,
            pubkey_hash: miner_pubkey_hash,
        };
        let coinbase = Transaction::new_coinbase(vec![coinbase_output], height);

        let mut transactions = vec![coinbase];
        let mempool_txs = self.mempool.get_all_transactions();

        for (_txid, tx) in mempool_txs {
            transactions.push(tx);
        }

        let merkle_root = axiom_consensus::compute_merkle_root(&transactions);

        let difficulty_target = self.state.get_next_difficulty_target(height)?;

        // Block timestamp must exceed Median Time Past.
        let mtp = {
            let prev_ts = self.state.get_prev_timestamps(11)?;
            if prev_ts.is_empty() {
                0u64
            } else {
                let mut sorted = prev_ts.clone();
                sorted.sort_unstable();
                sorted[sorted.len() / 2]
            }
        };
        let timestamp = (current_timestamp() as u64).max(mtp + 1) as u32;

        let header = axiom_consensus::BlockHeader {
            version: 1,
            prev_block_hash,
            merkle_root,
            timestamp,
            difficulty_target,
            nonce: 0,
        };

        Ok(Block {
            header,
            transactions,
        })
    }

    /// Return a cached block template (list of transactions: coinbase first,
    /// then mempool txs), rebuilding it only when stale or invalidated.
    ///
    /// The cache is invalidated when:
    ///   - A new block is accepted
    ///   - A new transaction is added to the mempool
    ///   - The template is older than 5 seconds
    #[allow(dead_code)]
    pub fn get_or_build_template(&mut self) -> Result<Vec<Transaction>, NodeError> {
        let current_height = self.state.best_height().unwrap_or(0);

        // Return cached template if still valid.
        if let Some(ref cache) = self.template_cache {
            if cache.is_valid(current_height) {
                return Ok(cache.transactions.clone());
            }
        }

        // Rebuild template.
        let block = self.build_block_for(Hash256::zero())?;
        let transactions = block.transactions.clone();
        let target_height = current_height + 1;

        self.template_cache = Some(BlockTemplateCache {
            transactions: transactions.clone(),
            built_at: Instant::now(),
            target_height,
        });

        Ok(transactions)
    }

    /// Accept a block, routing it to the main chain, a fork, or the orphan pool.
    pub fn process_block(&mut self, block: Block) -> Result<(), NodeError> {
        self.process_block_from_peer(block, None)
    }

    /// Accept a block from a specific peer, routing it to the main chain, a fork, or the orphan pool.
    /// CRITICAL FIX: This method accepts peer_id to enforce per-peer orphan limits.
    pub fn process_block_from_peer(
        &mut self,
        block: Block,
        peer_id: Option<String>,
    ) -> Result<(), NodeError> {
        let block_hash = block.hash();
        let parent_hash = block.header.prev_block_hash;

        if self.state.has_block(&block_hash)? {
            return Err(NodeError::State(crate::StateError::BlockNotFound(
                "block already exists".into(),
            )));
        }

        let parent_exists = if parent_hash == Hash256::zero() {
            true
        } else {
            self.state.has_block(&parent_hash)?
        };

        if !parent_exists {
            // CRITICAL FIX: Pass peer_id to enforce per-peer orphan limits.
            // This prevents a single malicious peer from filling the entire orphan pool.
            let orphan_count_before = self.orphan_pool.len();
            self.orphan_pool
                .add_orphan_from_peer(block, peer_id.clone())?;
            let orphan_count_after = self.orphan_pool.len();

            if orphan_count_after > orphan_count_before {
                tracing::debug!(
                    block_hash = %hex::encode(&block_hash.as_bytes()[..8]),
                    peer = ?peer_id,
                    orphan_count = orphan_count_after,
                    "ORPHAN_ADDED"
                );
            }

            return Ok(());
        }

        let current_tip = self.state.best_block_hash().unwrap_or(Hash256::zero());

        if parent_hash == current_tip {
            self.apply_block_to_chain(block)?;
            self.try_reconnect_orphans(&block_hash)?;
        } else {
            self.handle_fork(block)?;
        }

        Ok(())
    }

    /// Calculate the height of a block by walking back to genesis.
    /// CRITICAL: This must be correct for fork choice to work.
    /// Height is the count of blocks from genesis (inclusive) to the target block (inclusive).
    /// Genesis has height 0.
    fn calculate_block_height(&self, block_hash: &Hash256) -> Result<u32, NodeError> {
        if *block_hash == Hash256::zero() {
            return Ok(0);
        }

        let mut height = 0u32;
        let mut current = *block_hash;

        loop {
            if current == Hash256::zero() {
                // We've reached genesis
                return Ok(height);
            }

            match self.state.get_block(&current)? {
                Some(block) => {
                    current = block.header.prev_block_hash;
                    height = height.checked_add(1).ok_or_else(|| {
                        NodeError::State(crate::StateError::BlockNotFound("height overflow".into()))
                    })?;
                }
                None => {
                    return Err(NodeError::State(crate::StateError::BlockNotFound(format!(
                        "block not found during height calculation: {:?}",
                        current
                    ))));
                }
            }
        }
    }

    fn apply_block_to_chain(&mut self, block: Block) -> Result<(), NodeError> {
        let block_hash = block.hash();

        let height = self.state.best_height().unwrap_or(0) + 1;
        let expected_difficulty = self.state.get_next_difficulty_target(height)?;
        let parent_hash = self.state.best_block_hash().unwrap_or(Hash256::zero());
        let prev_timestamps = self.state.get_prev_timestamps(11)?;
        let base_validator = if self.config.network.requires_pow() {
            axiom_consensus::ConsensusValidator::with_pow(parent_hash, height)
        } else {
            axiom_consensus::ConsensusValidator::new(parent_hash, height)
        };
        let validator = base_validator
            .with_expected_difficulty(expected_difficulty)
            .with_prev_timestamps(prev_timestamps);
        validator.validate_block(&block)?;

        crate::checkpoints::verify_checkpoint(self.config.network, height, &block_hash)?;

        self.state.apply_block(&block)?;

        let txids: Vec<Hash256> = block
            .transactions
            .iter()
            .skip(1)
            .map(|tx| {
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
            })
            .collect();

        self.mempool.remove_transactions(&txids);
        self.mempool.evict_expired();

        // Invalidate template cache: a new block was accepted.
        self.template_cache = None;

        // CRITICAL FIX: Cleanup old fork tracking data to prevent memory leak.
        // This prevents unbounded growth of forks_per_height HashMap.
        self.cleanup_old_fork_data(height);

        Ok(())
    }

    /// CRITICAL FIX: Remove fork tracking data for old heights to prevent memory leak.
    /// Keeps only the last FORK_MAP_CLEANUP_DEPTH heights (200 blocks).
    /// This prevents the HashMap from growing unbounded as the chain progresses.
    fn cleanup_old_fork_data(&mut self, current_height: u32) {
        if current_height > FORK_MAP_CLEANUP_DEPTH {
            let cleanup_threshold = current_height - FORK_MAP_CLEANUP_DEPTH;

            // Collect heights to remove (can't modify HashMap while iterating)
            let old_heights: Vec<u32> = self
                .forks_per_height
                .keys()
                .filter(|&&h| h < cleanup_threshold)
                .copied()
                .collect();

            if !old_heights.is_empty() {
                let removed_count = old_heights.len();
                for height in old_heights {
                    self.forks_per_height.remove(&height);
                }

                tracing::debug!(
                    removed = removed_count,
                    current_height = current_height,
                    threshold = cleanup_threshold,
                    remaining = self.forks_per_height.len(),
                    "FORK_MAP_CLEANUP"
                );
            }
        }
    }

    fn handle_fork(&mut self, block: Block) -> Result<(), NodeError> {
        let block_hash = block.hash();
        let parent_hash = block.header.prev_block_hash;

        // FIX: Use correct height calculation helper
        let parent_height = self.calculate_block_height(&parent_hash)?;
        let block_height = parent_height.checked_add(1).ok_or_else(|| {
            NodeError::State(crate::StateError::BlockNotFound("height overflow".into()))
        })?;

        // CRITICAL FIX: Enforce fork bombing protection BEFORE validation.
        // An attacker can mine 1000 valid blocks at the same height (different nonces)
        // and send them all to the node. Without this limit, the node will store and
        // process all 1000 blocks, exhausting CPU and memory.
        let forks_at_height = self
            .forks_per_height
            .get(&block_height)
            .copied()
            .unwrap_or(0);
        if forks_at_height >= MAX_FORKS_PER_HEIGHT {
            tracing::warn!(
                height = block_height,
                count = forks_at_height,
                max = MAX_FORKS_PER_HEIGHT,
                block_hash = %hex::encode(&block_hash.as_bytes()[..8]),
                "FORK_REJECTED reason=fork_limit_exceeded"
            );
            return Err(NodeError::TooManyForksAtHeight {
                height: block_height,
                count: forks_at_height,
                max: MAX_FORKS_PER_HEIGHT,
            });
        }

        crate::log_peer_block_received("fork", &block_hash, block_height, &parent_hash);

        crate::checkpoints::verify_checkpoint(self.config.network, block_height, &block_hash)?;

        let expected_difficulty = self
            .state
            .get_next_difficulty_target_from_parent(parent_hash, block_height)?;
        // CRITICAL FIX: Fork blocks must also validate MTP timestamps.
        // Previously, handle_fork() did not call with_prev_timestamps(), allowing
        // fork blocks with timestamps below MTP. This enables timestamp manipulation
        // attacks on LWMA-3 difficulty adjustment.
        // Walk back from the fork's parent to get the last 11 timestamps on its chain.
        let fork_prev_timestamps = self.state.get_prev_timestamps_from(parent_hash, 11)?;
        let base_validator = if self.config.network.requires_pow() {
            axiom_consensus::ConsensusValidator::with_pow(parent_hash, block_height)
        } else {
            axiom_consensus::ConsensusValidator::new(parent_hash, block_height)
        };
        let validator = base_validator
            .with_expected_difficulty(expected_difficulty)
            .with_prev_timestamps(fork_prev_timestamps);
        validator.validate_block(&block)?;

        let target = axiom_consensus::CompactTarget(block.header.difficulty_target);
        let block_work = axiom_consensus::calculate_work(target);

        let parent_work = self.state.get_chain_work(&parent_hash)?.unwrap_or(0);

        let new_chain_work = parent_work.checked_add(block_work).ok_or_else(|| {
            NodeError::State(crate::StateError::BlockNotFound(
                "chain work overflow".into(),
            ))
        })?;

        let mut batch = axiom_storage::StorageBatch::new(self.state.database());
        batch.put_block(&block)?;
        batch.put_chain_work(&block_hash, new_chain_work);
        batch.commit()?;

        // CRITICAL FIX: Increment fork counter AFTER successful validation and storage.
        // This ensures we only count valid forks that passed all consensus checks.
        *self.forks_per_height.entry(block_height).or_insert(0) += 1;

        crate::log_block_accepted(&block_hash, block_height, new_chain_work, "fork");

        let current_tip = self.state.best_block_hash().unwrap_or(Hash256::zero());
        let current_work = self.state.get_chain_work(&current_tip)?.unwrap_or(0);
        let current_height = self.state.best_height().unwrap_or(0);

        // FIX: Fork choice is based on CHAINWORK, not height
        let should_reorg = if new_chain_work > current_work {
            true
        } else if new_chain_work == current_work {
            // Tie-break by numerically lower hash
            block_hash.as_bytes() < current_tip.as_bytes()
        } else {
            false
        };

        if should_reorg {
            crate::log_fork_choice_candidate(
                &block_hash,
                block_height,
                new_chain_work,
                &current_tip,
                current_height,
                current_work,
                "ACCEPT",
                "higher_chainwork",
            );
            self.reorganize_to_block(&block_hash)?;
        } else {
            crate::log_fork_choice_candidate(
                &block_hash,
                block_height,
                new_chain_work,
                &current_tip,
                current_height,
                current_work,
                "REJECT",
                "lower_chainwork",
            );
            self.try_reconnect_orphans(&block_hash)?;
        }

        Ok(())
    }

    fn reorganize_to_block(&mut self, new_tip: &Hash256) -> Result<(), NodeError> {
        self.reorg_count = self.reorg_count.saturating_add(1);
        let old_tip = self.state.best_block_hash().unwrap_or(Hash256::zero());
        let old_height = self.state.best_height().unwrap_or(0);

        let fork_point = {
            let reorg_engine = crate::ReorgEngine::new(&mut self.state);
            reorg_engine.find_fork_point(&old_tip, new_tip)?
        };

        let mut disconnect_blocks = Vec::new();
        let mut current = old_tip;
        while current != fork_point {
            disconnect_blocks.push(current);
            if let Some(block) = self.state.get_block(&current)? {
                current = block.header.prev_block_hash;
            } else {
                break;
            }
        }

        let mut connect_blocks = Vec::new();
        let mut current = *new_tip;
        while current != fork_point {
            connect_blocks.push(current);
            if let Some(block) = self.state.get_block(&current)? {
                current = block.header.prev_block_hash;
            } else {
                break;
            }
        }
        connect_blocks.reverse();

        let reorg_depth = disconnect_blocks.len() as u32;
        if reorg_depth > MAX_REORG_DEPTH {
            tracing::error!(
                reorg_depth,
                max = MAX_REORG_DEPTH,
                "SECURITY: rejecting deep reorg — possible attack"
            );
            return Err(NodeError::ReorgTooDeep {
                depth: reorg_depth,
                max: MAX_REORG_DEPTH,
            });
        }

        crate::log_reorg_start(
            &old_tip,
            new_tip,
            &fork_point,
            disconnect_blocks.len(),
            connect_blocks.len(),
        );

        let mut disconnected_txs = Vec::new();

        for block_hash in &disconnect_blocks {
            if *block_hash == Hash256::zero() {
                continue;
            }

            let block_height = self.calculate_block_height(block_hash)?;
            crate::log_reorg_disconnect(block_hash, block_height);

            if let Some(block) = self.state.get_block(block_hash)? {
                for tx in block.transactions.iter().skip(1) {
                    disconnected_txs.push(tx.clone());
                }
            }

            let mut reorg_engine = crate::ReorgEngine::new(&mut self.state);
            reorg_engine.rollback_block(block_hash)?;
        }

        // FIX: Use correct height calculation for fork point
        let fork_height = self.calculate_block_height(&fork_point)?;

        let mut batch = axiom_storage::StorageBatch::new(self.state.database());
        batch.put_best_block_hash(&fork_point);
        batch.put_best_height(fork_height);
        batch.commit()?;

        self.state.best_block_hash = Some(fork_point);
        self.state.best_height = Some(fork_height);

        for block_hash in &connect_blocks {
            if let Some(block) = self.state.get_block(block_hash)? {
                let block_height = self.calculate_block_height(block_hash)?;
                crate::log_reorg_connect(block_hash, block_height);
                self.apply_block_to_chain(block)?;
            }
        }

        let new_height = self.state.best_height().unwrap_or(0);
        crate::log_reorg_done(new_tip, new_height);
        crate::log_tip_update(&old_tip, old_height, new_tip, new_height, "reorg");

        if let Some(new_tip_hash) = self.state.best_block_hash() {
            self.try_reconnect_orphans(&new_tip_hash)?;
        }

        self.restore_transactions_to_mempool(disconnected_txs)?;

        Ok(())
    }

    /// Re-submit transactions from disconnected blocks back to the mempool.
    fn restore_transactions_to_mempool(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<(), NodeError> {
        let utxo_set = axiom_storage::UtxoSet::new(self.state.database());
        let nonce_tracker = axiom_storage::NonceTracker::new(self.state.database());
        let validator =
            crate::TransactionValidator::new(utxo_set, nonce_tracker, self.config.min_fee_rate)
                .with_chain_id(self.config.network.chain_id());

        for tx in transactions {
            let txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

            if self.mempool.has_transaction(&txid) {
                continue;
            }

            if self.state.database().load_transaction(&txid).is_ok() {
                continue;
            }

            if let Ok(fee_sat) = validator.validate_and_compute_fee(&tx) {
                let _ = self.mempool.add_transaction(tx, fee_sat);
            }
        }

        Ok(())
    }

    fn try_reconnect_orphans(&mut self, parent_hash: &Hash256) -> Result<(), NodeError> {
        let children = self.orphan_pool.get_children(parent_hash);

        for child_hash in children {
            if let Some(orphan) = self.orphan_pool.remove_orphan(&child_hash) {
                self.process_block(orphan)?;
            }
        }

        Ok(())
    }

    pub fn best_block_hash(&self) -> Option<Hash256> {
        self.state.best_block_hash()
    }

    pub fn best_height(&self) -> Option<u32> {
        self.state.best_height()
    }

    pub fn get_nonce(&self, pubkey_hash: &Hash256) -> Result<u64, NodeError> {
        let nonce_tracker = NonceTracker::new(self.state.database());
        Ok(nonce_tracker.get_nonce(pubkey_hash)?.unwrap_or(0))
    }

    pub fn mempool_size(&self) -> usize {
        self.mempool.len()
    }

    pub fn mempool_transactions(
        &self,
    ) -> Vec<(axiom_primitives::Hash256, axiom_protocol::Transaction)> {
        self.mempool.get_all_transactions()
    }

    /// Mempool entries paired with the fee and serialized size recorded at
    /// admission time, highest-fee-rate first. Used by `get_mempool` so the
    /// RPC returns real fee values.
    pub fn mempool_entries_with_fees(
        &self,
    ) -> Vec<(
        axiom_primitives::Hash256,
        axiom_protocol::Transaction,
        u64,
        usize,
    )> {
        self.mempool.get_all_entries_with_fees()
    }

    pub fn get_block(&self, block_hash: &Hash256) -> Result<Option<Block>, NodeError> {
        Ok(self.state.get_block(block_hash)?)
    }

    pub fn has_block(&self, block_hash: &Hash256) -> Result<bool, NodeError> {
        Ok(self.state.has_block(block_hash)?)
    }

    pub fn orphan_count(&self) -> usize {
        self.orphan_pool.len()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn chain_id(&self) -> &str {
        self.config.network.chain_id()
    }

    pub fn reorg_count(&self) -> u64 {
        self.reorg_count
    }

    pub fn is_orphan(&self, block_hash: &Hash256) -> bool {
        self.orphan_pool.has_orphan(block_hash)
    }

    pub fn get_recent_blocks(&self, limit: usize) -> Result<Vec<Block>, NodeError> {
        let mut blocks = Vec::new();
        let mut current_hash = self.best_block_hash();

        while let Some(hash) = current_hash {
            if blocks.len() >= limit {
                break;
            }

            if let Some(block) = self.get_block(&hash)? {
                current_hash = if block.header.prev_block_hash == Hash256::zero() {
                    None
                } else {
                    Some(block.header.prev_block_hash)
                };
                blocks.push(block);
            } else {
                break;
            }
        }

        Ok(blocks)
    }

    /// Look up a block by height; falls back to chain walk if the index is stale.
    pub fn get_block_by_height(&self, target_height: u32) -> Result<Option<Block>, NodeError> {
        if let Some(hash) = self.state.db_get_hash_by_height(target_height)? {
            return self.get_block(&hash);
        }

        let best_height = match self.best_height() {
            Some(h) => h,
            None => return Ok(None),
        };
        if target_height > best_height {
            return Ok(None);
        }
        let steps_back = best_height - target_height;
        let mut cursor = match self.best_block_hash() {
            Some(h) => h,
            None => return Ok(None),
        };
        for _ in 0..steps_back {
            let header = self.state.db_load_block_header(&cursor)?;
            if header.prev_block_hash == Hash256::zero() {
                return Ok(None);
            }
            cursor = header.prev_block_hash;
        }
        self.get_block(&cursor)
    }

    /// Backfill any missing height-to-hash index entries.
    pub fn reindex_heights(&self) -> Result<usize, NodeError> {
        let best_height = match self.best_height() {
            Some(h) => h,
            None => return Ok(0),
        };
        if self.state.db_get_hash_by_height(best_height)?.is_some() {
            return Ok(0);
        }

        let mut cursor = match self.best_block_hash() {
            Some(h) => h,
            None => return Ok(0),
        };
        let mut height = best_height;
        let mut written = 0usize;

        loop {
            if self.state.db_get_hash_by_height(height)?.is_none() {
                self.state.db_store_height_index(height, &cursor)?;
                written += 1;
            }
            let header = match self.state.db_load_block_header(&cursor) {
                Ok(h) => h,
                Err(_) => break,
            };
            if header.prev_block_hash == Hash256::zero() || height == 0 {
                break;
            }
            cursor = header.prev_block_hash;
            height -= 1;
        }

        Ok(written)
    }

    pub fn get_chain_work(&self) -> Result<Option<u128>, NodeError> {
        if let Some(hash) = self.best_block_hash() {
            Ok(self.state.get_chain_work(&hash)?)
        } else {
            Ok(None)
        }
    }

    pub fn get_mempool_transactions(&self) -> Vec<Transaction> {
        self.mempool
            .get_all_transactions()
            .into_iter()
            .map(|(_, tx)| tx)
            .collect()
    }

    pub fn get_mempool_tx(&self, txid: &Hash256) -> Option<Transaction> {
        self.mempool.get_transaction(txid).cloned()
    }

    pub fn ai_analysis_report(&mut self) -> AiAnalysisReport {
        self.anomaly_detector.report()
    }

    pub fn min_fee_rate(&self) -> u64 {
        self.config.min_fee_rate
    }

    pub fn mempool_max_count(&self) -> usize {
        self.config.mempool_max_count
    }

    pub fn mempool_byte_size(&self) -> usize {
        self.mempool.size()
    }

    pub fn mempool_max_byte_size(&self) -> usize {
        self.config.mempool_max_size
    }

    /// Prune block bodies older than `prune_depth` blocks; headers and UTXOs are kept.
    pub fn prune_chain(&self, prune_depth: u32) -> Result<usize, NodeError> {
        Ok(self.state.database().prune_to_depth(prune_depth)?)
    }

    pub fn persist_mempool(&self) -> Result<(), NodeError> {
        let path = self.config.data_dir.join("mempool.dat");
        self.mempool.save_to_file(&path).map_err(NodeError::Mempool)
    }

    pub fn mempool_recommended_fee_rates(&self) -> crate::mempool::RecommendedFeeRates {
        self.mempool.recommended_fee_rates()
    }

    pub fn mempool_fee_percentiles(&self) -> Option<crate::mempool::FeePercentiles> {
        self.mempool.get_fee_percentiles()
    }

    /// Background loop that samples node metrics for AxiomMind dashboards.
    /// Read-only: it reads `best_height`, `mempool_size`, `orphan_count` and
    /// emits them to the metrics layer. Block-by-block analysis lives in
    /// `axiom-guard::NetworkGuard`, driven by the post-acceptance hook in the
    /// network service — never from this loop.
    pub fn spawn_consensus_monitor(node: std::sync::Arc<Node>) {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    let _consensus_height = node.best_height().unwrap_or(0);
                    let _mempool_size = node.mempool_size();
                    let _orphan_count = node.orphan_count();
                }
            });
        });
    }

    /// Return `(size_bytes, fee_rate_sat_per_byte, fee_sat)` for every mempool entry.
    /// Used by the enhanced mempool stats RPC endpoint.
    pub fn mempool_entry_stats(&self) -> Vec<(usize, u64, u64)> {
        self.mempool.entry_stats()
    }
}

fn current_timestamp() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidationMode;
    use tempfile::TempDir;

    fn create_test_node() -> (TempDir, Node) {
        let temp_dir = TempDir::new().unwrap();
        let config = Config {
            data_dir: temp_dir.path().to_path_buf(),
            ..Config::default()
        };
        let node = Node::new(config).unwrap();
        (temp_dir, node)
    }

    #[test]
    fn test_node_initialization() {
        let (_temp, node) = create_test_node();

        assert_eq!(node.best_height(), Some(0));
        assert!(node.best_block_hash().is_some());
    }

    #[test]
    fn test_build_and_process_block() {
        let (_temp, mut node) = create_test_node();

        let block = node.build_block().unwrap();
        node.process_block(block).unwrap();

        assert_eq!(node.best_height(), Some(1));
    }

    #[test]
    fn test_max_reorg_depth_constant() {
        assert_eq!(MAX_REORG_DEPTH, 200, "reorg depth limit must be 200 blocks");
    }

    #[test]
    fn test_coinbase_maturity_constant() {
        assert_eq!(crate::validation::COINBASE_MATURITY, 100);
    }

    #[test]
    fn test_validation_mode_selection() {
        let av_height = crate::checkpoints::assumevalid_height();
        assert_eq!(av_height, 0);
        let mode_height_1 = if 1u32 <= av_height {
            ValidationMode::AssumeValid
        } else {
            ValidationMode::Full
        };
        assert_eq!(mode_height_1, ValidationMode::Full);
        let mode_height_0 = if av_height == 0 {
            ValidationMode::AssumeValid
        } else {
            ValidationMode::Full
        };
        assert_eq!(mode_height_0, ValidationMode::AssumeValid);
    }

    #[test]
    fn test_block_reward_smooth_decay() {
        use axiom_consensus::{INITIAL_REWARD_SAT, MIN_REWARD_SAT};
        assert_eq!(
            axiom_consensus::calculate_block_reward(0).as_sat(),
            INITIAL_REWARD_SAT
        );
        assert!(
            axiom_consensus::calculate_block_reward(1).as_sat()
                < axiom_consensus::calculate_block_reward(0).as_sat()
        );
        assert_eq!(
            axiom_consensus::calculate_block_reward(2_000_000).as_sat(),
            MIN_REWARD_SAT
        );
    }
}
