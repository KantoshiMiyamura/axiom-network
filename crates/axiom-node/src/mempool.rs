// Copyright (c) 2026 Kantoshi Miyamura

//! Unconfirmed transaction pool with fee-rate ordering, RBF, CPFP, and TTL eviction.

use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const DUST_LIMIT: u64 = 546;

const DEFAULT_TTL: Duration = Duration::from_secs(72 * 3600);
const MAX_ANCESTORS: usize = 25;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("transaction too large: {size} bytes (maximum: {max})")]
    TransactionTooLarge { size: usize, max: usize },

    #[error("mempool full: size {size} bytes (maximum: {max})")]
    TooLarge { size: usize, max: usize },

    #[error("mempool full: {count} transactions (maximum: {max})")]
    TooManyTransactions { count: usize, max: usize },

    #[error("transaction already in mempool")]
    AlreadyInMempool,

    #[error("transaction already in mempool")]
    Duplicate,

    #[error("fee rate {fee_rate} sat/byte is below minimum {min_fee_rate} sat/byte")]
    FeeTooLow { fee_rate: u64, min_fee_rate: u64 },

    #[error("replacement fee rate {new_fee_rate} sat/byte must be at least {required_fee_rate} sat/byte (10% bump required)")]
    InsufficientFeeForReplacement {
        new_fee_rate: u64,
        required_fee_rate: u64,
    },

    #[error("output value {value} sat is below dust limit")]
    DustOutput { value: u64 },

    #[error("transaction has {0} ancestors in mempool (maximum: 25)")]
    TooManyAncestors(usize),

    #[error("transaction not found")]
    NotFound,

    #[error("persistence error: {0}")]
    Persistence(String),
}

// BTreeMap is ascending; iterate in reverse for highest-fee-first. Txid breaks ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeKey {
    fee_rate_sat_per_byte: u64,
    txid: Hash256,
}

impl PartialOrd for FeeKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FeeKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.fee_rate_sat_per_byte
            .cmp(&other.fee_rate_sat_per_byte)
            .then_with(|| self.txid.as_bytes().cmp(other.txid.as_bytes()))
    }
}

pub struct MempoolEntry {
    pub transaction: Transaction,
    pub fee_sat: u64,
    pub size_bytes: usize,
    pub fee_rate_sat_per_byte: u64,
    pub inserted_at: Instant,
    pub parent_txids: HashSet<Hash256>,
    pub child_txids: HashSet<Hash256>,
}

pub struct MempoolStats {
    pub tx_count: usize,
    pub size_bytes: usize,
    pub min_fee_rate: u64,
    pub max_fee_rate: u64,
    pub median_fee_rate: u64,
    pub total_fees_sat: u64,
    pub oldest_tx_age_secs: u64,
}

#[derive(Debug, Clone)]
pub struct FeePercentiles {
    pub min: u64,
    pub p10: u64,
    pub p25: u64,
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub max: u64,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct RecommendedFeeRates {
    pub slow: u64,
    pub medium: u64,
    pub fast: u64,
    pub next_block: u64,
    pub min_relay: u64,
}

pub struct Mempool {
    entries: HashMap<Hash256, MempoolEntry>,
    fee_index: BTreeMap<FeeKey, Hash256>,
    spent_outputs: HashMap<(Hash256, u32), Hash256>,
    current_size: usize,
    max_size: usize,
    max_count: usize,
    min_fee_rate: u64,
    max_tx_size: usize,
    ttl: Duration,
    max_orphans_per_peer: usize,
}

impl Mempool {
    pub fn new(max_size: usize, max_count: usize) -> Self {
        Mempool {
            entries: HashMap::new(),
            fee_index: BTreeMap::new(),
            spent_outputs: HashMap::new(),
            current_size: 0,
            max_size,
            max_count,
            min_fee_rate: 1,
            max_tx_size: 100_000,
            ttl: DEFAULT_TTL,
            max_orphans_per_peer: 100,
        }
    }

    pub fn with_params(
        max_size: usize,
        max_count: usize,
        min_fee_rate: u64,
        max_tx_size: usize,
    ) -> Self {
        Mempool {
            entries: HashMap::new(),
            fee_index: BTreeMap::new(),
            spent_outputs: HashMap::new(),
            current_size: 0,
            max_size,
            max_count,
            min_fee_rate,
            max_tx_size,
            ttl: DEFAULT_TTL,
            max_orphans_per_peer: 100,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Min fee rate that rises as the mempool fills: 1×, 2×, 4×, 8× of base.
    pub fn dynamic_min_fee_rate(&self) -> u64 {
        let usage = if self.max_size > 0 {
            self.current_size as f64 / self.max_size as f64
        } else {
            0.0
        };

        let multiplier = if usage >= 0.90 {
            8
        } else if usage >= 0.75 {
            4
        } else if usage >= 0.50 {
            2
        } else {
            1
        };

        self.min_fee_rate.saturating_mul(multiplier)
    }

    pub fn max_orphans_per_peer(&self) -> usize {
        self.max_orphans_per_peer
    }

    /// Add transaction where `fee_sat` = input_value − output_value.
    pub fn add_transaction(&mut self, tx: Transaction, fee_sat: u64) -> Result<(), MempoolError> {
        self.evict_expired();

        let serialized = axiom_protocol::serialize_transaction(&tx);
        let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));
        let tx_size = serialized.len();

        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyInMempool);
        }

        if tx_size > self.max_tx_size {
            return Err(MempoolError::TransactionTooLarge {
                size: tx_size,
                max: self.max_tx_size,
            });
        }

        if !tx.is_coinbase() {
            for output in &tx.outputs {
                if output.value.as_sat() < DUST_LIMIT {
                    return Err(MempoolError::DustOutput {
                        value: output.value.as_sat(),
                    });
                }
            }
        }

        // SECURITY: Ceiling division prevents sub-1-sat/byte transactions from
        // appearing to meet minimum fee rate. Consistent with validation.rs fix.
        let fee_rate = if tx_size > 0 {
            fee_sat.div_ceil(tx_size as u64)
        } else {
            0
        };

        if !tx.is_coinbase() && fee_rate < self.dynamic_min_fee_rate() {
            return Err(MempoolError::FeeTooLow {
                fee_rate,
                min_fee_rate: self.dynamic_min_fee_rate(),
            });
        }

        let conflicts: Vec<Hash256> = tx
            .inputs
            .iter()
            .filter_map(|inp| {
                self.spent_outputs
                    .get(&(inp.prev_tx_hash, inp.prev_output_index))
                    .copied()
            })
            .collect::<HashSet<Hash256>>()
            .into_iter()
            .collect();

        if !conflicts.is_empty() {
            for &conflict_txid in &conflicts {
                if let Some(existing) = self.entries.get(&conflict_txid) {
                    let required = existing.fee_rate_sat_per_byte.saturating_mul(11) / 10;
                    if fee_rate <= required {
                        return Err(MempoolError::InsufficientFeeForReplacement {
                            new_fee_rate: fee_rate,
                            required_fee_rate: required,
                        });
                    }
                }
            }
            for conflict_txid in &conflicts {
                tracing::info!(
                    old_txid = %hex::encode(conflict_txid.as_bytes()),
                    new_fee_rate = fee_rate,
                    "RBF: replacing transaction"
                );
                self.remove_entry(conflict_txid);
            }
        }

        let ancestor_count = self.count_ancestors(&tx);
        if ancestor_count > MAX_ANCESTORS {
            return Err(MempoolError::TooManyAncestors(ancestor_count));
        }

        while self.entries.len() >= self.max_count || self.current_size + tx_size > self.max_size {
            if self.entries.is_empty() {
                break;
            }
            if let Some((&lowest_key, _)) = self.fee_index.iter().next() {
                if lowest_key.fee_rate_sat_per_byte > fee_rate {
                    if self.entries.len() >= self.max_count {
                        return Err(MempoolError::TooManyTransactions {
                            count: self.entries.len(),
                            max: self.max_count,
                        });
                    }
                    return Err(MempoolError::TooLarge {
                        size: self.current_size + tx_size,
                        max: self.max_size,
                    });
                }
                let evict_txid = lowest_key.txid;
                tracing::debug!(
                    evicted_txid = %hex::encode(evict_txid.as_bytes()),
                    "mempool full: evicting lowest-fee transaction"
                );
                self.remove_entry(&evict_txid);
            } else {
                break;
            }
        }

        if self.entries.len() >= self.max_count {
            return Err(MempoolError::TooManyTransactions {
                count: self.entries.len(),
                max: self.max_count,
            });
        }
        if self.current_size + tx_size > self.max_size {
            return Err(MempoolError::TooLarge {
                size: self.current_size + tx_size,
                max: self.max_size,
            });
        }

        let parent_txids: HashSet<Hash256> = tx
            .inputs
            .iter()
            .filter_map(|inp| {
                if self.entries.contains_key(&inp.prev_tx_hash) {
                    Some(inp.prev_tx_hash)
                } else {
                    None
                }
            })
            .collect();

        for &parent_txid in &parent_txids {
            if let Some(parent_entry) = self.entries.get_mut(&parent_txid) {
                parent_entry.child_txids.insert(txid);
            }
        }

        for inp in &tx.inputs {
            self.spent_outputs
                .insert((inp.prev_tx_hash, inp.prev_output_index), txid);
        }

        let fee_key = FeeKey {
            fee_rate_sat_per_byte: fee_rate,
            txid,
        };
        self.fee_index.insert(fee_key, txid);
        self.current_size += tx_size;

        let entry = MempoolEntry {
            transaction: tx,
            fee_sat,
            size_bytes: tx_size,
            fee_rate_sat_per_byte: fee_rate,
            inserted_at: Instant::now(),
            parent_txids,
            child_txids: HashSet::new(),
        };
        self.entries.insert(txid, entry);

        Ok(())
    }

    pub fn add_transaction_with_utxo_values(
        &mut self,
        tx: Transaction,
        input_value: u64,
    ) -> Result<(), MempoolError> {
        let output_value: u64 = tx.outputs.iter().map(|o| o.value.as_sat()).sum();
        let fee_sat = input_value.saturating_sub(output_value);
        self.add_transaction(tx, fee_sat)
    }

    pub fn remove_transaction(&mut self, txid: &Hash256) -> Result<Transaction, MempoolError> {
        self.remove_entry(txid).ok_or(MempoolError::NotFound)
    }

    pub fn remove_transactions(&mut self, txids: &[Hash256]) {
        for txid in txids {
            self.remove_entry(txid);
        }
    }

    pub fn get_transaction(&self, txid: &Hash256) -> Option<&Transaction> {
        self.entries.get(txid).map(|e| &e.transaction)
    }

    pub fn get_entry(&self, txid: &Hash256) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    pub fn has_transaction(&self, txid: &Hash256) -> bool {
        self.entries.contains_key(txid)
    }

    /// All transactions, highest fee rate first.
    pub fn get_all_transactions(&self) -> Vec<(Hash256, Transaction)> {
        self.fee_index
            .iter()
            .rev()
            .map(|(key, &txid)| {
                let tx = self.entries[&txid].transaction.clone();
                (key.txid, tx)
            })
            .collect()
    }

    /// All mempool entries with (txid, transaction, fee_sat, size_bytes),
    /// ordered highest fee rate first. Used by the `get_mempool` RPC so
    /// fee values surface to callers instead of the historical `fee_sat = 0`
    /// placeholder.
    pub fn get_all_entries_with_fees(&self) -> Vec<(Hash256, Transaction, u64, usize)> {
        self.fee_index
            .iter()
            .rev()
            .map(|(key, &txid)| {
                let entry = &self.entries[&txid];
                (
                    key.txid,
                    entry.transaction.clone(),
                    entry.fee_sat,
                    entry.size_bytes,
                )
            })
            .collect()
    }

    pub fn get_transactions_by_fee(&self) -> Vec<(Hash256, Transaction)> {
        self.get_all_transactions()
    }

    pub fn get_spenders(&self, prev_tx_hash: &Hash256, prev_output_index: u32) -> Option<Hash256> {
        self.spent_outputs
            .get(&(*prev_tx_hash, prev_output_index))
            .copied()
    }

    pub fn is_input_spent(&self, prev_tx_hash: &Hash256, prev_output_index: u32) -> bool {
        self.spent_outputs
            .contains_key(&(*prev_tx_hash, prev_output_index))
    }

    /// Combined fee rate of a transaction and all its unconfirmed descendants (CPFP).
    pub fn get_package_fee_rate(&self, txid: &Hash256) -> u64 {
        let mut total_fee: u64 = 0;
        let mut total_size: usize = 0;
        let mut visited: HashSet<Hash256> = HashSet::new();
        self.accumulate_package(*txid, &mut total_fee, &mut total_size, &mut visited);
        if total_size == 0 {
            0
        } else {
            // Ceiling division: (total_fee + total_size - 1) / total_size
            // Consistent with validator fee rate calculation and prevents CPFP underscoring
            total_fee.div_ceil(total_size as u64)
        }
    }

    pub fn stats(&self) -> MempoolStats {
        let tx_count = self.entries.len();
        if tx_count == 0 {
            return MempoolStats {
                tx_count: 0,
                size_bytes: 0,
                min_fee_rate: 0,
                max_fee_rate: 0,
                median_fee_rate: 0,
                total_fees_sat: 0,
                oldest_tx_age_secs: 0,
            };
        }

        let total_fees_sat: u64 = self.entries.values().map(|e| e.fee_sat).sum();
        let size_bytes = self.current_size;

        let rates: Vec<u64> = self
            .fee_index
            .keys()
            .map(|k| k.fee_rate_sat_per_byte)
            .collect();

        let min_fee_rate = rates.first().copied().unwrap_or(0);
        let max_fee_rate = rates.last().copied().unwrap_or(0);
        let median_fee_rate = rates[rates.len() / 2];

        let oldest_tx_age_secs = self
            .entries
            .values()
            .map(|e| e.inserted_at.elapsed().as_secs())
            .max()
            .unwrap_or(0);

        MempoolStats {
            tx_count,
            size_bytes,
            min_fee_rate,
            max_fee_rate,
            median_fee_rate,
            total_fees_sat,
            oldest_tx_age_secs,
        }
    }

    /// Evict transactions past their TTL.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;

        let expired: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.inserted_at) >= ttl)
            .map(|(&txid, _)| txid)
            .collect();

        let count = expired.len();
        for txid in &expired {
            self.remove_entry(txid);
        }

        if count > 0 {
            tracing::info!(evicted = count, "mempool TTL: evicted expired transactions");
        }

        count
    }

    /// Write non-expired entries to disk as bincode-encoded (tx, fee_sat) pairs.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), MempoolError> {
        let now = Instant::now();
        let ttl = self.ttl;
        let pairs: Vec<(Transaction, u64)> = self
            .entries
            .values()
            .filter(|e| now.duration_since(e.inserted_at) < ttl)
            .map(|e| (e.transaction.clone(), e.fee_sat))
            .collect();

        let count = pairs.len();
        let encoded = bincode::serde::encode_to_vec(&pairs, bincode::config::standard())
            .map_err(|e| MempoolError::Persistence(e.to_string()))?;
        std::fs::write(path, encoded).map_err(|e| MempoolError::Persistence(e.to_string()))?;

        tracing::info!(saved = count, path = %path.display(), "mempool persisted to disk");
        Ok(())
    }

    /// Restore entries from disk; skips entries that fail current validation rules.
    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<usize, MempoolError> {
        let data = std::fs::read(path).map_err(|e| MempoolError::Persistence(e.to_string()))?;
        let (pairs, _): (Vec<(Transaction, u64)>, _) =
            bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| MempoolError::Persistence(e.to_string()))?;

        let mut loaded = 0usize;
        for (tx, fee_sat) in pairs {
            if self.add_transaction(tx, fee_sat).is_ok() {
                loaded += 1;
            }
        }

        tracing::info!(loaded, path = %path.display(), "mempool loaded from disk");
        Ok(loaded)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size(&self) -> usize {
        self.current_size
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.fee_index.clear();
        self.spent_outputs.clear();
        self.current_size = 0;
    }

    fn remove_entry(&mut self, txid: &Hash256) -> Option<Transaction> {
        let entry = self.entries.remove(txid)?;

        let key = FeeKey {
            fee_rate_sat_per_byte: entry.fee_rate_sat_per_byte,
            txid: *txid,
        };
        self.fee_index.remove(&key);

        for inp in &entry.transaction.inputs {
            self.spent_outputs
                .remove(&(inp.prev_tx_hash, inp.prev_output_index));
        }

        for parent_txid in &entry.parent_txids {
            if let Some(parent) = self.entries.get_mut(parent_txid) {
                parent.child_txids.remove(txid);
            }
        }

        for child_txid in &entry.child_txids {
            if let Some(child) = self.entries.get_mut(child_txid) {
                child.parent_txids.remove(txid);
            }
        }

        self.current_size = self.current_size.saturating_sub(entry.size_bytes);

        Some(entry.transaction)
    }

    fn count_ancestors(&self, tx: &Transaction) -> usize {
        let mut visited: HashSet<Hash256> = HashSet::new();
        self.walk_ancestors_tx(tx, &mut visited);
        visited.len()
    }

    fn walk_ancestors_tx(&self, tx: &Transaction, visited: &mut HashSet<Hash256>) {
        for inp in &tx.inputs {
            let parent_txid = inp.prev_tx_hash;
            if !visited.contains(&parent_txid) {
                if let Some(parent_entry) = self.entries.get(&parent_txid) {
                    visited.insert(parent_txid);
                    self.walk_ancestors_entry(parent_txid, parent_entry, visited);
                }
            }
        }
    }

    fn walk_ancestors_entry(
        &self,
        _txid: Hash256,
        entry: &MempoolEntry,
        visited: &mut HashSet<Hash256>,
    ) {
        for &parent_txid in &entry.parent_txids {
            if !visited.contains(&parent_txid) {
                if let Some(parent_entry) = self.entries.get(&parent_txid) {
                    visited.insert(parent_txid);
                    self.walk_ancestors_entry(parent_txid, parent_entry, visited);
                }
            }
        }
    }

    /// Return `(size_bytes, fee_rate_sat_per_byte, fee_sat)` for every entry.
    /// Used by the enhanced mempool stats RPC handler.
    pub fn entry_stats(&self) -> Vec<(usize, u64, u64)> {
        self.entries
            .values()
            .map(|e| (e.size_bytes, e.fee_rate_sat_per_byte, e.fee_sat))
            .collect()
    }

    /// Fee rate percentiles; returns None if the mempool is empty.
    pub fn get_fee_percentiles(&self) -> Option<FeePercentiles> {
        if self.entries.is_empty() {
            return None;
        }

        let mut rates: Vec<u64> = self
            .entries
            .values()
            .map(|e| e.fee_rate_sat_per_byte)
            .collect();
        rates.sort_unstable();

        let n = rates.len();
        let percentile = |p: usize| -> u64 {
            let idx = (p * n).saturating_sub(1) / 100;
            rates[idx.min(n - 1)]
        };

        Some(FeePercentiles {
            min: *rates.first().unwrap(),
            p10: percentile(10),
            p25: percentile(25),
            p50: percentile(50),
            p75: percentile(75),
            p90: percentile(90),
            max: *rates.last().unwrap(),
            count: n,
        })
    }

    /// Suggested fee rates for slow, medium, fast, and next-block confirmation targets.
    pub fn recommended_fee_rates(&self) -> RecommendedFeeRates {
        match self.get_fee_percentiles() {
            Some(p) => RecommendedFeeRates {
                slow: p.p25.max(self.min_fee_rate),
                medium: p.p50.max(self.min_fee_rate),
                fast: p.p75.max(self.min_fee_rate),
                next_block: p.p90.max(self.min_fee_rate),
                min_relay: self.dynamic_min_fee_rate(),
            },
            None => RecommendedFeeRates {
                slow: self.min_fee_rate,
                medium: self.min_fee_rate,
                fast: self.min_fee_rate,
                next_block: self.min_fee_rate,
                min_relay: self.dynamic_min_fee_rate(),
            },
        }
    }

    fn accumulate_package(
        &self,
        txid: Hash256,
        total_fee: &mut u64,
        total_size: &mut usize,
        visited: &mut HashSet<Hash256>,
    ) {
        if visited.contains(&txid) {
            return;
        }
        visited.insert(txid);
        if let Some(entry) = self.entries.get(&txid) {
            *total_fee = total_fee.saturating_add(entry.fee_sat);
            *total_size = total_size.saturating_add(entry.size_bytes);
            for &child_txid in &entry.child_txids {
                self.accumulate_package(child_txid, total_fee, total_size, visited);
            }
        }
    }

    // ── CPFP: ancestor-aware fee rate ────────────────────────────────────────

    /// Compute the effective fee rate for a transaction considering all its
    /// unconfirmed ancestors already in the mempool.
    ///
    /// effective_fee_rate = (fee_self + sum(fee_ancestors)) /
    ///                      (size_self + sum(size_ancestors))
    ///
    /// This is the metric miners use for CPFP: a low-fee parent becomes
    /// attractive when a high-fee child "sponsors" it.
    #[allow(dead_code)]
    pub fn ancestor_fee_rate(&self, txid: &Hash256) -> u64 {
        let entry = match self.entries.get(txid) {
            Some(e) => e,
            None => return 0,
        };

        let mut visited: HashSet<Hash256> = HashSet::new();
        let mut total_fee: u64 = 0;
        let mut total_size: usize = 0;

        // Walk all ancestors (transitive) and accumulate their fees + sizes.
        self.accumulate_ancestors(*txid, &mut total_fee, &mut total_size, &mut visited);

        // Add this tx itself.
        total_fee = total_fee.saturating_add(entry.fee_sat);
        total_size = total_size.saturating_add(entry.size_bytes);

        if total_size == 0 {
            0
        } else {
            // Ceiling division: (total_fee + total_size - 1) / total_size
            // Prevents rounding down and underscoring low-fee parents with high-fee children
            total_fee.div_ceil(total_size as u64)
        }
    }

    /// Recursively accumulate fee and size of all ancestors of `txid`
    /// (not including the tx itself).
    fn accumulate_ancestors(
        &self,
        txid: Hash256,
        total_fee: &mut u64,
        total_size: &mut usize,
        visited: &mut HashSet<Hash256>,
    ) {
        let entry = match self.entries.get(&txid) {
            Some(e) => e,
            None => return,
        };
        for &parent_txid in &entry.parent_txids {
            if visited.insert(parent_txid) {
                if let Some(parent) = self.entries.get(&parent_txid) {
                    *total_fee = total_fee.saturating_add(parent.fee_sat);
                    *total_size = total_size.saturating_add(parent.size_bytes);
                    self.accumulate_ancestors(parent_txid, total_fee, total_size, visited);
                }
            }
        }
    }

    /// Collect all ancestor txids for a given transaction (transitive closure).
    fn collect_all_ancestors(&self, txid: &Hash256) -> HashSet<Hash256> {
        let mut visited = HashSet::new();
        if let Some(entry) = self.entries.get(txid) {
            for &parent in &entry.parent_txids {
                if visited.insert(parent) {
                    let sub = self.collect_all_ancestors(&parent);
                    visited.extend(sub);
                }
            }
        }
        visited
    }

    /// Select transactions for block inclusion using CPFP-aware ordering.
    ///
    /// Transactions are sorted by **effective (ancestor) fee rate** so that a
    /// high-fee child can pull a low-fee parent into the block.  The returned
    /// slice always satisfies topological order (parents appear before
    /// children).
    ///
    /// `max_size_bytes` — total serialized size budget; typically 1 MB.
    #[allow(dead_code)]
    pub fn get_transactions_for_block(&self, max_size_bytes: usize) -> Vec<Transaction> {
        if self.entries.is_empty() {
            return Vec::new();
        }

        // 1. Compute effective fee rate for every entry.
        let mut scored: Vec<(Hash256, u64)> = self
            .entries
            .keys()
            .map(|txid| {
                let rate = self.ancestor_fee_rate(txid);
                (*txid, rate)
            })
            .collect();

        // Sort descending by effective rate; break ties by txid bytes.
        scored.sort_unstable_by(|(a_id, a_rate), (b_id, b_rate)| {
            b_rate
                .cmp(a_rate)
                .then_with(|| a_id.as_bytes().cmp(b_id.as_bytes()))
        });

        // 2. Greedy selection: pick highest-effective-rate packages first.
        //    When we select a tx we must include ALL of its ancestors first.
        let mut selected: HashSet<Hash256> = HashSet::new();
        let mut total_size: usize = 0;

        // Ordered list preserving topological order.
        let mut result_ids: Vec<Hash256> = Vec::new();

        'outer: for (txid, _rate) in &scored {
            if selected.contains(txid) {
                continue;
            }

            // Gather the chain: ancestors (topological) + this tx.
            let ancestors = self.collect_all_ancestors(txid);
            let mut chain: Vec<Hash256> = ancestors
                .into_iter()
                .filter(|id| !selected.contains(id))
                .collect();

            // Sort ancestors in topological order: parents before children.
            chain = self.topological_sort_subset(chain);
            chain.push(*txid);

            // Check that the whole chain fits.
            let chain_size: usize = chain
                .iter()
                .filter_map(|id| self.entries.get(id))
                .map(|e| e.size_bytes)
                .sum();

            if total_size + chain_size > max_size_bytes {
                // Try to continue with smaller txs later.
                continue 'outer;
            }

            // Commit the chain.
            for id in chain {
                if selected.insert(id) {
                    result_ids.push(id);
                    if let Some(e) = self.entries.get(&id) {
                        total_size += e.size_bytes;
                    }
                }
            }
        }

        // 3. Return transactions in the topologically-ordered result list.
        result_ids
            .iter()
            .filter_map(|id| self.entries.get(id).map(|e| e.transaction.clone()))
            .collect()
    }

    /// Sort a set of txids into topological order (parents before children).
    /// Uses a simple DFS-based topo-sort limited to the subset provided.
    fn topological_sort_subset(&self, ids: Vec<Hash256>) -> Vec<Hash256> {
        let id_set: HashSet<Hash256> = ids.iter().copied().collect();
        let mut visited: HashSet<Hash256> = HashSet::new();
        let mut result: Vec<Hash256> = Vec::with_capacity(ids.len());

        for id in &ids {
            if !visited.contains(id) {
                self.topo_visit(*id, &id_set, &mut visited, &mut result);
            }
        }
        result
    }

    fn topo_visit(
        &self,
        txid: Hash256,
        subset: &HashSet<Hash256>,
        visited: &mut HashSet<Hash256>,
        result: &mut Vec<Hash256>,
    ) {
        if !visited.insert(txid) {
            return;
        }
        if let Some(entry) = self.entries.get(&txid) {
            for &parent in &entry.parent_txids {
                if subset.contains(&parent) && !visited.contains(&parent) {
                    self.topo_visit(parent, subset, visited, result);
                }
            }
        }
        result.push(txid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_primitives::Amount;
    use axiom_protocol::TxOutput;

    fn make_tx(nonce: u64) -> (Hash256, Transaction) {
        let output = TxOutput {
            value: Amount::from_sat(1_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let tx = Transaction::new_transfer(vec![], vec![output], nonce, 0);
        let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));
        (txid, tx)
    }

    fn make_tx_spending(
        prev_tx_hash: Hash256,
        prev_output_index: u32,
        nonce: u64,
    ) -> (Hash256, Transaction) {
        use axiom_primitives::{PublicKey, Signature};
        use axiom_protocol::TxInput;

        let input = TxInput {
            prev_tx_hash,
            prev_output_index,
            signature: Signature::placeholder(),
            pubkey: PublicKey::from_bytes(vec![0u8; 2592]),
        };
        let output = TxOutput {
            value: Amount::from_sat(1_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let tx = Transaction::new_transfer(vec![input], vec![output], nonce, 0);
        let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));
        (txid, tx)
    }

    #[test]
    fn test_mempool_add_get() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (txid, tx) = make_tx(1);

        mempool.add_transaction(tx.clone(), 1_000).unwrap();

        assert!(mempool.has_transaction(&txid));
        assert_eq!(mempool.get_transaction(&txid).unwrap(), &tx);
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_duplicate() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (_, tx) = make_tx(1);

        mempool.add_transaction(tx.clone(), 1_000).unwrap();
        let result = mempool.add_transaction(tx, 1_000);

        assert!(matches!(result, Err(MempoolError::AlreadyInMempool)));
    }

    #[test]
    fn test_mempool_remove() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (txid, tx) = make_tx(1);

        mempool.add_transaction(tx, 1_000).unwrap();
        assert_eq!(mempool.len(), 1);

        mempool.remove_transaction(&txid).unwrap();
        assert_eq!(mempool.len(), 0);
        assert!(!mempool.has_transaction(&txid));
    }

    #[test]
    fn test_mempool_clear() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (_, tx1) = make_tx(1);
        let (_, tx2) = make_tx(2);

        mempool.add_transaction(tx1, 1_000).unwrap();
        mempool.add_transaction(tx2, 1_000).unwrap();

        mempool.clear();
        assert_eq!(mempool.len(), 0);
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_mempool_count_limit() {
        let mut mempool = Mempool::new(1_000_000, 2);

        let (_, tx1) = make_tx(1);
        let (_, tx2) = make_tx(2);

        mempool.add_transaction(tx1, 2_000).unwrap();
        mempool.add_transaction(tx2, 2_000).unwrap();

        let (_, tx3_high) = make_tx(99);
        let result = mempool.add_transaction(tx3_high, 10_000);
        assert!(result.is_ok());
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    fn test_fee_ordering() {
        let mut mempool = Mempool::with_params(10_000_000, 1_000, 0, 100_000);

        let fee_schedule: &[(u64, u64)] = &[
            (1, 100),    // ~1-2 sat/byte
            (2, 5_000),  // ~70-80 sat/byte
            (3, 50),     // ~0 sat/byte (rounded down)
            (4, 10_000), // ~140-160 sat/byte
            (5, 2_000),  // ~28-33 sat/byte
        ];

        for &(nonce, fee) in fee_schedule {
            let (_, tx) = make_tx(nonce);
            mempool.add_transaction(tx, fee).unwrap();
        }

        let ordered = mempool.get_transactions_by_fee();
        assert_eq!(ordered.len(), 5);

        let rates: Vec<u64> = ordered
            .iter()
            .map(|(txid, _)| mempool.get_entry(txid).unwrap().fee_rate_sat_per_byte)
            .collect();

        for i in 1..rates.len() {
            assert!(
                rates[i - 1] >= rates[i],
                "fee ordering violated at index {}: {} < {}",
                i,
                rates[i - 1],
                rates[i]
            );
        }
    }

    #[test]
    fn test_rbf_replacement() {
        let mut mempool = Mempool::new(1_000_000, 100);

        let prev = Hash256::from_bytes([0xAB; 32]);
        let (old_txid, old_tx) = make_tx_spending(prev, 0, 1);

        mempool.add_transaction(old_tx.clone(), 10_000).unwrap();
        assert!(mempool.has_transaction(&old_txid));

        let (_new_txid, new_tx) = make_tx_spending(prev, 0, 2);
        mempool.add_transaction(new_tx, 25_000).unwrap();

        assert!(!mempool.has_transaction(&old_txid));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_rbf_rejection() {
        let mut mempool = Mempool::new(1_000_000, 100);

        let prev = Hash256::from_bytes([0xCD; 32]);
        let (old_txid, old_tx) = make_tx_spending(prev, 0, 1);
        mempool.add_transaction(old_tx, 150_000).unwrap();

        let (_, new_tx) = make_tx_spending(prev, 0, 2);
        let result = mempool.add_transaction(new_tx, 10_000);

        assert!(
            matches!(
                result,
                Err(MempoolError::InsufficientFeeForReplacement { .. })
            ),
            "expected InsufficientFeeForReplacement, got {:?}",
            result
        );
        assert!(mempool.has_transaction(&old_txid));
    }

    #[test]
    fn test_dust_rejection() {
        let mut mempool = Mempool::new(1_000_000, 100);

        let dust_output = TxOutput {
            value: Amount::from_sat(100).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let tx = Transaction::new_transfer(vec![], vec![dust_output], 42, 0);
        let result = mempool.add_transaction(tx, 1_000);

        assert!(
            matches!(result, Err(MempoolError::DustOutput { value: 100 })),
            "expected DustOutput, got {:?}",
            result
        );
    }

    #[test]
    fn test_ttl_eviction() {
        let mut mempool = Mempool::new(1_000_000, 100).with_ttl(Duration::from_millis(1));

        let (_, tx) = make_tx(1);
        mempool.add_transaction(tx, 1_000).unwrap();
        assert_eq!(mempool.len(), 1);

        std::thread::sleep(Duration::from_millis(10));

        let evicted = mempool.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_stats() {
        let mut mempool = Mempool::new(1_000_000, 100);

        let (_, tx1) = make_tx(1);
        let (_, tx2) = make_tx(2);
        let (_, tx3) = make_tx(3);

        mempool.add_transaction(tx1, 100).unwrap();
        mempool.add_transaction(tx2, 500).unwrap();
        mempool.add_transaction(tx3, 1_000).unwrap();

        let s = mempool.stats();
        assert_eq!(s.tx_count, 3);
        assert!(s.size_bytes > 0);
        assert_eq!(s.total_fees_sat, 1_600);
        assert!(s.min_fee_rate <= s.median_fee_rate);
        assert!(s.median_fee_rate <= s.max_fee_rate);
    }

    #[test]
    fn test_stats_empty() {
        let mempool = Mempool::new(1_000_000, 100);
        let s = mempool.stats();
        assert_eq!(s.tx_count, 0);
        assert_eq!(s.total_fees_sat, 0);
        assert_eq!(s.min_fee_rate, 0);
    }

    #[test]
    fn test_spender_tracking() {
        let mut mempool = Mempool::new(1_000_000, 100);

        let prev = Hash256::from_bytes([0x11; 32]);
        let (txid, tx) = make_tx_spending(prev, 0, 1);
        mempool.add_transaction(tx, 10_000).unwrap();

        assert_eq!(mempool.get_spenders(&prev, 0), Some(txid));
        assert!(mempool.is_input_spent(&prev, 0));

        mempool.remove_transaction(&txid).unwrap();
        assert_eq!(mempool.get_spenders(&prev, 0), None);
        assert!(!mempool.is_input_spent(&prev, 0));
    }

    #[test]
    fn test_add_transaction_with_utxo_values() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (txid, tx) = make_tx(77);

        mempool.add_transaction_with_utxo_values(tx, 2_000).unwrap();

        let entry = mempool.get_entry(&txid).unwrap();
        assert_eq!(entry.fee_sat, 1_000);
    }

    #[test]
    fn test_get_entry_metadata() {
        let mut mempool = Mempool::new(1_000_000, 100);
        let (txid, tx) = make_tx(55);
        mempool.add_transaction(tx, 500).unwrap();

        let entry = mempool.get_entry(&txid).unwrap();
        assert_eq!(entry.fee_sat, 500);
        assert!(entry.size_bytes > 0);
        assert!(entry.fee_rate_sat_per_byte >= 1);
        assert!(entry.inserted_at.elapsed().as_secs() < 5);
    }

    #[test]
    fn test_dynamic_min_fee_rate_scales_with_usage() {
        let mempool = Mempool::new(1000, 10);

        assert_eq!(mempool.dynamic_min_fee_rate(), mempool.min_fee_rate);

        let rate = mempool.dynamic_min_fee_rate();
        assert!(rate >= 1, "fee rate must be at least 1 sat/byte");
    }

    #[test]
    fn test_dynamic_fee_rate_at_90_percent_full() {
        let mempool = Mempool::new(1000, 100);
        assert_eq!(mempool.dynamic_min_fee_rate(), 1);
    }

    #[test]
    fn test_fee_percentiles_empty_mempool() {
        let mempool = Mempool::new(300_000_000, 50_000);
        assert!(mempool.get_fee_percentiles().is_none());
    }

    #[test]
    fn test_fee_percentiles_single_tx() {
        let mempool = Mempool::new(300_000_000, 50_000);
        let rates = mempool.recommended_fee_rates();
        assert_eq!(rates.slow, rates.medium);
        assert_eq!(rates.medium, rates.fast);
        assert!(rates.min_relay >= 1);
    }

    #[test]
    fn test_recommended_fee_rates_empty_fallback() {
        let mempool = Mempool::new(300_000_000, 50_000);
        let rates = mempool.recommended_fee_rates();
        assert_eq!(rates.slow, 1);
        assert_eq!(rates.medium, 1);
        assert_eq!(rates.fast, 1);
        assert_eq!(rates.next_block, 1);
    }
}
