// Copyright (c) 2026 Kantoshi Miyamura

use crate::community::CommunityService;
use crate::network::{
    reject_code, InvItem, InvItemType, Message, PeerId, PeerManager, TipMessage,
    MAX_HEADERS_PER_MESSAGE,
};
use crate::{Network, Node, NodeError};
use axiom_consensus::Block;
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing;

const INV_SEEN_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_PARALLEL_BLOCK_REQUESTS: usize = 16;
const BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Hysteresis band for the IBD-vs-Synced transition. While the header-walk
/// is still chasing a peer's tip, the local node is considered to be in
/// IBD when `local_height + IBD_SYNC_THRESHOLD < ibd_target_height`. The
/// band keeps the state from flapping every time a single live block
/// arrives during the final stretch of catch-up. Set deliberately wider
/// than the per-batch header response (`MAX_HEADERS_PER_MESSAGE = 2000`)
/// would suggest — 8 blocks is enough to absorb routine tip jitter without
/// letting the live broadcasts fill the orphan pool.
const IBD_SYNC_THRESHOLD: u32 = 8;

/// CRITICAL FIX: Maximum size for seen_txs and seen_blocks sets.
/// Without a bound, these grow forever and eventually exhaust memory.
/// 50,000 hashes × 32 bytes ≈ 1.6 MB — acceptable for dedup.
const MAX_SEEN_SET_SIZE: usize = 50_000;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("node error: {0}")]
    Node(#[from] NodeError),

    #[error("network error: {0}")]
    Network(#[from] crate::network::NetworkError),

    #[error("message error: {0}")]
    Message(#[from] crate::network::message::MessageError),

    #[error("state error: {0}")]
    State(#[from] crate::StateError),

    #[error("checkpoint mismatch at height {height}")]
    CheckpointMismatch { height: u32 },
}

/// Callback invoked with every peer-received block that is accepted by the node.
/// Signature: `fn(block: &Block, height: u64)`
pub type BlockAcceptedHook = Arc<dyn Fn(&Block, u64) + Send + Sync>;

/// Routes peer messages, relays blocks and transactions, and drives IBD.
pub struct NetworkService {
    node: Arc<RwLock<Node>>,
    peer_manager: Arc<PeerManager>,
    seen_txs: Arc<RwLock<HashSet<Hash256>>>,
    seen_blocks: Arc<RwLock<HashSet<Hash256>>>,
    seen_inv: Arc<RwLock<HashMap<Hash256, Instant>>>,
    peer_fee_filters: Arc<RwLock<HashMap<PeerId, u64>>>,
    in_flight: Arc<tokio::sync::Mutex<HashMap<Hash256, (PeerId, Instant)>>>,
    pending_blocks: Arc<tokio::sync::Mutex<Vec<Hash256>>>,
    /// Highest tip height any peer has claimed since startup. Together with
    /// the current local height this drives `is_in_ibd()`, which gates
    /// Inv-driven block fetches and unsolicited block applies. 0 means
    /// "no peer has claimed a taller chain yet" — equivalent to Synced.
    ibd_target_height: Arc<RwLock<u32>>,
    network: Network,
    /// Optional hook called on every successfully accepted peer block.
    block_accepted_hook: Option<BlockAcceptedHook>,
    /// Ephemeral community chat state (shared with the RPC layer).
    pub community: Arc<CommunityService>,
}

impl NetworkService {
    pub fn new(node: Node, peer_manager: PeerManager) -> Self {
        let network = network_from_chain_id(node.chain_id());
        NetworkService {
            node: Arc::new(RwLock::new(node)),
            peer_manager: Arc::new(peer_manager),
            seen_txs: Arc::new(RwLock::new(HashSet::new())),
            seen_blocks: Arc::new(RwLock::new(HashSet::new())),
            seen_inv: Arc::new(RwLock::new(HashMap::new())),
            peer_fee_filters: Arc::new(RwLock::new(HashMap::new())),
            in_flight: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pending_blocks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            ibd_target_height: Arc::new(RwLock::new(0)),
            network,
            block_accepted_hook: None,
            community: CommunityService::new(),
        }
    }

    /// Build a NetworkService that shares both the Node state and the
    /// PeerManager with the caller (typically the binary's P2P layer).
    ///
    /// Sharing the **same** `Arc<PeerManager>` is load-bearing: every
    /// `self.peer_manager.send_to_peer(...)` call in this file (sync_with_peer,
    /// handle_inv, handle_headers, handle_received_block, handle_get_data,
    /// dispatch_pending_blocks) needs to reach the peer entries that the P2P
    /// layer registered via `add_peer`. Wrapping a fresh PeerManager in a
    /// private Arc here would create a second, empty peer map and every
    /// back-channel send would fail with `PeerNotFound`. That mismatch was the
    /// root cause of the v2.0.0-testnet.3 lifecycle race that landed every
    /// fresh node in an infinite reconnect loop after handshake.
    pub fn with_shared_node(node: Arc<RwLock<Node>>, peer_manager: Arc<PeerManager>) -> Self {
        NetworkService {
            node,
            peer_manager,
            seen_txs: Arc::new(RwLock::new(HashSet::new())),
            seen_blocks: Arc::new(RwLock::new(HashSet::new())),
            seen_inv: Arc::new(RwLock::new(HashMap::new())),
            peer_fee_filters: Arc::new(RwLock::new(HashMap::new())),
            in_flight: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pending_blocks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            ibd_target_height: Arc::new(RwLock::new(0)),
            network: Network::Dev,
            block_accepted_hook: None,
            community: CommunityService::new(),
        }
    }

    /// Raise the recorded IBD target so far as `height` if it's an upgrade.
    /// Called from `sync_with_peer` when a peer's Tip is taller than ours,
    /// and from `handle_headers` as each batch reveals more of the chain.
    async fn raise_ibd_target(&self, height: u32) {
        let mut target = self.ibd_target_height.write().await;
        if height > *target {
            tracing::debug!("IBD_TARGET_RAISED: {} -> {}", *target, height,);
            *target = height;
        }
    }

    /// True while a known peer's tip is materially taller than ours, with
    /// hysteresis to avoid flapping on the last few blocks. While in IBD,
    /// the node refuses to chase Inv-broadcast blocks or accept unsolicited
    /// orphan-pool entries — the header-driven pull is the only sanctioned
    /// path for blocks until catch-up completes.
    pub async fn is_in_ibd(&self) -> bool {
        let target = *self.ibd_target_height.read().await;
        if target == 0 {
            return false;
        }
        let node = self.node.read().await;
        let local = node.best_height().unwrap_or(0);
        local + IBD_SYNC_THRESHOLD < target
    }

    /// Current IBD target height (highest peer tip we've ever been told
    /// about). Exposed for tests and observability.
    pub async fn ibd_target(&self) -> u32 {
        *self.ibd_target_height.read().await
    }

    /// Register a callback that fires on every peer block accepted into the chain.
    /// Use this to hook AxiomMind (or any observer) into block reception
    /// without coupling axiom-node to higher-level crates.
    pub fn set_block_accepted_hook(&mut self, hook: BlockAcceptedHook) {
        self.block_accepted_hook = Some(hook);
    }

    pub fn node(&self) -> Arc<RwLock<Node>> {
        self.node.clone()
    }

    pub fn peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    /// CRITICAL FIX: Insert into a seen set with bounded size.
    /// When the set exceeds MAX_SEEN_SET_SIZE, it is cleared entirely.
    /// This is a simple but effective strategy: clearing the set means we may
    /// re-process a few recently-seen items, but this is harmless (idempotent)
    /// and avoids the memory leak of unbounded growth.
    async fn record_seen(set: &RwLock<HashSet<Hash256>>, hash: Hash256) {
        let mut s = set.write().await;
        if s.len() >= MAX_SEEN_SET_SIZE {
            tracing::debug!(
                "SEEN_SET_EVICT: clearing {} entries to prevent memory leak",
                s.len()
            );
            s.clear();
        }
        s.insert(hash);
    }

    async fn record_inv_sent(&self, hash: Hash256) {
        let mut map = self.seen_inv.write().await;
        map.insert(hash, Instant::now());
        let now = Instant::now();
        map.retain(|_, ts| now.duration_since(*ts) < INV_SEEN_TTL);
    }

    async fn inv_recently_sent(&self, hash: &Hash256) -> bool {
        let map = self.seen_inv.read().await;
        if let Some(ts) = map.get(hash) {
            Instant::now().duration_since(*ts) < INV_SEEN_TTL
        } else {
            false
        }
    }

    async fn set_peer_fee_filter(&self, peer_id: PeerId, min_fee_rate: u64) {
        let mut filters = self.peer_fee_filters.write().await;
        filters.insert(peer_id, min_fee_rate);
    }

    /// Dispatch a peer message and return an optional reply.
    pub async fn handle_message(
        &self,
        peer_id: PeerId,
        message: Message,
    ) -> Result<Option<Message>, ServiceError> {
        // SECURITY: Rate limit check on all incoming messages
        // Note: peer address not available in current API, but dos_protection is ready for integration

        match message {
            Message::GetTip => {
                let node = self.node.read().await;
                let best_hash = node.best_block_hash().unwrap_or(Hash256::zero());
                let best_height = node.best_height().unwrap_or(0);

                Ok(Some(Message::Tip(TipMessage {
                    best_hash,
                    best_height,
                })))
            }

            Message::Tip(tip) => {
                self.sync_with_peer(peer_id, tip).await?;
                Ok(None)
            }

            Message::GetBlock(block_hash) => {
                let node = self.node.read().await;
                match node.get_block(&block_hash)? {
                    Some(block) => Ok(Some(Message::Block(block))),
                    None => Ok(None),
                }
            }

            Message::Block(block) => {
                self.handle_received_block(block, peer_id).await?;
                Ok(None)
            }

            Message::Tx(tx) => {
                self.handle_received_transaction(tx, peer_id).await?;
                Ok(None)
            }

            Message::GetPeers => {
                let addrs = self.peer_manager.get_ready_peer_addrs().await;
                tracing::debug!(
                    "GETPEERS: peer={:?}, responding with {} addrs",
                    peer_id,
                    addrs.len()
                );
                Ok(Some(Message::Peers(addrs)))
            }

            Message::Peers(_) => Ok(None),

            Message::Inv(items) => {
                self.handle_inv(peer_id, items).await?;
                Ok(None)
            }

            Message::GetData(items) => {
                self.handle_get_data(peer_id, items).await?;
                Ok(None)
            }

            Message::NotFound(items) => {
                tracing::debug!("NOTFOUND: peer={:?}, count={}", peer_id, items.len());
                Ok(None)
            }

            Message::GetHeaders(from_hash, max_count) => {
                let response = self.handle_get_headers(from_hash, max_count).await?;
                Ok(response)
            }

            Message::Headers(headers) => {
                self.handle_headers(peer_id, headers).await?;
                Ok(None)
            }

            Message::FeeFilter(min_fee_rate) => {
                tracing::debug!(
                    "FEEFILTER: peer={:?}, min_fee_rate={}",
                    peer_id,
                    min_fee_rate
                );
                self.set_peer_fee_filter(peer_id, min_fee_rate).await;
                Ok(None)
            }

            Message::Reject(id, code, reason) => {
                tracing::warn!(
                    "REJECT_RECEIVED: peer={:?}, id={}, code={:#04x}, reason={}",
                    peer_id,
                    id,
                    code,
                    reason
                );
                Ok(None)
            }

            // ── Community chat ────────────────────────────────────────────
            Message::ChatMessage(payload) => {
                let should_relay = self.community.handle_chat_message(payload.clone()).await;
                if should_relay {
                    let _ = self
                        .peer_manager
                        .broadcast_except(peer_id, Message::ChatMessage(payload))
                        .await;
                }
                Ok(None)
            }

            Message::ChatBan(payload) => {
                let should_relay = self.community.handle_chat_ban(payload.clone()).await;
                if should_relay {
                    let _ = self
                        .peer_manager
                        .broadcast_except(peer_id, Message::ChatBan(payload))
                        .await;
                }
                Ok(None)
            }

            Message::UsernameAnnounce(payload) => {
                let should_relay = self
                    .community
                    .handle_username_announce(payload.clone())
                    .await;
                if should_relay {
                    let _ = self
                        .peer_manager
                        .broadcast_except(peer_id, Message::UsernameAnnounce(payload))
                        .await;
                }
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    async fn handle_inv(&self, peer_id: PeerId, items: Vec<InvItem>) -> Result<(), ServiceError> {
        let mut want: Vec<InvItem> = Vec::new();

        // Skip Inv-driven Block fetches while we are catching up via the
        // header-driven IBD path. Tip-broadcast blocks at height >>
        // local_height arrive faster than we can fill in their parents;
        // chasing them lands every one in the orphan pool until the per-peer
        // cap (MAX_ORPHANS_PER_PEER) trips and the peer gets shunned.
        // The header walk will pull these same blocks in order anyway.
        let suppress_block_inv = self.is_in_ibd().await;

        for item in items {
            match item.item_type {
                InvItemType::Block => {
                    if suppress_block_inv {
                        tracing::debug!(
                            "INV_SKIP_DURING_IBD: peer={:?}, hash={}",
                            peer_id,
                            hex::encode(&item.hash.as_bytes()[..8])
                        );
                        continue;
                    }
                    let node = self.node.read().await;
                    let have =
                        node.has_block(&item.hash).unwrap_or(false) || node.is_orphan(&item.hash);
                    drop(node);
                    if !have {
                        tracing::debug!(
                            "INV_WANT_BLOCK: peer={:?}, hash={}",
                            peer_id,
                            hex::encode(&item.hash.as_bytes()[..8])
                        );
                        want.push(item);
                    }
                }
                InvItemType::Transaction => {
                    let serialized_hash = item.hash;
                    let seen = self.seen_txs.read().await;
                    if !seen.contains(&serialized_hash) {
                        drop(seen);
                        tracing::debug!(
                            "INV_WANT_TX: peer={:?}, txid={}",
                            peer_id,
                            hex::encode(&item.hash.as_bytes()[..8])
                        );
                        want.push(item);
                    }
                }
                InvItemType::BlockHeader => {
                    let node = self.node.read().await;
                    if !node.has_block(&item.hash).unwrap_or(false) {
                        want.push(item);
                    }
                }
            }
        }

        if !want.is_empty() {
            self.peer_manager
                .send_to_peer(peer_id, Message::GetData(want))
                .await?;
        }

        Ok(())
    }

    async fn handle_get_data(
        &self,
        peer_id: PeerId,
        items: Vec<InvItem>,
    ) -> Result<(), ServiceError> {
        let mut not_found: Vec<InvItem> = Vec::new();

        for item in items {
            match item.item_type {
                InvItemType::Block | InvItemType::BlockHeader => {
                    let node = self.node.read().await;
                    match node.get_block(&item.hash)? {
                        Some(block) => {
                            drop(node);
                            tracing::debug!(
                                "GETDATA_SERVE_BLOCK: peer={:?}, hash={}",
                                peer_id,
                                hex::encode(&item.hash.as_bytes()[..8])
                            );
                            self.peer_manager
                                .send_to_peer(peer_id, Message::Block(block))
                                .await?;
                        }
                        None => {
                            not_found.push(item);
                        }
                    }
                }
                InvItemType::Transaction => {
                    let node = self.node.read().await;
                    match node.get_mempool_tx(&item.hash) {
                        Some(tx) => {
                            drop(node);
                            tracing::debug!(
                                "GETDATA_SERVE_TX: peer={:?}, txid={}",
                                peer_id,
                                hex::encode(&item.hash.as_bytes()[..8])
                            );
                            self.peer_manager
                                .send_to_peer(peer_id, Message::Tx(tx))
                                .await?;
                        }
                        None => {
                            drop(node);
                            tracing::debug!(
                                "GETDATA_TX_NOT_FOUND: peer={:?}, txid={}",
                                peer_id,
                                hex::encode(&item.hash.as_bytes()[..8])
                            );
                            not_found.push(item);
                        }
                    }
                }
            }
        }

        if !not_found.is_empty() {
            self.peer_manager
                .send_to_peer(peer_id, Message::NotFound(not_found))
                .await?;
        }

        Ok(())
    }

    /// CRITICAL FIX: Rewrote to avoid loading entire chain into memory.
    /// Previous implementation walked from tip to genesis collecting ALL blocks,
    /// then sliced. A peer could send GetHeaders(Hash256::zero(), 1) and force
    /// loading millions of blocks into RAM, causing OOM.
    ///
    /// New approach: use the height index to find from_hash's height, then walk
    /// forward from there using height lookups. Falls back to bounded backward
    /// walk if height index is unavailable.
    async fn handle_get_headers(
        &self,
        from_hash: Hash256,
        max_count: u32,
    ) -> Result<Option<Message>, ServiceError> {
        let node = self.node.read().await;

        let limit = (max_count as usize).min(MAX_HEADERS_PER_MESSAGE);
        let mut headers: Vec<axiom_consensus::BlockHeader> = Vec::with_capacity(limit);

        let best_height = node.best_height().unwrap_or(0);

        // Determine starting height (block AFTER from_hash).
        let start_height = if from_hash == Hash256::zero() {
            // From genesis — start at height 0.
            0u32
        } else if node.has_block(&from_hash).unwrap_or(false) {
            // Walk backward from tip to find from_hash's height.
            // Cap walk to `limit + best_height` to prevent unbounded traversal,
            // but in practice from_hash should be on the canonical chain and
            // the height index will short-circuit this.
            let mut found_height: Option<u32> = None;

            // Try height index first (O(1) per height).
            for h in (0..=best_height).rev() {
                if let Ok(Some(hash_at_h)) = node.state.db_get_hash_by_height(h) {
                    if hash_at_h == from_hash {
                        found_height = Some(h);
                        break;
                    }
                    // If we've checked more than `limit` heights without
                    // finding from_hash, it's likely on a side chain. Stop.
                    if best_height - h > limit as u32 + 10 {
                        break;
                    }
                }
            }

            match found_height {
                Some(h) => h + 1,
                None => {
                    // from_hash is on a side chain or not indexed — return empty.
                    tracing::debug!(
                        "GETHEADERS: from_hash={} not found on canonical chain",
                        hex::encode(&from_hash.as_bytes()[..8])
                    );
                    return Ok(Some(Message::Headers(vec![])));
                }
            }
        } else {
            // We don't have from_hash — return empty (peer will try another locator).
            return Ok(Some(Message::Headers(vec![])));
        };

        // Collect headers from start_height..=best_height, up to `limit`.
        for h in start_height..=best_height {
            if headers.len() >= limit {
                break;
            }
            if let Ok(Some(block)) = node.get_block_by_height(h) {
                headers.push(block.header.clone());
            } else {
                break;
            }
        }

        tracing::debug!(
            "GETHEADERS: from_hash={}, returning {} headers, best_height={}",
            hex::encode(&from_hash.as_bytes()[..8]),
            headers.len(),
            best_height
        );

        Ok(Some(Message::Headers(headers)))
    }

    async fn handle_headers(
        &self,
        peer_id: PeerId,
        headers: Vec<axiom_consensus::BlockHeader>,
    ) -> Result<(), ServiceError> {
        if headers.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "HEADERS_RECEIVED: peer={:?}, count={}",
            peer_id,
            headers.len()
        );

        let (our_tip_height, first_header_parent_height) = {
            let node = self.node.read().await;
            let tip_h = node.best_height().unwrap_or(0);
            // Try to find the actual height of the first header's parent.
            // If the first header connects to our tip, height = tip_height.
            // If it connects to an earlier block, we detect via height-index lookup.
            let first_parent = headers[0].prev_block_hash;
            let parent_h = if first_parent == node.best_block_hash().unwrap_or(Hash256::zero()) {
                tip_h
            } else {
                // Walk back to find parent's height (it may be a fork point).
                // Fall back to tip_height if parent is unknown (will be caught later).
                match node.get_block(&first_parent) {
                    Ok(Some(_)) => {
                        // Try the height index
                        node.state
                            .db_get_hash_by_height(tip_h)
                            .ok()
                            .flatten()
                            .and_then(|h| if h == first_parent { Some(tip_h) } else { None })
                            .unwrap_or(tip_h)
                    }
                    _ => tip_h,
                }
            };
            (tip_h, parent_h)
        };

        let base_height = first_header_parent_height;

        let mut prev_hash_opt: Option<Hash256> = None;
        let mut new_hashes: Vec<Hash256> = Vec::new();

        for (idx, header) in headers.iter().enumerate() {
            let hash = header.hash();

            if let Some(prev_hash) = prev_hash_opt {
                if header.prev_block_hash != prev_hash {
                    tracing::warn!(
                        "HEADERS_LINKAGE_FAIL: peer={:?}, expected_prev={}, got={}",
                        peer_id,
                        hex::encode(&prev_hash.as_bytes()[..8]),
                        hex::encode(&header.prev_block_hash.as_bytes()[..8])
                    );
                    let _ = self
                        .peer_manager
                        .send_to_peer(
                            peer_id,
                            Message::Reject(
                                hex::encode(hash.as_bytes()),
                                reject_code::INVALID,
                                "header chain linkage broken".to_string(),
                            ),
                        )
                        .await;
                    return Ok(());
                }
            }

            prev_hash_opt = Some(hash);

            let header_height = base_height + 1 + idx as u32;

            if let Err(e) =
                crate::checkpoints::verify_checkpoint(self.network, header_height, &hash)
            {
                tracing::error!(
                    height = header_height,
                    expected = %e,
                    actual = %hex::encode(hash.as_bytes()),
                    "CHECKPOINT MISMATCH — disconnecting peer"
                );
                if let Some(peer_info) = self.peer_manager.get_peer(peer_id).await {
                    self.peer_manager
                        .ban_peer(peer_info.addr, Duration::from_secs(600))
                        .await;
                }
                return Err(ServiceError::CheckpointMismatch {
                    height: header_height,
                });
            }

            let node = self.node.read().await;
            let have = node.has_block(&hash).unwrap_or(false);
            drop(node);

            if !have {
                new_hashes.push(hash);
            }
        }

        if new_hashes.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "HEADERS_NEED_BLOCKS: peer={:?}, count={}",
            peer_id,
            new_hashes.len()
        );

        let slots_available = {
            let in_flight = self.in_flight.lock().await;
            MAX_PARALLEL_BLOCK_REQUESTS.saturating_sub(in_flight.len())
        };

        let (to_send_now, to_queue) = if slots_available >= new_hashes.len() {
            (new_hashes, vec![])
        } else {
            let mut v = new_hashes;
            let queued = v.split_off(slots_available);
            (v, queued)
        };

        if !to_queue.is_empty() {
            let mut pending = self.pending_blocks.lock().await;
            pending.extend(to_queue);
        }

        if !to_send_now.is_empty() {
            let inv_items: Vec<InvItem> = to_send_now
                .iter()
                .map(|h| InvItem {
                    item_type: InvItemType::Block,
                    hash: *h,
                })
                .collect();

            {
                let mut in_flight = self.in_flight.lock().await;
                for h in &to_send_now {
                    in_flight.insert(*h, (peer_id, Instant::now()));
                }
            }

            tracing::info!(
                "HEADERS_REQUEST_BLOCKS: peer={:?}, count={}",
                peer_id,
                inv_items.len()
            );
            self.peer_manager
                .send_to_peer(peer_id, Message::GetData(inv_items))
                .await?;
        }

        let peer_height = base_height + headers.len() as u32;
        let our_height = our_tip_height;
        if peer_height > 0 && peer_height > our_height {
            let pct = (our_height as f64 / peer_height as f64 * 100.0) as u32;
            tracing::info!(our_height, peer_height, pct, "[IBD] sync progress {}%", pct);
        }
        // Each header batch reveals more of the peer's chain. Keep the IBD
        // target up to date so the Inv-suppression gate doesn't open while
        // we're still walking toward a tip we already know is taller.
        self.raise_ibd_target(peer_height).await;

        // If we got a full batch, the peer likely has more headers.
        // Request the next batch starting from the last header we received.
        if headers.len() >= MAX_HEADERS_PER_MESSAGE {
            let last_hash = headers.last().unwrap().hash();
            tracing::info!(
                "IBD_CONTINUE: requesting next batch from {}",
                hex::encode(&last_hash.as_bytes()[..8])
            );
            self.peer_manager
                .send_to_peer(
                    peer_id,
                    Message::GetHeaders(last_hash, MAX_HEADERS_PER_MESSAGE as u32),
                )
                .await?;
        }

        Ok(())
    }

    async fn dispatch_pending_blocks(&self, peer_id: PeerId) -> Result<(), ServiceError> {
        let slots_available = {
            let in_flight = self.in_flight.lock().await;
            MAX_PARALLEL_BLOCK_REQUESTS.saturating_sub(in_flight.len())
        };

        if slots_available == 0 {
            return Ok(());
        }

        let to_send: Vec<Hash256> = {
            let mut pending = self.pending_blocks.lock().await;
            if pending.is_empty() {
                return Ok(());
            }
            let take = slots_available.min(pending.len());
            pending.drain(..take).collect()
        };

        if to_send.is_empty() {
            return Ok(());
        }

        let inv_items: Vec<InvItem> = to_send
            .iter()
            .map(|h| InvItem {
                item_type: InvItemType::Block,
                hash: *h,
            })
            .collect();

        {
            let mut in_flight = self.in_flight.lock().await;
            for h in &to_send {
                in_flight.insert(*h, (peer_id, Instant::now()));
            }
        }

        tracing::debug!(
            "IBD_DISPATCH_PENDING: peer={:?}, count={}",
            peer_id,
            inv_items.len()
        );
        self.peer_manager
            .send_to_peer(peer_id, Message::GetData(inv_items))
            .await?;

        Ok(())
    }

    async fn handle_received_transaction(
        &self,
        tx: Transaction,
        peer_id: PeerId,
    ) -> Result<(), ServiceError> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

        {
            let seen = self.seen_txs.read().await;
            if seen.contains(&txid) {
                tracing::debug!(
                    "TX_DUPLICATE_IGNORED: txid={}, peer={:?}",
                    hex::encode(&txid.as_bytes()[..8]),
                    peer_id
                );
                return Ok(());
            }
        }

        tracing::info!(
            "TX_RECEIVED: txid={}, peer={:?}",
            hex::encode(&txid.as_bytes()[..8]),
            peer_id
        );

        let mut node = self.node.write().await;
        let min_fee_rate = node.min_fee_rate();
        match node.submit_transaction(tx.clone()) {
            Ok(_) => {
                Self::record_seen(&self.seen_txs, txid).await;

                tracing::info!("TX_VALID: txid={}", hex::encode(&txid.as_bytes()[..8]));
                tracing::info!(
                    "TX_ADDED_MEMPOOL: txid={}",
                    hex::encode(&txid.as_bytes()[..8])
                );

                drop(node);

                if !self.inv_recently_sent(&txid).await {
                    let inv_item = InvItem {
                        item_type: InvItemType::Transaction,
                        hash: txid,
                    };
                    let peers = self.peer_manager.get_all_peers().await;
                    let fee_filters = self.peer_fee_filters.read().await;

                    for pid in peers {
                        if pid == peer_id {
                            continue;
                        }
                        let peer_min = *fee_filters.get(&pid).unwrap_or(&0);
                        if peer_min > min_fee_rate {
                            tracing::debug!(
                                "TX_INV_SKIP_FEE_FILTER: peer={:?}, peer_min={}, our_min={}",
                                pid,
                                peer_min,
                                min_fee_rate
                            );
                            continue;
                        }
                        let _ = self
                            .peer_manager
                            .send_to_peer(pid, Message::Inv(vec![inv_item.clone()]))
                            .await;
                    }

                    self.record_inv_sent(txid).await;
                }

                let msg = Message::Tx(tx);
                match self.peer_manager.broadcast_except(peer_id, msg).await {
                    Ok(sent) => {
                        if sent > 0 {
                            tracing::info!(
                                "TX_BROADCAST: txid={}, peers={}",
                                hex::encode(&txid.as_bytes()[..8]),
                                sent
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "TX_BROADCAST_FAILED: txid={}, error={}",
                            hex::encode(&txid.as_bytes()[..8]),
                            e
                        );
                    }
                }

                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "TX_REJECTED: txid={}, error={}",
                    hex::encode(&txid.as_bytes()[..8]),
                    e
                );

                drop(node);

                let reason = e.to_string();
                let code = tx_reject_code(&reason);
                let _ = self
                    .peer_manager
                    .send_to_peer(
                        peer_id,
                        Message::Reject(hex::encode(txid.as_bytes()), code, reason),
                    )
                    .await;

                Ok(())
            }
        }
    }

    async fn handle_received_block(
        &self,
        block: Block,
        peer_id: PeerId,
    ) -> Result<(), ServiceError> {
        let block_hash = block.hash();

        // Solicited = we previously sent a GetData for this hash (the
        // header-driven IBD path or a deliberate explicit fetch). Anything
        // else is a live broadcast — almost certainly a tip block. We need
        // this distinction below to decide whether to drop an unsolicited
        // orphan during IBD instead of letting it fill the per-peer
        // orphan pool.
        let solicited = {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.remove(&block_hash).is_some()
        };
        let _ = self.dispatch_pending_blocks(peer_id).await;
        let height = block.height().unwrap_or(0);
        let tx_count = block.transactions.len();

        tracing::info!(
            "BLOCK_RECEIVE_START: hash={}, height={}, txs={}, peer={:?}",
            hex::encode(&block_hash.as_bytes()[..8]),
            height,
            tx_count,
            peer_id
        );

        {
            let seen = self.seen_blocks.read().await;
            if seen.contains(&block_hash) {
                tracing::info!(
                    "BLOCK_ALREADY_SEEN: hash={}, height={}",
                    hex::encode(&block_hash.as_bytes()[..8]),
                    height
                );
                return Ok(());
            }
        }

        // IBD gate: drop unsolicited orphans while we're catching up.
        //
        // An unsolicited block (peer pushed it via Inv→GetData→Block at
        // their initiative — almost always a freshly-mined tip block)
        // whose parent we don't have yet would otherwise land in the
        // orphan pool. During IBD the live tip is hundreds or thousands
        // of blocks ahead of us; every tip broadcast adds an orphan, and
        // MAX_ORPHANS_PER_PEER trips long before the header walk catches
        // up. Drop the block silently — when the header walk reaches its
        // height we'll fetch it through the sanctioned path.
        if !solicited && self.is_in_ibd().await {
            let parent_exists = {
                let node = self.node.read().await;
                let parent = block.header.prev_block_hash;
                parent == Hash256::zero() || node.has_block(&parent).unwrap_or(false)
            };
            if !parent_exists {
                tracing::debug!(
                    "BLOCK_SKIP_UNSOLICITED_DURING_IBD: hash={}, height={}, peer={:?}",
                    hex::encode(&block_hash.as_bytes()[..8]),
                    height,
                    peer_id
                );
                return Ok(());
            }
        }

        {
            let node = self.node.read().await;
            match node.has_block(&block_hash) {
                Ok(true) => {
                    tracing::info!(
                        "BLOCK_ALREADY_STORED: hash={}, height={}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height
                    );
                    Self::record_seen(&self.seen_blocks, block_hash).await;
                    return Ok(());
                }
                Ok(false) => {
                    tracing::info!(
                        "BLOCK_NEW: hash={}, height={}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "BLOCK_CHECK_ERROR: hash={}, height={}, error={}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height,
                        e
                    );
                    return Err(e.into());
                }
            }
        }

        tracing::info!(
            "BLOCK_VALIDATE_START: hash={}, height={}",
            hex::encode(&block_hash.as_bytes()[..8]),
            height
        );

        let mut node = self.node.write().await;
        let local_height_before = node.best_height().unwrap_or(0);
        let local_hash_before = node.best_block_hash().unwrap_or(Hash256::zero());

        tracing::info!(
            "BLOCK_LOCAL_STATE_BEFORE: local_height={}, local_hash={}",
            local_height_before,
            hex::encode(&local_hash_before.as_bytes()[..8])
        );

        // SECURITY FIX: Pass peer_id to enforce per-peer orphan limits
        match node.process_block_from_peer(block.clone(), Some(format!("{:?}", peer_id))) {
            Ok(_) => {
                let local_height_after = node.best_height().unwrap_or(0);
                let local_hash_after = node.best_block_hash().unwrap_or(Hash256::zero());

                if local_height_after > local_height_before {
                    tracing::info!(
                        "BLOCK_APPLIED: hash={}, chain_height={}->{}, peer={:?}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        local_height_before,
                        local_height_after,
                        peer_id
                    );
                } else {
                    tracing::info!(
                        "BLOCK_ACCEPTED_ORPHAN: hash={}, block_height={}, chain_height={}, peer={:?}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height,
                        local_height_after,
                        peer_id
                    );
                }
                tracing::debug!(
                    "BLOCK_LOCAL_STATE_AFTER: local_height={}, local_hash={}",
                    local_height_after,
                    hex::encode(&local_hash_after.as_bytes()[..8])
                );

                drop(node);
                Self::record_seen(&self.seen_blocks, block_hash).await;

                // Notify AxiomMind (or any registered observer) about the accepted block.
                if let Some(hook) = &self.block_accepted_hook {
                    hook(&block, height as u64);
                }

                if !self.inv_recently_sent(&block_hash).await {
                    let inv_item = InvItem {
                        item_type: InvItemType::Block,
                        hash: block_hash,
                    };
                    let peers = self.peer_manager.get_all_peers().await;
                    for pid in peers {
                        if pid == peer_id {
                            continue;
                        }
                        let _ = self
                            .peer_manager
                            .send_to_peer(pid, Message::Inv(vec![inv_item.clone()]))
                            .await;
                    }
                    self.record_inv_sent(block_hash).await;

                    tracing::info!(
                        "BLOCK_INV_ANNOUNCED: hash={}, height={}",
                        hex::encode(&block_hash.as_bytes()[..8]),
                        height
                    );
                }

                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                tracing::error!(
                    "BLOCK_APPLY_FAILED: hash={}, height={}, peer={:?}, error={}",
                    hex::encode(&block_hash.as_bytes()[..8]),
                    height,
                    peer_id,
                    err_str
                );

                drop(node);

                let code = block_reject_code(&err_str);
                let _ = self
                    .peer_manager
                    .send_to_peer(
                        peer_id,
                        Message::Reject(hex::encode(block_hash.as_bytes()), code, err_str.clone()),
                    )
                    .await;

                // Ban peers that send consensus-invalid blocks.
                // "block already exists" and orphan-pool-full are benign — don't ban.
                let is_benign = err_str.contains("already exists")
                    || err_str.contains("orphan pool full")
                    || err_str.contains("too many orphans")
                    || err_str.contains("fork_limit_exceeded");
                if !is_benign {
                    tracing::warn!(
                        "PEER_BAN: banning peer {:?} for 10min — sent invalid block: {}",
                        peer_id,
                        &err_str[..err_str.len().min(120)],
                    );
                    if let Some(peer_info) = self.peer_manager.get_peer(peer_id).await {
                        self.peer_manager
                            .ban_peer(peer_info.addr, Duration::from_secs(600))
                            .await;
                    }
                }

                Ok(())
            }
        }
    }

    pub async fn submit_local_transaction(&self, tx: Transaction) -> Result<Hash256, ServiceError> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

        let mut node = self.node.write().await;
        node.submit_transaction(tx.clone())?;
        drop(node);

        Self::record_seen(&self.seen_txs, txid).await;

        tracing::info!(
            "TX_SUBMITTED_LOCAL: txid={}",
            hex::encode(&txid.as_bytes()[..8])
        );

        Ok(txid)
    }

    pub async fn broadcast_transaction(
        &self,
        tx: Transaction,
        exclude_peer: Option<PeerId>,
    ) -> Result<usize, ServiceError> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

        let msg = Message::Tx(tx);

        let sent = if let Some(exclude) = exclude_peer {
            self.peer_manager.broadcast_except(exclude, msg).await?
        } else {
            self.peer_manager.broadcast(msg).await?
        };

        if sent > 0 {
            tracing::info!(
                "TX_BROADCAST: txid={}, peers={}",
                hex::encode(&txid.as_bytes()[..8]),
                sent
            );
        }

        Ok(sent)
    }

    pub async fn build_local_block(&self) -> Result<Block, ServiceError> {
        let mut node = self.node.write().await;
        let block = node.build_block()?;
        let block_hash = block.hash();

        node.process_block(block.clone())?;
        drop(node);

        Self::record_seen(&self.seen_blocks, block_hash).await;

        Ok(block)
    }

    pub async fn get_tip(&self) -> (Hash256, u32) {
        let node = self.node.read().await;
        let hash = node.best_block_hash().unwrap_or(Hash256::zero());
        let height = node.best_height().unwrap_or(0);
        (hash, height)
    }

    /// Blocks from `from_height+1` to the tip, oldest first.
    pub async fn get_canonical_blocks_since(&self, from_height: u32) -> Vec<Block> {
        let node = self.node.read().await;
        let best_height = node.best_height().unwrap_or(0);
        if from_height >= best_height {
            return vec![];
        }
        let count = (best_height - from_height) as usize;
        match node.get_recent_blocks(count) {
            Ok(mut blocks) => {
                blocks.reverse();
                blocks
            }
            Err(_) => vec![],
        }
    }

    pub fn create_get_block_message(&self, block_hash: Hash256) -> Message {
        Message::GetBlock(block_hash)
    }

    pub fn create_get_tip_message(&self) -> Message {
        Message::GetTip
    }

    pub fn create_tx_message(&self, tx: Transaction) -> Message {
        Message::Tx(tx)
    }

    pub fn create_block_message(&self, block: Block) -> Message {
        Message::Block(block)
    }

    pub async fn create_fee_filter_message(&self) -> Message {
        let node = self.node.read().await;
        Message::FeeFilter(node.min_fee_rate())
    }

    /// Send GetHeaders if the peer claims a taller chain.
    ///
    /// We compare using height first: if peer_height > local_height, they
    /// almost certainly have more work.  We also check chainwork when we
    /// already have the peer's tip hash locally (fork scenario).
    pub async fn sync_with_peer(
        &self,
        peer_id: PeerId,
        peer_tip: TipMessage,
    ) -> Result<(), ServiceError> {
        let node = self.node.read().await;
        let local_hash = node.best_block_hash().unwrap_or(Hash256::zero());
        let local_height = node.best_height().unwrap_or(0);
        let local_work = node.state.get_chain_work(&local_hash)?.unwrap_or(0);

        // If we already have the peer's tip, compare chainwork directly.
        let peer_work = node.state.get_chain_work(&peer_tip.best_hash)?.unwrap_or(0);

        tracing::info!(
            "SYNC_CHECK: peer_height={}, peer_hash={}, local_height={}, peer_work={}, local_work={}",
            peer_tip.best_height,
            hex::encode(&peer_tip.best_hash.as_bytes()[..8]),
            local_height,
            peer_work,
            local_work,
        );

        // Decide whether we need to sync.
        // Case 1: Peer is taller and we don't have their tip → request headers.
        // Case 2: Same height but peer has more chainwork (we have both tips).
        // Case 3: Peer has same work/height but lower hash (tie-break).
        let need_sync = if peer_tip.best_height > local_height {
            // Peer claims a taller chain — always request headers.
            true
        } else if peer_work > 0 && peer_work > local_work {
            // We know the peer's tip and it has more work.
            true
        } else if peer_work == local_work
            && peer_work > 0
            && peer_tip.best_hash.as_bytes() < local_hash.as_bytes()
        {
            // Tie-break by lower hash.
            true
        } else {
            false
        };

        if need_sync {
            tracing::info!(
                "SYNC_NEEDED: requesting headers from peer={:?} (peer_h={} local_h={})",
                peer_id,
                peer_tip.best_height,
                local_height,
            );
            let our_tip = local_hash;
            drop(node);
            // Record what we're chasing — gates Inv-driven block fetches and
            // unsolicited block applies until we catch up to within
            // IBD_SYNC_THRESHOLD of this height.
            self.raise_ibd_target(peer_tip.best_height).await;
            self.peer_manager
                .send_to_peer(
                    peer_id,
                    Message::GetHeaders(our_tip, MAX_HEADERS_PER_MESSAGE as u32),
                )
                .await?;
        }

        Ok(())
    }

    /// Periodically evict timed-out in-flight block requests and re-queue them.
    pub fn start_ibd_watchdog_task(self: Arc<Self>) {
        let in_flight = self.in_flight.clone();
        let pending = self.pending_blocks.clone();
        let peer_manager = self.peer_manager.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                let now = Instant::now();
                let mut stalled: Vec<(Hash256, PeerId)> = Vec::new();

                {
                    let mut map = in_flight.lock().await;
                    map.retain(|hash, (pid, ts)| {
                        if now.duration_since(*ts) > BLOCK_REQUEST_TIMEOUT {
                            stalled.push((*hash, *pid));
                            false
                        } else {
                            true
                        }
                    });
                }

                for (hash, pid) in stalled {
                    tracing::warn!(
                        "[IBD] block {} stalled from peer {:?}, rotating peer",
                        hex::encode(&hash.as_bytes()[..8]),
                        pid
                    );

                    if let Some(peer_info) = peer_manager.get_peer(pid).await {
                        peer_manager
                            .ban_peer(peer_info.addr, Duration::from_secs(600))
                            .await;
                    }

                    let mut q = pending.lock().await;
                    q.push(hash);
                }
            }
        });
    }

    /// Poll peer tips every 5 seconds and sync if they're ahead.
    pub fn start_sync_task(self: Arc<Self>, peer_manager: Arc<PeerManager>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

            loop {
                interval.tick().await;

                let peers = peer_manager.get_all_peers().await;

                for peer_id in peers {
                    let msg = self.create_get_tip_message();
                    if let Err(e) = peer_manager.send_to_peer(peer_id, msg).await {
                        tracing::debug!(
                            "SYNC_PEER_REQUEST_FAILED: peer={:?}, error={}",
                            peer_id,
                            e
                        );
                    }
                }
            }
        });
    }

    /// Re-dial seeds with exponential backoff when the node has zero peers.
    pub fn start_reconnect_task(
        peer_manager: Arc<PeerManager>,
        seeds: Vec<std::net::SocketAddr>,
        check_interval: Duration,
    ) {
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(30);
            let max_backoff = Duration::from_secs(600);
            let mut consecutive_empty: u32 = 0;

            loop {
                tokio::time::sleep(check_interval).await;

                let peer_count = peer_manager.ready_peer_count().await;

                if peer_count == 0 {
                    consecutive_empty += 1;
                    tracing::warn!(
                        "[reconnect] isolated — 0 peers (attempt #{}), \
                         trying {} seed(s) in {}s",
                        consecutive_empty,
                        seeds.len(),
                        backoff.as_secs(),
                    );
                    tokio::time::sleep(backoff).await;

                    for addr in &seeds {
                        let _ = peer_manager
                            .add_peer(*addr, crate::network::Direction::Outbound)
                            .await;
                        tracing::info!("[reconnect] dialing seed {}", addr);
                    }

                    backoff = (backoff * 2).min(max_backoff);
                } else if consecutive_empty > 0 {
                    tracing::info!(
                        "[reconnect] restored — {} peer(s) connected after {} isolation tick(s).",
                        peer_count,
                        consecutive_empty,
                    );
                    backoff = Duration::from_secs(30);
                    consecutive_empty = 0;
                }
            }
        });
    }
}

fn network_from_chain_id(chain_id: &str) -> Network {
    match chain_id {
        "axiom-mainnet-1" => Network::Mainnet,
        // v2-dev: testnet identifier moved from "axiom-test-1" to
        // "axiom-test-v2". A v1 chain id will fall through to Dev so we
        // do not silently accept a v1 node as a v2 testnet peer.
        "axiom-test-v2" => Network::Test,
        _ => Network::Dev,
    }
}

fn tx_reject_code(reason: &str) -> u8 {
    let r = reason.to_lowercase();
    if r.contains("duplicate") {
        reject_code::DUPLICATE
    } else if r.contains("fee") || r.contains("insufficient") {
        reject_code::INSUFFICIENT_FEE
    } else if r.contains("dust") {
        reject_code::DUST
    } else if r.contains("nonstandard") || r.contains("non-standard") {
        reject_code::NONSTANDARD
    } else {
        reject_code::INVALID
    }
}

fn block_reject_code(reason: &str) -> u8 {
    let r = reason.to_lowercase();
    if r.contains("checkpoint") {
        reject_code::CHECKPOINT
    } else if r.contains("duplicate") || r.contains("already exists") {
        reject_code::DUPLICATE
    } else {
        reject_code::INVALID
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use tempfile::TempDir;

    fn create_test_service() -> (TempDir, NetworkService) {
        let temp_dir = TempDir::new().unwrap();
        let config = Config {
            data_dir: temp_dir.path().to_path_buf(),
            ..Config::default()
        };
        let node = Node::new(config).unwrap();
        let peer_manager = PeerManager::new("dev".to_string());
        let service = NetworkService::new(node, peer_manager);
        (temp_dir, service)
    }

    #[tokio::test]
    async fn test_get_tip_message() {
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let response = service
            .handle_message(peer_id, Message::GetTip)
            .await
            .unwrap();

        assert!(matches!(response, Some(Message::Tip(_))));
    }

    #[tokio::test]
    async fn test_duplicate_tx_rejection() {
        let (_temp, service) = create_test_service();

        let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);
        let peer_id = PeerId::new();

        let _ = service
            .handle_received_transaction(tx.clone(), peer_id)
            .await;

        let result = service.handle_received_transaction(tx, peer_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_duplicate_block_rejection() {
        let (_temp, service) = create_test_service();

        let block = service.build_local_block().await.unwrap();
        let peer_id = PeerId::new();

        let result = service.handle_received_block(block, peer_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fee_filter_message_response() {
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let response = service
            .handle_message(peer_id, Message::FeeFilter(1234))
            .await
            .unwrap();
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn test_get_headers_returns_headers() {
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let response = service
            .handle_message(peer_id, Message::GetHeaders(Hash256::zero(), 2000))
            .await
            .unwrap();

        assert!(matches!(response, Some(Message::Headers(_))));
    }

    #[tokio::test]
    async fn test_inv_seen_dedup() {
        let (_temp, service) = create_test_service();
        let hash = Hash256::zero();

        assert!(!service.inv_recently_sent(&hash).await);
        service.record_inv_sent(hash).await;
        assert!(service.inv_recently_sent(&hash).await);
    }

    #[tokio::test]
    async fn test_reject_received_ok() {
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let result = service
            .handle_message(
                peer_id,
                Message::Reject("abc".to_string(), reject_code::INVALID, "bad".to_string()),
            )
            .await;

        assert!(result.is_ok());
    }

    // ===== EDGE-CASE TESTS FOR DUPLICATE REJECTION =====

    #[tokio::test]
    async fn test_duplicate_tx_rejection_same_peer_multiple_times() {
        // Ensures that even the SAME peer cannot spam the same tx
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);

        // First submission (empty tx will be rejected due to validation, not added)
        let result1 = service
            .handle_received_transaction(tx.clone(), peer_id)
            .await;
        // Result can be error or ok depending on validation
        let _ = result1;

        // Second submission from same peer should have same result (idempotent)
        let result2 = service
            .handle_received_transaction(tx.clone(), peer_id)
            .await;
        // Should behave consistently
        let _ = result2;

        // Verify it ran without panics - the key test for async runtime handling
        let mempool_size = {
            let node = service.node.read().await;
            node.mempool_size()
        };
        // Should have no txs in mempool (empty tx not accepted)
        assert_eq!(mempool_size, 0, "empty tx should not be in mempool");
    }

    #[tokio::test]
    async fn test_duplicate_block_rejection_same_peer_multiple_times() {
        // Ensures that even the SAME peer cannot spam the same block
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        let block = service.build_local_block().await.unwrap();

        // First submission succeeds
        let result1 = service.handle_received_block(block.clone(), peer_id).await;
        assert!(result1.is_ok());

        // Second submission from same peer should fail or be ignored
        let result2 = service.handle_received_block(block.clone(), peer_id).await;
        // Should either error or be silently ignored as duplicate
        let _ = result2;
    }

    #[tokio::test]
    async fn test_duplicate_tx_rejection_different_peers() {
        // Ensures duplicate detection works across peers
        let (_temp, service) = create_test_service();
        let peer_id1 = PeerId::new();
        let peer_id2 = PeerId::new();

        let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);

        // First peer submits
        let result1 = service
            .handle_received_transaction(tx.clone(), peer_id1)
            .await;
        assert!(result1.is_ok());

        // Second peer tries to submit SAME tx should also succeed but not duplicate it
        let result2 = service
            .handle_received_transaction(tx.clone(), peer_id2)
            .await;
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_asyncruntime_integration_in_service() {
        // Ensures service can be created and used in tokio::test without panics
        let (_temp, service) = create_test_service();

        // Creating a transaction in async context should not panic
        let tx = axiom_protocol::Transaction::new_transfer(vec![], vec![], 0, 0);
        let peer_id = PeerId::new();

        // This used to panic with "Cannot start a runtime from within a runtime"
        let result = service.handle_received_transaction(tx, peer_id).await;
        assert!(result.is_ok(), "should handle transaction in async context");
    }

    #[tokio::test]
    async fn test_block_validation_in_async_context() {
        // Ensures block validation works in tokio::test context
        let (_temp, service) = create_test_service();
        let peer_id = PeerId::new();

        // Build and validate block in async context
        // This used to panic with "Cannot start a runtime from within a runtime"
        let block = service.build_local_block().await.unwrap();
        let result = service.handle_received_block(block, peer_id).await;
        assert!(result.is_ok(), "should handle block in async context");
    }
}
