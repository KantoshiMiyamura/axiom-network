// Copyright (c) 2026 Kantoshi Miyamura

//! Ephemeral P2P community chat.
//!
//! ## Architecture
//! - Messages are **never** written to disk — pure in-RAM gossip ring buffer.
//! - Each message has a 1-hour TTL; the oldest entries are evicted at 500 messages.
//! - **AxiomMind** content moderation: a fast keyword + pattern classifier rates
//!   every message before relay.  Messages scoring above threshold are dropped
//!   and the sender is marked for ban voting.
//! - **Consensus ban**: when 3 distinct nodes cast a `ChatBan` vote for the same
//!   address within 60 seconds, a 24-hour chat ban is applied locally and relayed.
//! - **Username cache**: `UsernameAnnounce` payloads are kept in a `HashMap`;
//!   lookups are O(1) for the RPC layer.

use crate::network::{ChatBanPayload, ChatMessagePayload, UsernameAnnouncePayload};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing;

// ── tunables ──────────────────────────────────────────────────────────────────

/// Maximum number of messages kept in RAM (oldest are dropped when exceeded).
const MAX_MESSAGES: usize = 500;
/// Messages older than this are silently dropped.
const MSG_TTL: Duration = Duration::from_secs(3600);
/// Ban votes within this window from 3+ distinct nodes trigger a ban.
const BAN_VOTE_WINDOW: Duration = Duration::from_secs(60);
/// Duration of a consensus-triggered chat ban.
const BAN_DURATION: Duration = Duration::from_secs(86_400); // 24 h
/// Channel capacity for live-push to RPC WebSocket subscribers.
const LIVE_CHANNEL_CAPACITY: usize = 256;

// ── AxiomMind v1 denylist ────────────────────────────────────────────────────
//
// Deterministic substring + run-length classifier. Lower-cased ASCII only.
// Runs in the gossip relay path; verdict gates whether a message is rebroadcast
// and whether the sender is recorded as a ban-vote candidate. Affects the
// in-RAM message ring only — never the chain.

const BANNED_WORDS: &[&str] = &[
    // Hate speech — slurs omitted here; actual list lives in axiom-guard
    "nigger",
    "faggot",
    "kike",
    "spic",
    "chink",
    // Harassment
    "kill yourself",
    "kys",
    "die bitch",
    // CSAM indicators — zero tolerance
    "cp link",
    "childporn",
    // Spam
    "buy crypto now",
    "100x guaranteed",
    "send me your private key",
];

/// Result of AxiomMind content classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModerationVerdict {
    /// Message is clean — relay it.
    Allow,
    /// Message contains violating content — drop and record a ban vote.
    Block { reason: String },
}

/// Classify a message body using the AxiomMind v1 ruleset.
pub fn axiom_mind_classify(text: &str) -> ModerationVerdict {
    let lower = text.to_lowercase();
    for word in BANNED_WORDS {
        if lower.contains(word) {
            return ModerationVerdict::Block {
                reason: "policy violation: contains banned phrase".to_string(),
            };
        }
    }
    // Spam heuristic: more than 4 consecutive identical characters
    let mut run = 1usize;
    let chars: Vec<char> = lower.chars().collect();
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run += 1;
            if run > 4 {
                return ModerationVerdict::Block {
                    reason: "spam: excessive repeated characters".into(),
                };
            }
        } else {
            run = 1;
        }
    }
    ModerationVerdict::Allow
}

// ── core types ────────────────────────────────────────────────────────────────

/// A community message as stored in the ring buffer.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub payload: ChatMessagePayload,
    pub received_at: Instant,
}

/// A single ban vote.
#[derive(Debug, Clone)]
struct BanVote {
    voter_address: String,
    cast_at: Instant,
}

/// A currently-active ban entry.
#[derive(Debug, Clone)]
struct ActiveBan {
    expires_at: Instant,
}

// ── CommunityService ──────────────────────────────────────────────────────────

/// Thread-safe community chat state.  Wrap in `Arc` and share freely.
pub struct CommunityService {
    /// Ring buffer of recent messages (newest at back).
    messages: RwLock<VecDeque<StoredMessage>>,
    /// Ban votes keyed by target address.
    ban_votes: RwLock<HashMap<String, Vec<BanVote>>>,
    /// Active bans keyed by address.
    active_bans: RwLock<HashMap<String, ActiveBan>>,
    /// Username → address and reverse caches.
    username_by_address: RwLock<HashMap<String, String>>,
    address_by_username: RwLock<HashMap<String, String>>,
    /// Nonce dedup set (prevents replay within TTL window).
    seen_nonces: RwLock<HashMap<u64, Instant>>,
    /// Live-push channel for RPC WebSocket subscribers.
    pub live_tx: broadcast::Sender<ChatMessagePayload>,
}

impl CommunityService {
    pub fn new() -> Arc<Self> {
        let (live_tx, _) = broadcast::channel(LIVE_CHANNEL_CAPACITY);
        Arc::new(CommunityService {
            messages: RwLock::new(VecDeque::new()),
            ban_votes: RwLock::new(HashMap::new()),
            active_bans: RwLock::new(HashMap::new()),
            username_by_address: RwLock::new(HashMap::new()),
            address_by_username: RwLock::new(HashMap::new()),
            seen_nonces: RwLock::new(HashMap::new()),
            live_tx,
        })
    }

    /// Subscribe to live incoming messages (for WebSocket push).
    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessagePayload> {
        self.live_tx.subscribe()
    }

    // ── public handlers (called from NetworkService) ──────────────────────

    /// Handle an incoming `ChatMessage` from a peer.
    /// Returns `true` if the message should be relayed to other peers.
    pub async fn handle_chat_message(&self, payload: ChatMessagePayload) -> bool {
        // 1. Timestamp sanity: reject messages more than 5 minutes in the future
        //    or older than MSG_TTL (they won't fit in our window anyway).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if payload.timestamp > now_unix + 300 {
            tracing::debug!(
                "CHAT_DROP: future timestamp from {}",
                payload.sender_address
            );
            return false;
        }
        if now_unix.saturating_sub(payload.timestamp) > MSG_TTL.as_secs() {
            tracing::debug!("CHAT_DROP: expired message from {}", payload.sender_address);
            return false;
        }

        // 2. Nonce dedup.
        {
            let mut nonces = self.seen_nonces.write().await;
            let now = Instant::now();
            nonces.retain(|_, ts| now.duration_since(*ts) < MSG_TTL);
            if nonces.contains_key(&payload.nonce) {
                return false;
            }
            nonces.insert(payload.nonce, now);
        }

        // 3. Check active ban.
        if self.is_banned(&payload.sender_address).await {
            tracing::info!(
                "CHAT_DROP: banned sender {}",
                &payload.sender_address[..payload.sender_address.len().min(16)]
            );
            return false;
        }

        // 4. Text length guard.
        if payload.text.len() > crate::network::MAX_CHAT_TEXT_BYTES {
            tracing::debug!(
                "CHAT_DROP: message too long from {}",
                payload.sender_address
            );
            return false;
        }

        // 5. AxiomMind content moderation.
        match axiom_mind_classify(&payload.text) {
            ModerationVerdict::Allow => {}
            ModerationVerdict::Block { reason } => {
                tracing::info!(
                    "AXIOM_MIND_BLOCK: sender={} reason={}",
                    &payload.sender_address[..payload.sender_address.len().min(16)],
                    reason
                );
                // Self-issue a ban vote on behalf of this node.
                let ban = ChatBanPayload {
                    target_address: payload.sender_address.clone(),
                    reason: reason.clone(),
                    timestamp: now_unix,
                    voter_address: String::from("axiom-mind-local"),
                    signature: vec![],
                };
                self.handle_chat_ban(ban).await;
                return false;
            }
        }

        // 6. Store in ring buffer.
        {
            let mut msgs = self.messages.write().await;
            let now = Instant::now();
            // Evict expired.
            while msgs
                .front()
                .is_some_and(|m| now.duration_since(m.received_at) > MSG_TTL)
            {
                msgs.pop_front();
            }
            // Cap at MAX_MESSAGES.
            while msgs.len() >= MAX_MESSAGES {
                msgs.pop_front();
            }
            msgs.push_back(StoredMessage {
                payload: payload.clone(),
                received_at: now,
            });
        }

        // 7. Push to live WebSocket subscribers (ignore send errors — no subscribers is fine).
        let _ = self.live_tx.send(payload);

        true // relay
    }

    /// Handle an incoming `ChatBan` vote from a peer.
    /// Returns `true` if the vote should be relayed.
    pub async fn handle_chat_ban(&self, payload: ChatBanPayload) -> bool {
        let now = Instant::now();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Timestamp sanity
        if payload.timestamp > now_unix + 60 {
            return false;
        }

        let mut votes = self.ban_votes.write().await;
        let entry = votes.entry(payload.target_address.clone()).or_default();

        // Evict stale votes outside the window.
        entry.retain(|v| now.duration_since(v.cast_at) < BAN_VOTE_WINDOW);

        // Deduplicate per voter.
        if entry
            .iter()
            .any(|v| v.voter_address == payload.voter_address)
        {
            return false; // already voted
        }

        entry.push(BanVote {
            voter_address: payload.voter_address.clone(),
            cast_at: now,
        });

        let vote_count = entry.len();
        let target = payload.target_address.clone();
        let reason = payload.reason.clone();
        drop(votes);

        if vote_count >= 3 {
            // Consensus reached — apply ban.
            self.apply_ban(&target, &reason, now).await;
            tracing::info!(
                "CHAT_BAN_CONSENSUS: target={} reason={}",
                &target[..target.len().min(16)],
                reason
            );
        }

        true // relay the vote
    }

    /// Handle an incoming `UsernameAnnounce` from a peer.
    /// Returns `true` if it should be relayed (first time we've seen it).
    pub async fn handle_username_announce(&self, payload: UsernameAnnouncePayload) -> bool {
        // Basic validation: username must be ≤ MAX_USERNAME_BYTES and printable ASCII.
        if payload.username.is_empty()
            || payload.username.len() > crate::network::MAX_USERNAME_BYTES
            || !payload
                .username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return false;
        }

        let mut by_addr = self.username_by_address.write().await;
        let mut by_name = self.address_by_username.write().await;

        // If username is already claimed by a different address, ignore.
        if let Some(existing_addr) = by_name.get(&payload.username) {
            if *existing_addr != payload.address {
                return false;
            }
        }

        let already_known = by_addr
            .get(&payload.address)
            .is_some_and(|u| *u == payload.username);

        by_addr.insert(payload.address.clone(), payload.username.clone());
        by_name.insert(payload.username, payload.address);

        !already_known // relay only if new
    }

    // ── query API (used by RPC) ───────────────────────────────────────────

    /// Return up to `limit` most recent messages (newest first).
    pub async fn recent_messages(&self, limit: usize) -> Vec<StoredMessage> {
        let msgs = self.messages.read().await;
        msgs.iter().rev().take(limit).cloned().collect()
    }

    /// Look up the registered username for an AXM address.
    pub async fn username_of(&self, address: &str) -> Option<String> {
        self.username_by_address.read().await.get(address).cloned()
    }

    /// Check whether an address is currently banned.
    pub async fn is_banned(&self, address: &str) -> bool {
        let mut bans = self.active_bans.write().await;
        if let Some(ban) = bans.get(address) {
            if Instant::now() < ban.expires_at {
                return true;
            }
            bans.remove(address);
        }
        false
    }

    // ── internal ─────────────────────────────────────────────────────────

    async fn apply_ban(&self, address: &str, _reason: &str, now: Instant) {
        let mut bans = self.active_bans.write().await;
        bans.insert(
            address.to_owned(),
            ActiveBan {
                expires_at: now + BAN_DURATION,
            },
        );
        // Purge any messages from the now-banned address.
        let mut msgs = self.messages.write().await;
        msgs.retain(|m| m.payload.sender_address != address);
    }
}

impl Default for CommunityService {
    fn default() -> Self {
        let (live_tx, _) = broadcast::channel(LIVE_CHANNEL_CAPACITY);
        CommunityService {
            messages: RwLock::new(VecDeque::new()),
            ban_votes: RwLock::new(HashMap::new()),
            active_bans: RwLock::new(HashMap::new()),
            username_by_address: RwLock::new(HashMap::new()),
            address_by_username: RwLock::new(HashMap::new()),
            seen_nonces: RwLock::new(HashMap::new()),
            live_tx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(text: &str, sender: &str, nonce: u64) -> ChatMessagePayload {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ChatMessagePayload {
            username: "tester".into(),
            sender_address: sender.into(),
            text: text.into(),
            timestamp: ts,
            nonce,
            signature: vec![],
        }
    }

    #[tokio::test]
    async fn test_allow_clean_message() {
        let svc = CommunityService::new();
        let relayed = svc
            .handle_chat_message(make_msg("hello world", "axm_alice", 1))
            .await;
        assert!(relayed);
        let msgs = svc.recent_messages(10).await;
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload.text, "hello world");
    }

    #[tokio::test]
    async fn test_block_banned_word() {
        let svc = CommunityService::new();
        let relayed = svc
            .handle_chat_message(make_msg("kys loser", "axm_bad", 2))
            .await;
        assert!(!relayed);
        let msgs = svc.recent_messages(10).await;
        assert_eq!(msgs.len(), 0);
    }

    #[tokio::test]
    async fn test_nonce_dedup() {
        let svc = CommunityService::new();
        svc.handle_chat_message(make_msg("hi", "axm_alice", 99))
            .await;
        let relayed = svc
            .handle_chat_message(make_msg("hi again", "axm_alice", 99))
            .await;
        assert!(!relayed, "duplicate nonce should be dropped");
        let msgs = svc.recent_messages(10).await;
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn test_consensus_ban() {
        let svc = CommunityService::new();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for i in 0u8..3 {
            svc.handle_chat_ban(ChatBanPayload {
                target_address: "axm_bad_actor".into(),
                reason: "spam".into(),
                timestamp: now_unix,
                voter_address: format!("axm_node_{}", i),
                signature: vec![],
            })
            .await;
        }

        assert!(svc.is_banned("axm_bad_actor").await);
    }

    #[tokio::test]
    async fn test_username_claim() {
        let svc = CommunityService::new();
        svc.handle_username_announce(UsernameAnnouncePayload {
            username: "satoshi".into(),
            address: "axm_abc123".into(),
            registration_tx: [0u8; 32],
            timestamp: 0,
        })
        .await;
        assert_eq!(svc.username_of("axm_abc123").await, Some("satoshi".into()));
    }

    #[tokio::test]
    async fn test_moderation_classifier() {
        assert_eq!(
            axiom_mind_classify("hello everyone"),
            ModerationVerdict::Allow
        );
        assert!(matches!(
            axiom_mind_classify("nigger"),
            ModerationVerdict::Block { .. }
        ));
        assert!(matches!(
            axiom_mind_classify("aaaaaa"), // 6 identical chars
            ModerationVerdict::Block { .. }
        ));
    }
}
