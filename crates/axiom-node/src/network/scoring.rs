// Copyright (c) 2026 Kantoshi Miyamura

//! Peer scoring and reputation system.

use crate::network::PeerId;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PEER_BAN_THRESHOLD: i32 = -100;
pub const PEER_PENALTY_INVALID_MESSAGE: i32 = -10;
pub const PEER_PENALTY_PROTOCOL_VIOLATION: i32 = -20;
pub const PEER_PENALTY_SPAM: i32 = -5;
pub const PEER_PENALTY_SLOW_RESPONSE: i32 = -3;
pub const PEER_REWARD_VALID_BLOCK: i32 = 1;
pub const PEER_REWARD_VALID_TX: i32 = 1;
pub const PEER_REWARD_HELPFUL_PEER: i32 = 5;

pub const TEMPORARY_BAN_DURATION_SECS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct PeerScore {
    pub peer_id: PeerId,
    pub score: i32,
    pub invalid_messages: u32,
    pub protocol_violations: u32,
    pub spam_count: u32,
    pub valid_blocks: u32,
    pub valid_txs: u32,
    pub last_updated: u64,
    pub banned_until: Option<u64>,
}

impl PeerScore {
    pub fn new(peer_id: PeerId) -> Self {
        PeerScore {
            peer_id,
            score: 0,
            invalid_messages: 0,
            protocol_violations: 0,
            spam_count: 0,
            valid_blocks: 0,
            valid_txs: 0,
            last_updated: current_timestamp(),
            banned_until: None,
        }
    }

    pub fn is_banned(&self) -> bool {
        if let Some(ban_until) = self.banned_until {
            current_timestamp() < ban_until
        } else {
            false
        }
    }

    pub fn ban_temporarily(&mut self) {
        self.banned_until = Some(current_timestamp() + TEMPORARY_BAN_DURATION_SECS);
    }

    pub fn unban(&mut self) {
        self.banned_until = None;
    }
}

pub struct PeerScorer {
    scores: HashMap<PeerId, PeerScore>,
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerScorer {
    pub fn new() -> Self {
        PeerScorer {
            scores: HashMap::new(),
        }
    }

    pub fn get_or_create(&mut self, peer_id: PeerId) -> &mut PeerScore {
        self.scores
            .entry(peer_id)
            .or_insert_with(|| PeerScore::new(peer_id))
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerScore> {
        self.scores.get(peer_id)
    }

    pub fn record_invalid_message(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.invalid_messages += 1;
        score.score += PEER_PENALTY_INVALID_MESSAGE;
        score.last_updated = current_timestamp();

        if score.score <= PEER_BAN_THRESHOLD {
            score.ban_temporarily();
        }
    }

    pub fn record_protocol_violation(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.protocol_violations += 1;
        score.score += PEER_PENALTY_PROTOCOL_VIOLATION;
        score.last_updated = current_timestamp();

        if score.score <= PEER_BAN_THRESHOLD {
            score.ban_temporarily();
        }
    }

    pub fn record_spam(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.spam_count += 1;
        score.score += PEER_PENALTY_SPAM;
        score.last_updated = current_timestamp();

        if score.score <= PEER_BAN_THRESHOLD {
            score.ban_temporarily();
        }
    }

    pub fn record_slow_response(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.score += PEER_PENALTY_SLOW_RESPONSE;
        score.last_updated = current_timestamp();

        if score.score <= PEER_BAN_THRESHOLD {
            score.ban_temporarily();
        }
    }

    pub fn record_valid_block(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.valid_blocks += 1;
        score.score += PEER_REWARD_VALID_BLOCK;
        score.last_updated = current_timestamp();
    }

    pub fn record_valid_tx(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.valid_txs += 1;
        score.score += PEER_REWARD_VALID_TX;
        score.last_updated = current_timestamp();
    }

    pub fn record_helpful_peer(&mut self, peer_id: PeerId) {
        let score = self.get_or_create(peer_id);
        score.score += PEER_REWARD_HELPFUL_PEER;
        score.last_updated = current_timestamp();
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.get(peer_id).map(|s| s.is_banned()).unwrap_or(false)
    }

    pub fn get_banned_peers(&self) -> Vec<PeerId> {
        self.scores
            .values()
            .filter(|s| s.is_banned())
            .map(|s| s.peer_id)
            .collect()
    }

    pub fn cleanup_expired_bans(&mut self) {
        for score in self.scores.values_mut() {
            if let Some(ban_until) = score.banned_until {
                if current_timestamp() >= ban_until {
                    score.unban();
                }
            }
        }
    }

    pub fn remove(&mut self, peer_id: &PeerId) {
        self.scores.remove(peer_id);
    }

    pub fn get_all(&self) -> Vec<PeerScore> {
        self.scores.values().cloned().collect()
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_score_creation() {
        let peer_id = PeerId::new();
        let score = PeerScore::new(peer_id);
        assert_eq!(score.score, 0);
        assert!(!score.is_banned());
    }

    #[test]
    fn test_peer_ban() {
        let peer_id = PeerId::new();
        let mut score = PeerScore::new(peer_id);
        score.ban_temporarily();
        assert!(score.is_banned());
    }

    #[test]
    fn test_scorer_invalid_message() {
        let mut scorer = PeerScorer::new();
        let peer_id = PeerId::new();

        scorer.record_invalid_message(peer_id);
        let score = scorer.get(&peer_id).unwrap();
        assert_eq!(score.invalid_messages, 1);
        assert_eq!(score.score, PEER_PENALTY_INVALID_MESSAGE);
    }

    #[test]
    fn test_scorer_ban_threshold() {
        let mut scorer = PeerScorer::new();
        let peer_id = PeerId::new();

        for _ in 0..11 {
            scorer.record_invalid_message(peer_id);
        }

        assert!(scorer.is_banned(&peer_id));
    }

    #[test]
    fn test_scorer_valid_block() {
        let mut scorer = PeerScorer::new();
        let peer_id = PeerId::new();

        scorer.record_valid_block(peer_id);
        let score = scorer.get(&peer_id).unwrap();
        assert_eq!(score.valid_blocks, 1);
        assert_eq!(score.score, PEER_REWARD_VALID_BLOCK);
    }

    #[test]
    fn test_scorer_cleanup_bans() {
        let mut scorer = PeerScorer::new();
        let peer_id = PeerId::new();

        scorer.record_invalid_message(peer_id);
        for _ in 0..11 {
            scorer.record_invalid_message(peer_id);
        }

        assert!(scorer.is_banned(&peer_id));

        if let Some(score) = scorer.scores.get_mut(&peer_id) {
            score.unban();
        }

        assert!(!scorer.is_banned(&peer_id));
    }
}
