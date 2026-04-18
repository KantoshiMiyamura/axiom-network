// Copyright (c) 2026 Kantoshi Miyamura
// Peer reputation tracking. AxiomMind remembers who behaves well and who doesn't.
// reputation.rs — Per-peer reputation with temporal decay and adaptive thresholds

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── EWMA-based adaptive thresholds ───────────────────────────────────────────

/// Exponential weighted moving average — learns normal baselines
#[derive(Debug, Clone)]
pub struct Ewma {
    pub value: f64,
    pub alpha: f64,
    initialized: bool,
    recent: VecDeque<f64>,  // last 50 samples for variance
}

impl Ewma {
    pub fn new(alpha: f64, initial: f64) -> Self {
        Self { value: initial, alpha, initialized: false, recent: VecDeque::with_capacity(50) }
    }

    pub fn update(&mut self, x: f64) -> f64 {
        if !self.initialized {
            self.value = x;
            self.initialized = true;
        } else {
            self.value = self.alpha * x + (1.0 - self.alpha) * self.value;
        }
        if self.recent.len() >= 50 { self.recent.pop_front(); }
        self.recent.push_back(x);
        self.value
    }

    pub fn variance(&self) -> f64 {
        if self.recent.len() < 2 { return self.value * 0.01; }
        let mean = self.recent.iter().sum::<f64>() / self.recent.len() as f64;
        let var = self.recent.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / self.recent.len() as f64;
        var.max(0.001)
    }

    pub fn std_dev(&self) -> f64 { self.variance().sqrt() }

    /// Returns sigma deviation of x from learned baseline
    pub fn z_score(&self, x: f64) -> f64 {
        let sd = self.std_dev().max(self.value * 0.05).max(0.1);
        (x - self.value).abs() / sd
    }

    pub fn is_initialized(&self) -> bool { self.initialized }
}

impl Default for Ewma {
    fn default() -> Self { Self::new(0.1, 0.0) }
}

/// Violation record
#[derive(Debug, Clone)]
pub struct Violation {
    pub ts: u64,
    pub severity: f32,
    pub reason: String,
}

/// Per-peer reputation score with temporal decay (EWMA-based)
#[derive(Debug, Clone)]
pub struct PeerScore {
    pub addr: String,
    pub score: f64,           // 0.0 (banned) – 1.0 (trusted)
    pub violations: Vec<Violation>,
    pub rewards: u32,
    pub last_seen: u64,
    pub last_decay: u64,
}

impl PeerScore {
    pub fn new(addr: String) -> Self {
        let now = now_secs();
        Self { addr, score: 1.0, violations: Vec::new(), rewards: 0, last_seen: now, last_decay: now }
    }

    pub fn penalize(&mut self, severity: f32, reason: &str) {
        self.score = (self.score - severity as f64).max(0.0);
        self.violations.push(Violation { ts: now_secs(), severity, reason: reason.to_string() });
        // Keep last 50 violations
        if self.violations.len() > 50 { self.violations.remove(0); }
    }

    pub fn reward(&mut self, amount: f64) {
        self.score = (self.score + amount).min(1.0);
        self.rewards += 1;
    }

    /// Apply temporal decay — score recovers toward 1.0 at 5% per hour
    pub fn apply_decay(&mut self) {
        let now = now_secs();
        let elapsed_hours = (now - self.last_decay) as f64 / 3600.0;
        if elapsed_hours > 0.0 {
            let recovery = 0.05 * elapsed_hours * (1.0 - self.score);
            self.score = (self.score + recovery).min(1.0);
            self.last_decay = now;
        }
    }

    pub fn is_suspicious(&self) -> bool { self.score < 0.5 }
    pub fn is_banned(&self) -> bool { self.score < 0.2 }
    pub fn violation_count(&self) -> usize { self.violations.len() }
}

/// Registry of all peer reputations with EWMA adaptive thresholds
#[derive(Debug, Default)]
pub struct ReputationRegistry {
    peers: HashMap<String, PeerScore>,
    // Adaptive thresholds (EWMA-learned)
    pub block_time_ewma: Ewma,
    pub peer_count_ewma: Ewma,
    pub mempool_ewma: Ewma,
    pub fee_ewma: Ewma,
    pub orphan_ewma: Ewma,
}

impl ReputationRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            block_time_ewma: Ewma::new(0.05, 30.0),   // slow — block time baseline
            peer_count_ewma: Ewma::new(0.10, 8.0),    // peer count baseline
            mempool_ewma: Ewma::new(0.10, 0.0),        // mempool size baseline
            fee_ewma: Ewma::new(0.10, 10.0),           // fee rate baseline
            orphan_ewma: Ewma::new(0.05, 0.0),         // orphan rate baseline
        }
    }

    pub fn get_or_create(&mut self, addr: &str) -> &mut PeerScore {
        self.peers.entry(addr.to_string()).or_insert_with(|| PeerScore::new(addr.to_string()))
    }

    pub fn penalize(&mut self, addr: &str, severity: f32, reason: &str) {
        self.get_or_create(addr).penalize(severity, reason);
    }

    pub fn reward(&mut self, addr: &str, amount: f64) {
        self.get_or_create(addr).reward(amount);
    }

    pub fn is_banned(&self, addr: &str) -> bool {
        self.peers.get(addr).map(|p| p.is_banned()).unwrap_or(false)
    }

    pub fn score(&self, addr: &str) -> f64 {
        self.peers.get(addr).map(|p| p.score).unwrap_or(1.0)
    }

    /// Apply decay to all peers
    pub fn decay_all(&mut self) {
        for peer in self.peers.values_mut() {
            peer.apply_decay();
        }
    }

    /// Update block time EWMA, returns z-score deviation
    pub fn update_block_time(&mut self, secs: f64) -> f64 {
        self.block_time_ewma.update(secs);
        self.block_time_ewma.z_score(secs)
    }

    pub fn update_peer_count(&mut self, count: usize) -> f64 {
        self.peer_count_ewma.update(count as f64);
        self.peer_count_ewma.z_score(count as f64)
    }

    pub fn update_mempool(&mut self, size: usize) -> f64 {
        self.mempool_ewma.update(size as f64);
        self.mempool_ewma.z_score(size as f64)
    }

    pub fn update_fee(&mut self, sat_per_byte: f64) -> f64 {
        self.fee_ewma.update(sat_per_byte);
        self.fee_ewma.z_score(sat_per_byte)
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }

    pub fn suspicious_peers(&self) -> Vec<&PeerScore> {
        self.peers.values().filter(|p| p.is_suspicious()).collect()
    }

    pub fn banned_peers(&self) -> Vec<&PeerScore> {
        self.peers.values().filter(|p| p.is_banned()).collect()
    }
}

// ── Legacy peer reputation table (preserved for backwards compatibility) ──────

/// Simple per-peer reputation record (legacy, block-relay focused)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRepScore {
    pub peer_id: String,
    /// Reputation score: 0.0 (adversarial) — 1.0 (trusted). Starts at 0.5.
    pub score: f64,
    pub valid_blocks_relayed: u64,
    pub invalid_blocks_relayed: u64,
    pub connections: u64,
    pub last_seen_height: u64,
}

impl PeerRepScore {
    fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            score: 0.5,
            valid_blocks_relayed: 0,
            invalid_blocks_relayed: 0,
            connections: 1,
            last_seen_height: 0,
        }
    }

    pub fn record_valid_block(&mut self, height: u64) {
        self.valid_blocks_relayed += 1;
        self.last_seen_height = height;
        self.score = (self.score + 0.005).min(1.0);
    }

    pub fn record_invalid_block(&mut self) {
        self.invalid_blocks_relayed += 1;
        self.score = (self.score - 0.15).max(0.0);
    }

    pub fn is_trusted(&self) -> bool { self.score > 0.65 }
    pub fn is_suspect(&self) -> bool { self.score < 0.25 }
    pub fn is_banned(&self) -> bool { self.score < 0.05 }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerReputationTable {
    peers: HashMap<String, PeerRepScore>,
}

impl PeerReputationTable {
    pub fn new() -> Self { Self::default() }

    pub fn record_valid_block(&mut self, peer_id: &str, height: u64) {
        self.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerRepScore::new(peer_id.to_string()))
            .record_valid_block(height);
    }

    pub fn record_invalid_block(&mut self, peer_id: &str) {
        self.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerRepScore::new(peer_id.to_string()))
            .record_invalid_block();
    }

    pub fn get_score(&self, peer_id: &str) -> f64 {
        self.peers.get(peer_id).map(|p| p.score).unwrap_or(0.5)
    }

    pub fn trusted_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_trusted()).count()
    }

    pub fn banned_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_banned()).count()
    }

    pub fn total_count(&self) -> usize { self.peers.len() }

    pub fn top_peers(&self, n: usize) -> Vec<&PeerRepScore> {
        let mut peers: Vec<&PeerRepScore> = self.peers.values().collect();
        peers.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        peers.into_iter().take(n).collect()
    }
}
