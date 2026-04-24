// Copyright (c) 2026 Kantoshi Miyamura

//! Patch-recommendation telemetry for AxiomMind v2.
//!
//! INVARIANT: nothing in this module mutates source files, on-chain state,
//! or peer state. `Patch` and `CodeChange` are descriptive metadata; the
//! `apply_patch` and `vote` functions are no-ops that exist solely to keep
//! the dashboard state machine consistent. Wiring either to real I/O
//! requires explicit operator review (see AI-CONSENSUS-AUDIT.md, R2).

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Vulnerability types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityType {
    NonceSaturation,
    TimestampManipulation,
    PrivateKeyExposure,
    MerkleTreeCollision,
    DoubleSpendsDetection,
    ReorgDepthIssue,
    FeeRatePrecision,
    RateLimiterBypass,
    MempoolAncestorLimit,
    RangeProofMemory,
}

/// Patch status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchStatus {
    Generated,
    Validated,
    Approved,
    Applied,
    Failed,
    Rolled,
}

/// Vulnerability record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub vuln_type: VulnerabilityType,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub affected_component: String,
    pub discovered_at: u64,
    pub cve_id: Option<String>,
}

/// Patch record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub id: String,
    pub vulnerability_id: String,
    pub status: PatchStatus,
    pub code_changes: Vec<CodeChange>,
    pub created_at: u64,
    pub applied_at: Option<u64>,
    pub consensus_votes: HashMap<String, bool>,
    pub approval_threshold: f64,
}

/// Individual code change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChange {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
    pub old_code: String,
    pub new_code: String,
    pub reason: String,
}

/// Patch application result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    pub patch_id: String,
    pub success: bool,
    pub message: String,
    pub applied_at: u64,
    pub rollback_available: bool,
}

/// Vulnerability database
pub struct VulnerabilityDatabase {
    vulnerabilities: Arc<RwLock<HashMap<String, Vulnerability>>>,
    patches: Arc<RwLock<HashMap<String, Patch>>>,
    patch_history: Arc<RwLock<Vec<PatchResult>>>,
}

impl Default for VulnerabilityDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnerabilityDatabase {
    pub fn new() -> Self {
        VulnerabilityDatabase {
            vulnerabilities: Arc::new(RwLock::new(HashMap::new())),
            patches: Arc::new(RwLock::new(HashMap::new())),
            patch_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a vulnerability
    pub async fn register_vulnerability(&self, vuln: Vulnerability) {
        let mut vulns = self.vulnerabilities.write().await;
        vulns.insert(vuln.id.clone(), vuln);
    }

    /// Get vulnerability by ID
    pub async fn get_vulnerability(&self, id: &str) -> Option<Vulnerability> {
        let vulns = self.vulnerabilities.read().await;
        vulns.get(id).cloned()
    }

    /// Get all vulnerabilities
    pub async fn get_all_vulnerabilities(&self) -> Vec<Vulnerability> {
        let vulns = self.vulnerabilities.read().await;
        vulns.values().cloned().collect()
    }

    /// Register a patch
    pub async fn register_patch(&self, patch: Patch) {
        let mut patches = self.patches.write().await;
        patches.insert(patch.id.clone(), patch);
    }

    /// Get patch by ID
    pub async fn get_patch(&self, id: &str) -> Option<Patch> {
        let patches = self.patches.read().await;
        patches.get(id).cloned()
    }

    /// Get patches for vulnerability
    pub async fn get_patches_for_vulnerability(&self, vuln_id: &str) -> Vec<Patch> {
        let patches = self.patches.read().await;
        patches
            .values()
            .filter(|p| p.vulnerability_id == vuln_id)
            .cloned()
            .collect()
    }

    /// Record patch application
    pub async fn record_patch_result(&self, result: PatchResult) {
        let mut history = self.patch_history.write().await;
        history.push(result);
    }

    /// Get patch history
    pub async fn get_patch_history(&self, limit: usize) -> Vec<PatchResult> {
        let history = self.patch_history.read().await;
        history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Patch generator
pub struct PatchGenerator;

impl PatchGenerator {
    /// Generate a patch for a vulnerability
    pub fn generate(vulnerability: &Vulnerability) -> Result<Patch, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let patch_id = format!("PATCH-{}-{}", vulnerability.id, now);

        let code_changes = match vulnerability.vuln_type {
            VulnerabilityType::NonceSaturation => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/validation.rs".to_string(),
                    line_start: 213,
                    line_end: 220,
                    old_code: "nonce = nonce.saturating_add(1);".to_string(),
                    new_code: "nonce = nonce.checked_add(1).ok_or(\"Nonce overflow\")?;".to_string(),
                    reason: "Use checked_add instead of saturating_add to prevent nonce saturation attacks".to_string(),
                }]
            }
            VulnerabilityType::TimestampManipulation => {
                vec![CodeChange {
                    file: "crates/axiom-consensus/src/pow.rs".to_string(),
                    line_start: 130,
                    line_end: 145,
                    old_code: "let difficulty = calculate_lwma3(timestamps);".to_string(),
                    new_code: "validate_timestamps(&timestamps)?; let difficulty = calculate_lwma3(timestamps);".to_string(),
                    reason: "Validate timestamps before using in LWMA-3 calculation".to_string(),
                }]
            }
            VulnerabilityType::PrivateKeyExposure => {
                vec![CodeChange {
                    file: "crates/axiom-rpc/src/handlers.rs".to_string(),
                    line_start: 751,
                    line_end: 900,
                    old_code: "accept_private_key_from_rpc()".to_string(),
                    new_code: "// Private key acceptance removed for security".to_string(),
                    reason: "Remove private key acceptance from RPC endpoints".to_string(),
                }]
            }
            VulnerabilityType::MerkleTreeCollision => {
                vec![CodeChange {
                    file: "crates/axiom-consensus/src/validation.rs".to_string(),
                    line_start: 300,
                    line_end: 320,
                    old_code: "validate_merkle_root(block)".to_string(),
                    new_code: "validate_merkle_root_with_collision_check(block)?".to_string(),
                    reason: "Add collision detection to merkle tree validation".to_string(),
                }]
            }
            VulnerabilityType::DoubleSpendsDetection => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/validation.rs".to_string(),
                    line_start: 500,
                    line_end: 550,
                    old_code: "check_double_spend(tx)".to_string(),
                    new_code: "check_double_spend_with_mempool_check(tx)?".to_string(),
                    reason: "Enhance double-spend detection with mempool analysis".to_string(),
                }]
            }
            VulnerabilityType::ReorgDepthIssue => {
                vec![CodeChange {
                    file: "crates/axiom-consensus/src/consensus.rs".to_string(),
                    line_start: 200,
                    line_end: 250,
                    old_code: "max_reorg_depth = 100".to_string(),
                    new_code: "max_reorg_depth = 10".to_string(),
                    reason: "Reduce maximum reorg depth to prevent deep reorganizations".to_string(),
                }]
            }
            VulnerabilityType::FeeRatePrecision => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/validation.rs".to_string(),
                    line_start: 600,
                    line_end: 620,
                    old_code: "fee_rate as f32".to_string(),
                    new_code: "fee_rate as f64".to_string(),
                    reason: "Use f64 for fee rate calculations to prevent precision loss".to_string(),
                }]
            }
            VulnerabilityType::RateLimiterBypass => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/network/message.rs".to_string(),
                    line_start: 400,
                    line_end: 450,
                    old_code: "check_rate_limit(peer)".to_string(),
                    new_code: "check_rate_limit_with_ip_validation(peer)?".to_string(),
                    reason: "Add IP validation to rate limiter to prevent bypass".to_string(),
                }]
            }
            VulnerabilityType::MempoolAncestorLimit => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/mempool.rs".to_string(),
                    line_start: 300,
                    line_end: 350,
                    old_code: "max_ancestors = 1000".to_string(),
                    new_code: "max_ancestors = 100".to_string(),
                    reason: "Reduce mempool ancestor limit to prevent memory exhaustion".to_string(),
                }]
            }
            VulnerabilityType::RangeProofMemory => {
                vec![CodeChange {
                    file: "crates/axiom-node/src/validation.rs".to_string(),
                    line_start: 700,
                    line_end: 750,
                    old_code: "deserialize_range_proof(data)".to_string(),
                    new_code: "check_range_proof_size(data)?; deserialize_range_proof(data)".to_string(),
                    reason: "Check range proof size before deserialization to prevent DoS".to_string(),
                }]
            }
        };

        Ok(Patch {
            id: patch_id,
            vulnerability_id: vulnerability.id.clone(),
            status: PatchStatus::Generated,
            code_changes,
            created_at: now,
            applied_at: None,
            consensus_votes: HashMap::new(),
            approval_threshold: 0.66, // 2/3 majority
        })
    }
}

/// Consensus engine for patch voting
pub struct ConsensusEngine {
    #[allow(dead_code)]
    node_id: String,
    #[allow(dead_code)]
    peer_count: usize,
}

impl ConsensusEngine {
    pub fn new(node_id: String, peer_count: usize) -> Self {
        ConsensusEngine { node_id, peer_count }
    }

    /// Stub. Patch voting never escapes this process — see module doc.
    pub async fn vote(&self, _patch: &Patch, _approve: bool) -> Result<(), String> {
        Ok(())
    }

    /// Check if patch has consensus
    pub fn has_consensus(&self, patch: &Patch) -> bool {
        if patch.consensus_votes.is_empty() {
            return false;
        }

        let approvals = patch.consensus_votes.values().filter(|&&v| v).count();
        let total = patch.consensus_votes.len();
        let approval_rate = approvals as f64 / total as f64;

        approval_rate >= patch.approval_threshold
    }

    /// Get consensus status
    pub fn get_consensus_status(&self, patch: &Patch) -> ConsensusStatus {
        let total_votes = patch.consensus_votes.len();
        let approvals = patch.consensus_votes.values().filter(|&&v| v).count();
        let rejections = total_votes - approvals;

        ConsensusStatus {
            total_votes,
            approvals,
            rejections,
            approval_rate: if total_votes > 0 {
                approvals as f64 / total_votes as f64
            } else {
                0.0
            },
            has_consensus: self.has_consensus(patch),
        }
    }
}

/// Consensus status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStatus {
    pub total_votes: usize,
    pub approvals: usize,
    pub rejections: usize,
    pub approval_rate: f64,
    pub has_consensus: bool,
}

/// Self-healing system
pub struct SelfHealingSystem {
    pub vulnerability_db: Arc<VulnerabilityDatabase>,
    pub patch_generator: Arc<PatchGenerator>,
    pub consensus_engine: Arc<ConsensusEngine>,
    rollback_stack: Arc<RwLock<Vec<Patch>>>,
}

impl SelfHealingSystem {
    pub fn new(node_id: String, peer_count: usize) -> Self {
        SelfHealingSystem {
            vulnerability_db: Arc::new(VulnerabilityDatabase::new()),
            patch_generator: Arc::new(PatchGenerator),
            consensus_engine: Arc::new(ConsensusEngine::new(node_id, peer_count)),
            rollback_stack: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Generate, validate, and record a patch for telemetry. Does not modify
    /// any source file or chain state — see module-level invariant.
    pub async fn heal(&self, vulnerability: &Vulnerability) -> Result<PatchResult, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut _patch = PatchGenerator::generate(vulnerability)?;
        _patch.status = PatchStatus::Generated;

        self.validate_patch(&_patch)?;
        _patch.status = PatchStatus::Validated;

        _patch.status = PatchStatus::Approved;

        self.apply_patch(&_patch)?;
        _patch.status = PatchStatus::Applied;

        // Record in database
        self.vulnerability_db.register_patch(_patch.clone()).await;

        // Push to rollback stack
        let mut stack = self.rollback_stack.write().await;
        stack.push(_patch.clone());

        let result = PatchResult {
            patch_id: _patch.id,
            success: true,
            message: format!("Successfully patched vulnerability: {}", vulnerability.id),
            applied_at: now,
            rollback_available: true,
        };

        self.vulnerability_db.record_patch_result(result.clone()).await;

        Ok(result)
    }

    /// Validate a patch
    fn validate_patch(&self, _patch: &Patch) -> Result<(), String> {
        // Check that patch has code changes
        if _patch.code_changes.is_empty() {
            return Err("Patch has no code changes".to_string());
        }

        // Check that all code changes are valid
        for change in &_patch.code_changes {
            if change.file.is_empty() || change.new_code.is_empty() {
                return Err("Invalid code change in patch".to_string());
            }
        }

        Ok(())
    }

    /// No-op. Invariant: this function MUST NOT touch the filesystem or any
    /// chain state. The AI subsystem is advisory; consensus / source-of-truth
    /// changes are operator-driven. Wiring this to filesystem mutation
    /// requires an explicit security review.
    fn apply_patch(&self, _patch: &Patch) -> Result<(), String> {
        Ok(())
    }

    /// Rollback the last patch
    pub async fn rollback_last_patch(&self) -> Result<PatchResult, String> {
        let mut stack = self.rollback_stack.write().await;

        if let Some(patch) = stack.pop() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let result = PatchResult {
                patch_id: patch.id,
                success: true,
                message: "Successfully rolled back patch".to_string(),
                applied_at: now,
                rollback_available: !stack.is_empty(),
            };

            self.vulnerability_db.record_patch_result(result.clone()).await;

            Ok(result)
        } else {
            Err("No patches to rollback".to_string())
        }
    }

    /// Get healing status
    pub async fn get_status(&self) -> HealingStatus {
        let vulns = self.vulnerability_db.get_all_vulnerabilities().await;
        let patches = self.vulnerability_db.get_patch_history(1000).await;

        let critical_vulns = vulns
            .iter()
            .filter(|v| v.severity == VulnerabilitySeverity::Critical)
            .count();

        let successful_patches = patches.iter().filter(|p| p.success).count();
        let failed_patches = patches.iter().filter(|p| !p.success).count();

        HealingStatus {
            total_vulnerabilities: vulns.len(),
            critical_vulnerabilities: critical_vulns,
            total_patches_applied: successful_patches,
            failed_patches,
            rollback_available: !self.rollback_stack.read().await.is_empty(),
        }
    }
}

/// Healing status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingStatus {
    pub total_vulnerabilities: usize,
    pub critical_vulnerabilities: usize,
    pub total_patches_applied: usize,
    pub failed_patches: usize,
    pub rollback_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_generation() {
        let vuln = Vulnerability {
            id: "VULN-001".to_string(),
            vuln_type: VulnerabilityType::NonceSaturation,
            severity: VulnerabilitySeverity::Critical,
            description: "Nonce saturation vulnerability".to_string(),
            affected_component: "validation".to_string(),
            discovered_at: 0,
            cve_id: None,
        };

        let patch = PatchGenerator::generate(&vuln);
        assert!(patch.is_ok());
        let patch = patch.unwrap();
        assert!(!patch.code_changes.is_empty());
    }

    #[tokio::test]
    async fn test_vulnerability_database() {
        let db = VulnerabilityDatabase::new();

        let vuln = Vulnerability {
            id: "VULN-001".to_string(),
            vuln_type: VulnerabilityType::NonceSaturation,
            severity: VulnerabilitySeverity::Critical,
            description: "Test vulnerability".to_string(),
            affected_component: "test".to_string(),
            discovered_at: 0,
            cve_id: None,
        };

        db.register_vulnerability(vuln.clone()).await;
        let retrieved = db.get_vulnerability("VULN-001").await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_self_healing_system() {
        let system = SelfHealingSystem::new("node1".to_string(), 10);

        let vuln = Vulnerability {
            id: "VULN-001".to_string(),
            vuln_type: VulnerabilityType::NonceSaturation,
            severity: VulnerabilitySeverity::Critical,
            description: "Test vulnerability".to_string(),
            affected_component: "test".to_string(),
            discovered_at: 0,
            cve_id: None,
        };

        let result = system.heal(&vuln).await;
        assert!(result.is_ok());
        assert!(result.unwrap().success);
    }
}
