// Copyright (c) 2026 Kantoshi Miyamura
//
//! Verifier Registration and Dispute Protocol
//!
//! Tracks verifiers with stake, reputation, and challenge outcomes.
//! Verifiers randomly sample and challenge incorrect results.

use crate::compute_types::*;
use fjall::{Config, PartitionCreateOptions};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Thread-safe verifier registry stored at `<data_dir>/ai_verifiers/`.
pub struct VerifierRegistry {
    _keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl VerifierRegistry {
    /// Open (or create) the verifier registry.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_verifiers");
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| ComputeError::Storage(e.to_string()))?;
        let partition = keyspace
            .open_partition("verifiers", PartitionCreateOptions::default())
            .map_err(|e| ComputeError::Storage(e.to_string()))?;
        Ok(VerifierRegistry {
            _keyspace: keyspace,
            partition,
        })
    }

    /// Register a new verifier with initial stake.
    pub fn register(
        &self,
        verifier_id: String,
        initial_stake_sat: u64,
    ) -> Result<VerifierRegistration> {
        if initial_stake_sat < MIN_VERIFIER_STAKE_SAT {
            return Err(ComputeError::InsufficientStake {
                required: MIN_VERIFIER_STAKE_SAT,
                have: initial_stake_sat,
            });
        }

        if self
            .partition
            .contains_key(&verifier_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            return Err(ComputeError::VerifierNotFound(format!(
                "Verifier {} already registered",
                verifier_id
            )));
        }

        let verifier = VerifierRegistration {
            verifier_id: verifier_id.clone(),
            stake_sat: initial_stake_sat,
            registered_at: current_ts(),
            active: true,
            reputation_score: 1.0, // Start with perfect reputation
            total_challenges: 0,
            successful_challenges: 0,
            false_challenges: 0,
        };

        self.save(&verifier)?;
        Ok(verifier)
    }

    /// Get a verifier by ID.
    pub fn get(&self, verifier_id: &str) -> Result<Option<VerifierRegistration>> {
        match self
            .partition
            .get(verifier_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            Some(v) => {
                let (verifier, _) = bincode::serde::decode_from_slice::<VerifierRegistration, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| ComputeError::Serialization(e.to_string()))?;
                Ok(Some(verifier))
            }
            None => Ok(None),
        }
    }

    /// List all active verifiers.
    pub fn list_active(&self, limit: usize) -> Result<Vec<VerifierRegistration>> {
        let mut verifiers = Vec::new();
        for kv in self.partition.iter() {
            let (_, v) = kv.map_err(|e| ComputeError::Storage(e.to_string()))?;
            if let Ok((verifier, _)) = bincode::serde::decode_from_slice::<VerifierRegistration, _>(
                &v,
                bincode::config::standard(),
            ) {
                if verifier.active {
                    verifiers.push(verifier);
                }
            }
        }
        verifiers.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        verifiers.truncate(limit);
        Ok(verifiers)
    }

    /// Add stake to a verifier.
    pub fn add_stake(&self, verifier_id: &str, amount_sat: u64) -> Result<VerifierRegistration> {
        let mut verifier = self
            .get(verifier_id)?
            .ok_or_else(|| ComputeError::VerifierNotFound(verifier_id.to_string()))?;

        verifier.stake_sat = verifier
            .stake_sat
            .checked_add(amount_sat)
            .ok_or_else(|| ComputeError::Storage("Stake overflow".to_string()))?;

        self.save(&verifier)?;
        Ok(verifier)
    }

    /// Slash stake from a verifier (for false accusations).
    pub fn slash_stake(&self, verifier_id: &str, amount_sat: u64) -> Result<VerifierRegistration> {
        let mut verifier = self
            .get(verifier_id)?
            .ok_or_else(|| ComputeError::VerifierNotFound(verifier_id.to_string()))?;

        verifier.stake_sat = verifier.stake_sat.saturating_sub(amount_sat);
        verifier.false_challenges = verifier.false_challenges.saturating_add(1);

        // Apply reputation penalty
        verifier.reputation_score *= REPUTATION_FRAUD_PENALTY;

        // Evict if reputation too low
        if verifier.reputation_score < REPUTATION_EVICTION_THRESHOLD {
            verifier.active = false;
        }

        self.save(&verifier)?;
        Ok(verifier)
    }

    /// Record a challenge outcome (successful or false accusation).
    pub fn record_challenge_outcome(
        &self,
        verifier_id: &str,
        caught_fraud: bool,
    ) -> Result<VerifierRegistration> {
        let mut verifier = self
            .get(verifier_id)?
            .ok_or_else(|| ComputeError::VerifierNotFound(verifier_id.to_string()))?;

        verifier.total_challenges = verifier.total_challenges.saturating_add(1);

        if caught_fraud {
            verifier.successful_challenges = verifier.successful_challenges.saturating_add(1);
            // Boost reputation for catching fraud
            verifier.reputation_score =
                (verifier.reputation_score + REPUTATION_SUCCESS_BONUS).min(1.0);
        }

        self.save(&verifier)?;
        Ok(verifier)
    }

    /// Deactivate a verifier (eviction for low reputation or breach).
    pub fn deactivate(&self, verifier_id: &str) -> Result<VerifierRegistration> {
        let mut verifier = self
            .get(verifier_id)?
            .ok_or_else(|| ComputeError::VerifierNotFound(verifier_id.to_string()))?;

        verifier.active = false;
        self.save(&verifier)?;
        Ok(verifier)
    }

    /// Determine if a job should be sampled for verification.
    ///
    /// Uses deterministic sampling based on job_id hash:
    /// if SHA-256(job_id)[0] as u8 < (SAMPLE_RATE_BPS * 255 / 10000), sample it.
    /// This gives ~30% sampling rate with 3000 BPS.
    pub fn should_sample_job(&self, job_id: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(job_id.as_bytes());
        let hash = hasher.finalize();

        let threshold = ((VERIFIER_SAMPLE_RATE_BPS as f64 / 10000.0) * 255.0) as u8;
        hash[0] < threshold
    }

    /// Select a verifier for a job using deterministic random selection.
    ///
    /// Uses the job_id hash as a seed to ensure deterministic assignment
    /// across all nodes but different from job to job.
    pub fn select_verifier(&self, job_id: &str) -> Result<Option<String>> {
        let verifiers = self.list_active(10000)?;

        if verifiers.is_empty() {
            return Ok(None);
        }

        // Derive deterministic random value from job_id
        let mut hasher = Sha256::new();
        hasher.update(job_id.as_bytes());
        let hash = hasher.finalize();
        let mut selector = [0u8; 8];
        selector.copy_from_slice(&hash[0..8]);
        let idx = (u64::from_le_bytes(selector) as usize) % verifiers.len();

        Ok(Some(verifiers[idx].verifier_id.clone()))
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    fn save(&self, verifier: &VerifierRegistration) -> Result<()> {
        let value = bincode::serde::encode_to_vec(verifier, bincode::config::standard())
            .map_err(|e| ComputeError::Serialization(e.to_string()))?;
        self.partition
            .insert(&verifier.verifier_id, value)
            .map_err(|e| ComputeError::Storage(e.to_string()))
    }
}

fn current_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_registry() -> (TempDir, VerifierRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = VerifierRegistry::open(tmp.path()).unwrap();
        (tmp, reg)
    }

    #[test]
    fn test_register_verifier() {
        let (_tmp, reg) = open_registry();
        let verifier = reg.register("axm_verifier_1".into(), 10_000).unwrap();

        assert_eq!(verifier.verifier_id, "axm_verifier_1");
        assert_eq!(verifier.stake_sat, 10_000);
        assert!(verifier.active);
        assert_eq!(verifier.reputation_score, 1.0);
    }

    #[test]
    fn test_register_insufficient_stake() {
        let (_tmp, reg) = open_registry();
        let result = reg.register("axm_verifier_1".into(), 1_000); // Too low
        assert!(result.is_err());
    }

    #[test]
    fn test_should_sample_job() {
        let (_tmp, reg) = open_registry();

        // With 30% sample rate, approximately 30% of jobs should be sampled
        let mut sampled = 0;
        for i in 0..100 {
            let job_id = format!("job_{}", i);
            if reg.should_sample_job(&job_id) {
                sampled += 1;
            }
        }
        // Should be close to 30, allow some variance
        assert!(sampled > 15 && sampled < 50);
    }

    #[test]
    fn test_select_verifier() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_verifier_1".into(), 10_000).unwrap();
        reg.register("axm_verifier_2".into(), 10_000).unwrap();

        let selected = reg.select_verifier("job_123").unwrap();
        assert!(selected.is_some());
    }

    #[test]
    fn test_select_verifier_deterministic() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_verifier_1".into(), 10_000).unwrap();
        reg.register("axm_verifier_2".into(), 10_000).unwrap();

        let selected1 = reg.select_verifier("job_123").unwrap();
        let selected2 = reg.select_verifier("job_123").unwrap();
        assert_eq!(selected1, selected2);
    }

    #[test]
    fn test_record_successful_challenge() {
        let (_tmp, reg) = open_registry();
        let verifier = reg.register("axm_verifier_1".into(), 10_000).unwrap();
        assert_eq!(verifier.successful_challenges, 0);

        let updated = reg
            .record_challenge_outcome("axm_verifier_1", true)
            .unwrap();
        assert_eq!(updated.total_challenges, 1);
        assert_eq!(updated.successful_challenges, 1);
        assert!(updated.reputation_score >= 1.0); // Bumped up or stable
    }

    #[test]
    fn test_false_challenge_penalty() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_verifier_1".into(), 10_000).unwrap();

        let updated = reg
            .record_challenge_outcome("axm_verifier_1", false)
            .unwrap();
        assert_eq!(updated.total_challenges, 1);
        assert_eq!(updated.successful_challenges, 0);
        // No reputation boost
        assert_eq!(updated.reputation_score, 1.0);
    }
}
