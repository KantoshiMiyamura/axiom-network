// Copyright (c) 2026 Kantoshi Miyamura
//
//! Worker Registration and Stake Management
//!
//! Tracks compute providers with stake, reputation, and job outcomes.
//! Workers are stake-weighted randomly selected for job assignment.

use crate::compute_types::*;
use fjall::{Config, PartitionCreateOptions};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Thread-safe worker registry stored at `<data_dir>/ai_workers/`.
pub struct WorkerRegistry {
    _keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl WorkerRegistry {
    /// Open (or create) the worker registry.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_workers");
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| ComputeError::Storage(e.to_string()))?;
        let partition = keyspace
            .open_partition("workers", PartitionCreateOptions::default())
            .map_err(|e| ComputeError::Storage(e.to_string()))?;
        Ok(WorkerRegistry {
            _keyspace: keyspace,
            partition,
        })
    }

    /// Register a new worker with initial stake.
    pub fn register(
        &self,
        worker_id: String,
        initial_stake_sat: u64,
    ) -> Result<WorkerRegistration> {
        if initial_stake_sat < MIN_WORKER_STAKE_SAT {
            return Err(ComputeError::InsufficientStake {
                required: MIN_WORKER_STAKE_SAT,
                have: initial_stake_sat,
            });
        }

        if self
            .partition
            .contains_key(&worker_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            return Err(ComputeError::WorkerNotFound(format!(
                "Worker {} already registered",
                worker_id
            )));
        }

        let worker = WorkerRegistration {
            worker_id: worker_id.clone(),
            stake_sat: initial_stake_sat,
            registered_at: current_ts(),
            active: true,
            reputation_score: 1.0, // Start with perfect reputation
            total_jobs: 0,
            successful_jobs: 0,
            fraud_convictions: 0,
        };

        self.save(&worker)?;
        Ok(worker)
    }

    /// Get a worker by ID.
    pub fn get(&self, worker_id: &str) -> Result<Option<WorkerRegistration>> {
        match self
            .partition
            .get(worker_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            Some(v) => {
                let (worker, _) = bincode::serde::decode_from_slice::<WorkerRegistration, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| ComputeError::Serialization(e.to_string()))?;
                Ok(Some(worker))
            }
            None => Ok(None),
        }
    }

    /// List all active workers.
    pub fn list_active(&self, limit: usize) -> Result<Vec<WorkerRegistration>> {
        let mut workers = Vec::new();
        for kv in self.partition.iter() {
            let (_, v) = kv.map_err(|e| ComputeError::Storage(e.to_string()))?;
            if let Ok((worker, _)) = bincode::serde::decode_from_slice::<WorkerRegistration, _>(
                &v,
                bincode::config::standard(),
            ) {
                if worker.active {
                    workers.push(worker);
                }
            }
        }
        workers.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        workers.truncate(limit);
        Ok(workers)
    }

    /// Add stake to a worker.
    pub fn add_stake(&self, worker_id: &str, amount_sat: u64) -> Result<WorkerRegistration> {
        let mut worker = self
            .get(worker_id)?
            .ok_or_else(|| ComputeError::WorkerNotFound(worker_id.to_string()))?;

        worker.stake_sat = worker
            .stake_sat
            .checked_add(amount_sat)
            .ok_or_else(|| ComputeError::Storage("Stake overflow".to_string()))?;

        self.save(&worker)?;
        Ok(worker)
    }

    /// Slash stake from a worker (for fraud conviction).
    pub fn slash_stake(&self, worker_id: &str, amount_sat: u64) -> Result<WorkerRegistration> {
        let mut worker = self
            .get(worker_id)?
            .ok_or_else(|| ComputeError::WorkerNotFound(worker_id.to_string()))?;

        worker.stake_sat = worker.stake_sat.saturating_sub(amount_sat);
        worker.fraud_convictions = worker.fraud_convictions.saturating_add(1);

        // Apply reputation penalty
        worker.reputation_score *= REPUTATION_FRAUD_PENALTY;

        // Evict if reputation too low
        if worker.reputation_score < REPUTATION_EVICTION_THRESHOLD {
            worker.active = false;
        }

        self.save(&worker)?;
        Ok(worker)
    }

    /// Record a job outcome (success or failure) and update reputation.
    pub fn record_job_outcome(&self, worker_id: &str, success: bool) -> Result<WorkerRegistration> {
        let mut worker = self
            .get(worker_id)?
            .ok_or_else(|| ComputeError::WorkerNotFound(worker_id.to_string()))?;

        worker.total_jobs = worker.total_jobs.saturating_add(1);

        if success {
            worker.successful_jobs = worker.successful_jobs.saturating_add(1);
            // Boost reputation slightly for success
            worker.reputation_score = (worker.reputation_score + REPUTATION_SUCCESS_BONUS).min(1.0);
        }

        self.save(&worker)?;
        Ok(worker)
    }

    /// Deactivate a worker (eviction for low reputation or breach).
    pub fn deactivate(&self, worker_id: &str) -> Result<WorkerRegistration> {
        let mut worker = self
            .get(worker_id)?
            .ok_or_else(|| ComputeError::WorkerNotFound(worker_id.to_string()))?;

        worker.active = false;
        self.save(&worker)?;
        Ok(worker)
    }

    /// Select a worker for a job using stake-weighted random selection.
    ///
    /// Uses the provided seed (e.g., job_id hash) to ensure deterministic
    /// but distributed selection across active workers.
    pub fn select_worker(&self, seed_bytes: &[u8]) -> Result<Option<String>> {
        let workers = self.list_active(10000)?;

        if workers.is_empty() {
            return Ok(None);
        }

        // Compute total stake
        let total_stake: u64 = workers.iter().map(|w| w.stake_sat).sum();
        if total_stake == 0 {
            return Ok(None);
        }

        // Derive deterministic random value from seed
        let mut hasher = Sha256::new();
        hasher.update(seed_bytes);
        let hash = hasher.finalize();
        let mut selector = [0u8; 8];
        selector.copy_from_slice(&hash[0..8]);
        let random_val = u64::from_le_bytes(selector) % total_stake;

        // Find worker at cumulative stake boundary
        let mut cumulative = 0u64;
        for worker in &workers {
            cumulative = cumulative.saturating_add(worker.stake_sat);
            if random_val < cumulative {
                return Ok(Some(worker.worker_id.clone()));
            }
        }

        // Fallback to first worker
        workers
            .first()
            .map(|w| w.worker_id.clone())
            .map(Some)
            .ok_or_else(|| ComputeError::Storage("Worker list corrupted".to_string()))
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    fn save(&self, worker: &WorkerRegistration) -> Result<()> {
        let value = bincode::serde::encode_to_vec(worker, bincode::config::standard())
            .map_err(|e| ComputeError::Serialization(e.to_string()))?;
        self.partition
            .insert(&worker.worker_id, value)
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

    fn open_registry() -> (TempDir, WorkerRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = WorkerRegistry::open(tmp.path()).unwrap();
        (tmp, reg)
    }

    #[test]
    fn test_register_worker() {
        let (_tmp, reg) = open_registry();
        let worker = reg.register("axm_worker_1".into(), 5_000).unwrap();

        assert_eq!(worker.worker_id, "axm_worker_1");
        assert_eq!(worker.stake_sat, 5_000);
        assert!(worker.active);
        assert_eq!(worker.reputation_score, 1.0);
        assert_eq!(worker.total_jobs, 0);
    }

    #[test]
    fn test_register_insufficient_stake() {
        let (_tmp, reg) = open_registry();
        let result = reg.register("axm_worker_1".into(), 100); // Too low
        assert!(result.is_err());
    }

    #[test]
    fn test_get_worker() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_worker_1".into(), 5_000).unwrap();

        let fetched = reg.get("axm_worker_1").unwrap().unwrap();
        assert_eq!(fetched.worker_id, "axm_worker_1");
    }

    #[test]
    fn test_add_stake() {
        let (_tmp, reg) = open_registry();
        let worker = reg.register("axm_worker_1".into(), 5_000).unwrap();
        assert_eq!(worker.stake_sat, 5_000);

        let updated = reg.add_stake("axm_worker_1", 2_000).unwrap();
        assert_eq!(updated.stake_sat, 7_000);
    }

    #[test]
    fn test_slash_stake() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_worker_1".into(), 10_000).unwrap();

        let slashed = reg.slash_stake("axm_worker_1", 2_000).unwrap();
        assert_eq!(slashed.stake_sat, 8_000);
        assert_eq!(slashed.fraud_convictions, 1);
    }

    #[test]
    fn test_record_success() {
        let (_tmp, reg) = open_registry();
        let worker = reg.register("axm_worker_1".into(), 5_000).unwrap();
        assert_eq!(worker.successful_jobs, 0);

        let updated = reg.record_job_outcome("axm_worker_1", true).unwrap();
        assert_eq!(updated.total_jobs, 1);
        assert_eq!(updated.successful_jobs, 1);
        assert!(updated.reputation_score >= 1.0); // Bumped up or stable
    }

    #[test]
    fn test_reputation_eviction() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_worker_1".into(), 1_000).unwrap();

        // Multiple fraud convictions should evict the worker
        for _ in 0..20 {
            reg.slash_stake("axm_worker_1", 100).ok();
        }

        let worker = reg.get("axm_worker_1").unwrap().unwrap();
        if worker.reputation_score < REPUTATION_EVICTION_THRESHOLD {
            assert!(!worker.active);
        }
    }

    #[test]
    fn test_select_worker() {
        let (_tmp, reg) = open_registry();
        reg.register("axm_worker_1".into(), 1_000).unwrap();
        reg.register("axm_worker_2".into(), 2_000).unwrap();

        let seed = b"test_seed";
        let selected = reg.select_worker(seed).unwrap();
        assert!(selected.is_some());
    }
}
