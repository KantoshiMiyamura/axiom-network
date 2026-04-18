// Copyright (c) 2026 Kantoshi Miyamura

//! Inference payment registry — Phase AI-2.
//!
//! Tracks `InferenceJob` records through their lifecycle:
//! `Pending` → `Completed` | `Cancelled`.
//!
//! Storage is a fjall LSM-tree partition at `<data_dir>/ai_jobs/`.
//! Jobs are keyed by their 64-char `job_id` hex string.

use crate::types::{InferenceJob, JobStatus};
use fjall::{Config, PartitionCreateOptions};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    #[error("storage error: {0}")]
    Storage(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("job not found: {0}")]
    NotFound(String),

    #[error("job is not in Pending state: {0}")]
    InvalidTransition(String),

    #[error("invalid hash (expected 64 lowercase hex chars): {0}")]
    InvalidHash(String),
}

pub type Result<T> = std::result::Result<T, InferenceError>;

/// Thread-safe inference job registry stored at `<data_dir>/ai_jobs/`.
pub struct InferenceRegistry {
    _keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl InferenceRegistry {
    /// Open (or create) the registry at `data_dir/ai_jobs`.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_jobs");
        let keyspace = Config::new(path).open()?;
        let partition = keyspace.open_partition("jobs", PartitionCreateOptions::default())?;
        Ok(InferenceRegistry {
            _keyspace: keyspace,
            partition,
        })
    }

    // ── Write operations ─────────────────────────────────────────────────────

    /// Create a new `Pending` inference job and persist it.
    pub fn create_job(
        &self,
        model_hash: String,
        requester: String,
        provider: String,
        amount_sat: u64,
    ) -> Result<InferenceJob> {
        // Use nanoseconds for ID derivation to avoid collisions within the same millisecond.
        let now_ns = now_nanos();
        let job_id = derive_job_id(&model_hash, &requester, now_ns);

        let job = InferenceJob {
            job_id: job_id.clone(),
            model_hash,
            requester,
            provider,
            amount_sat,
            status: JobStatus::Pending,
            result_hash: None,
            created_at: now_millis(),
            completed_at: None,
        };

        self.save(&job)?;
        Ok(job)
    }

    /// Mark a `Pending` job as `Completed` and record the result hash.
    ///
    /// Returns [`InferenceError::InvalidTransition`] if the job is not `Pending`.
    pub fn complete_job(&self, job_id: &str, result_hash: String) -> Result<InferenceJob> {
        validate_hex64(&result_hash)?;

        let mut job = self
            .get(job_id)?
            .ok_or_else(|| InferenceError::NotFound(job_id.to_string()))?;

        if job.status != JobStatus::Pending {
            return Err(InferenceError::InvalidTransition(job_id.to_string()));
        }

        job.status = JobStatus::Completed;
        job.result_hash = Some(result_hash);
        job.completed_at = Some(now_millis());

        self.save(&job)?;
        Ok(job)
    }

    /// Mark a `Pending` job as `Cancelled`.
    ///
    /// Returns [`InferenceError::InvalidTransition`] if the job is not `Pending`.
    pub fn cancel_job(&self, job_id: &str) -> Result<InferenceJob> {
        let mut job = self
            .get(job_id)?
            .ok_or_else(|| InferenceError::NotFound(job_id.to_string()))?;

        if job.status != JobStatus::Pending {
            return Err(InferenceError::InvalidTransition(job_id.to_string()));
        }

        job.status = JobStatus::Cancelled;
        job.completed_at = Some(now_millis());

        self.save(&job)?;
        Ok(job)
    }

    // ── Read operations ──────────────────────────────────────────────────────

    /// Fetch a job by its ID.
    pub fn get(&self, job_id: &str) -> Result<Option<InferenceJob>> {
        match self.partition.get(job_id)? {
            Some(v) => {
                let (job, _) = bincode::serde::decode_from_slice::<InferenceJob, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| InferenceError::Serialization(e.to_string()))?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Return up to `limit` jobs whose `requester` or `provider` matches
    /// `address`, sorted newest-first.
    pub fn list_jobs_for(&self, address: &str, limit: usize) -> Result<Vec<InferenceJob>> {
        let mut jobs = Vec::new();

        for kv in self.partition.iter() {
            let (_, v) = kv?;
            if let Ok((job, _)) = bincode::serde::decode_from_slice::<InferenceJob, _>(
                &v,
                bincode::config::standard(),
            ) {
                if job.requester == address || job.provider == address {
                    jobs.push(job);
                }
            }
        }

        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs.truncate(limit);
        Ok(jobs)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn save(&self, job: &InferenceJob) -> Result<()> {
        let value = bincode::serde::encode_to_vec(job, bincode::config::standard())
            .map_err(|e| InferenceError::Serialization(e.to_string()))?;
        self.partition.insert(&job.job_id, value)?;
        Ok(())
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Derive a unique job ID from model hash + requester + nanosecond timestamp.
fn derive_job_id(model_hash: &str, requester: &str, nanos: u128) -> String {
    let mut h = Sha256::new();
    h.update(model_hash.as_bytes());
    h.update(b"|");
    h.update(requester.as_bytes());
    h.update(b"|");
    h.update(nanos.to_le_bytes());
    hex::encode(h.finalize())
}

fn validate_hex64(s: &str) -> Result<()> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(InferenceError::InvalidHash(s.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::JobStatus;
    use tempfile::TempDir;

    const MODEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REQUESTER: &str = "axm_requester_address";
    const PROVIDER: &str = "axm_provider_address";
    const RESULT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn open_registry() -> (TempDir, InferenceRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = InferenceRegistry::open(tmp.path()).unwrap();
        (tmp, reg)
    }

    #[test]
    fn test_create_job_pending_state() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 1_000_000)
            .unwrap();

        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.model_hash, MODEL);
        assert_eq!(job.requester, REQUESTER);
        assert_eq!(job.provider, PROVIDER);
        assert_eq!(job.amount_sat, 1_000_000);
        assert!(job.result_hash.is_none());
        assert!(job.completed_at.is_none());
        assert_eq!(job.job_id.len(), 64); // 64-char hex
    }

    #[test]
    fn test_get_job_round_trip() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 500)
            .unwrap();
        let fetched = reg.get(&job.job_id).unwrap().expect("should exist");
        assert_eq!(fetched.job_id, job.job_id);
        assert_eq!(fetched.amount_sat, 500);
    }

    #[test]
    fn test_get_missing_job_returns_none() {
        let (_tmp, reg) = open_registry();
        let result = reg.get(&"0".repeat(64)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_complete_job_transitions_to_completed() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 1_000)
            .unwrap();

        let completed = reg.complete_job(&job.job_id, RESULT.into()).unwrap();
        assert_eq!(completed.status, JobStatus::Completed);
        assert_eq!(completed.result_hash.as_deref(), Some(RESULT));
        assert!(completed.completed_at.is_some());
    }

    #[test]
    fn test_complete_job_persists() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();
        reg.complete_job(&job.job_id, RESULT.into()).unwrap();

        let fetched = reg.get(&job.job_id).unwrap().unwrap();
        assert_eq!(fetched.status, JobStatus::Completed);
    }

    #[test]
    fn test_cancel_job_transitions_to_cancelled() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();

        let cancelled = reg.cancel_job(&job.job_id).unwrap();
        assert_eq!(cancelled.status, JobStatus::Cancelled);
        assert!(cancelled.completed_at.is_some());
    }

    #[test]
    fn test_complete_already_completed_errors() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();
        reg.complete_job(&job.job_id, RESULT.into()).unwrap();

        let err = reg.complete_job(&job.job_id, RESULT.into()).unwrap_err();
        assert!(matches!(err, InferenceError::InvalidTransition(_)));
    }

    #[test]
    fn test_cancel_already_cancelled_errors() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();
        reg.cancel_job(&job.job_id).unwrap();

        let err = reg.cancel_job(&job.job_id).unwrap_err();
        assert!(matches!(err, InferenceError::InvalidTransition(_)));
    }

    #[test]
    fn test_cancel_completed_job_errors() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();
        reg.complete_job(&job.job_id, RESULT.into()).unwrap();

        let err = reg.cancel_job(&job.job_id).unwrap_err();
        assert!(matches!(err, InferenceError::InvalidTransition(_)));
    }

    #[test]
    fn test_complete_with_invalid_result_hash() {
        let (_tmp, reg) = open_registry();
        let job = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();

        let err = reg
            .complete_job(&job.job_id, "not-a-hash".into())
            .unwrap_err();
        assert!(matches!(err, InferenceError::InvalidHash(_)));
    }

    #[test]
    fn test_complete_missing_job_errors() {
        let (_tmp, reg) = open_registry();
        let err = reg
            .complete_job(&"0".repeat(64), RESULT.into())
            .unwrap_err();
        assert!(matches!(err, InferenceError::NotFound(_)));
    }

    #[test]
    fn test_list_jobs_for_requester() {
        let (_tmp, reg) = open_registry();
        reg.create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 1_000)
            .unwrap();
        reg.create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 2_000)
            .unwrap();
        // Unrelated job
        reg.create_job(
            MODEL.into(),
            "other_requester".into(),
            PROVIDER.into(),
            3_000,
        )
        .unwrap();

        let jobs = reg.list_jobs_for(REQUESTER, 50).unwrap();
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|j| j.requester == REQUESTER));
    }

    #[test]
    fn test_list_jobs_for_provider() {
        let (_tmp, reg) = open_registry();
        reg.create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
            .unwrap();
        reg.create_job(MODEL.into(), "other".into(), "other_provider".into(), 0)
            .unwrap();

        let jobs = reg.list_jobs_for(PROVIDER, 50).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].provider, PROVIDER);
    }

    #[test]
    fn test_list_jobs_sorted_newest_first() {
        let (_tmp, reg) = open_registry();
        // Create two jobs — second will have a slightly later timestamp
        let job1 = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 1)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let job2 = reg
            .create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 2)
            .unwrap();

        let jobs = reg.list_jobs_for(REQUESTER, 50).unwrap();
        assert_eq!(jobs.len(), 2);
        // Newest first
        assert!(jobs[0].created_at >= jobs[1].created_at);
        // Verify it's job2 first
        assert_eq!(jobs[0].job_id, job2.job_id);
        assert_eq!(jobs[1].job_id, job1.job_id);
    }

    #[test]
    fn test_list_jobs_limit() {
        let (_tmp, reg) = open_registry();
        for _ in 0..5 {
            reg.create_job(MODEL.into(), REQUESTER.into(), PROVIDER.into(), 0)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let jobs = reg.list_jobs_for(REQUESTER, 3).unwrap();
        assert_eq!(jobs.len(), 3);
    }

    #[test]
    fn test_job_id_deterministic_for_same_inputs() {
        let id1 = derive_job_id(MODEL, REQUESTER, 1_000_000_u128);
        let id2 = derive_job_id(MODEL, REQUESTER, 1_000_000_u128);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_job_id_differs_for_different_timestamps() {
        let id1 = derive_job_id(MODEL, REQUESTER, 1_000_u128);
        let id2 = derive_job_id(MODEL, REQUESTER, 2_000_u128);
        assert_ne!(id1, id2);
    }
}
