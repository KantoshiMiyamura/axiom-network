// Copyright (c) 2026 Kantoshi Miyamura
//
//! Compute Protocol Coordinator
//!
//! Orchestrates the full job lifecycle: submission → assignment → computation → verification → settlement.
//! All protocol state transitions and validations happen here.

use crate::compute_types::*;
use crate::settlement::SettlementEngine;
use crate::verifier::VerifierRegistry;
use crate::worker::WorkerRegistry;
use fjall::{Config, PartitionCreateOptions};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Main protocol coordinator for the compute market.
pub struct ComputeProtocol {
    _keyspace: fjall::Keyspace,
    jobs_partition: fjall::PartitionHandle,
    disputes_partition: fjall::PartitionHandle,
    workers: WorkerRegistry,
    verifiers: VerifierRegistry,
    settlement: SettlementEngine,
}

impl ComputeProtocol {
    /// Open (or create) the protocol at `<data_dir>/ai_protocol/`.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_protocol");
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| ComputeError::Storage(e.to_string()))?;

        let jobs_partition = keyspace
            .open_partition("jobs", PartitionCreateOptions::default())
            .map_err(|e| ComputeError::Storage(e.to_string()))?;

        let disputes_partition = keyspace
            .open_partition("disputes", PartitionCreateOptions::default())
            .map_err(|e| ComputeError::Storage(e.to_string()))?;

        let data_dir_ref = data_dir.as_ref();
        let workers = WorkerRegistry::open(data_dir_ref)?;
        let verifiers = VerifierRegistry::open(data_dir_ref)?;
        let settlement = SettlementEngine::open(data_dir_ref)?;

        Ok(ComputeProtocol {
            _keyspace: keyspace,
            jobs_partition,
            disputes_partition,
            workers,
            verifiers,
            settlement,
        })
    }

    /// Submit a new compute job.
    ///
    /// Validates:
    /// - Fee >= MIN_JOB_FEE_SAT
    /// - Input hash is valid 64-char hex
    /// - Deadline is in the future
    /// - Requester doesn't have too many active jobs
    pub fn submit_job(&self, req: SubmitComputeJobRequest) -> Result<ComputeJob> {
        // Validate fee
        if req.fee_sat < MIN_JOB_FEE_SAT {
            return Err(ComputeError::InvalidFee(format!(
                "Fee {} is below minimum {}",
                req.fee_sat, MIN_JOB_FEE_SAT
            )));
        }

        // Validate hashes
        validate_hex64(&req.input_hash)?;
        validate_hex64(&req.model_hash)?;

        // Validate deadline
        let now = current_ts();
        let deadline_ts = now.saturating_add(req.deadline_secs);
        if deadline_ts <= now {
            return Err(ComputeError::DeadlineExpired);
        }

        // Check job limit for requester
        let requester_jobs = self.list_jobs_for_requester(&req.requester, 1000)?;
        let active_count = requester_jobs
            .iter()
            .filter(|j| {
                matches!(
                    j.status,
                    ComputeJobStatus::Submitted
                        | ComputeJobStatus::Assigned { .. }
                        | ComputeJobStatus::Computing { .. }
                )
            })
            .count();

        if active_count >= MAX_CONCURRENT_JOBS_PER_ADDRESS {
            return Err(ComputeError::TooManyActiveJobs(req.requester.clone()));
        }

        // Generate deterministic job ID
        let job_id = derive_job_id(&req.model_hash, &req.requester);

        // Check for duplicate
        if self
            .jobs_partition
            .contains_key(&job_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            return Err(ComputeError::JobNotFound(format!(
                "Job {} already exists",
                job_id
            )));
        }

        let job_type = match req.job_type.as_str() {
            "inference" => ComputeJobType::Inference,
            "validation" => ComputeJobType::Validation,
            "benchmark" => ComputeJobType::Benchmark,
            _ => return Err(ComputeError::InvalidFee("Invalid job type".into())),
        };

        let job = ComputeJob {
            job_id: job_id.clone(),
            job_type,
            model_hash: req.model_hash,
            input_hash: req.input_hash,
            requester: req.requester,
            fee_sat: req.fee_sat,
            deadline_ts,
            challenge_window_secs: DEFAULT_CHALLENGE_WINDOW_SECS,
            status: ComputeJobStatus::Submitted,
            created_at: now,
            result_size_limit_bytes: req.result_size_limit_bytes,
        };

        self.save_job(&job)?;
        Ok(job)
    }

    /// Assign a job to a worker.
    ///
    /// Transitions: SUBMITTED → ASSIGNED
    /// The worker will be selected from active workers.
    pub fn assign_job(&self, job_id: &str) -> Result<ComputeJob> {
        let mut job = self
            .get_job(job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(job_id.to_string()))?;

        // Must be in SUBMITTED state
        if !matches!(job.status, ComputeJobStatus::Submitted) {
            return Err(ComputeError::InvalidTransition {
                expected: "Submitted".into(),
                got: format!("{:?}", job.status),
            });
        }

        // Select a worker
        let worker_id = self
            .workers
            .select_worker(job_id.as_bytes())?
            .ok_or_else(|| ComputeError::WorkerNotFound("No active workers available".into()))?;

        // Verify worker is active
        let worker = self
            .workers
            .get(&worker_id)?
            .ok_or_else(|| ComputeError::WorkerNotActive(worker_id.clone()))?;

        if !worker.active {
            return Err(ComputeError::WorkerNotActive(worker_id));
        }

        job.status = ComputeJobStatus::Assigned { worker: worker_id };
        self.save_job(&job)?;
        Ok(job)
    }

    /// Worker acknowledges job, transitions to COMPUTING state.
    pub fn acknowledge_job(&self, job_id: &str, worker_id: &str) -> Result<ComputeJob> {
        let mut job = self
            .get_job(job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(job_id.to_string()))?;

        // Must be in ASSIGNED state with this worker
        let assigned_worker = match &job.status {
            ComputeJobStatus::Assigned { worker } => worker.clone(),
            _ => {
                return Err(ComputeError::InvalidTransition {
                    expected: "Assigned".into(),
                    got: format!("{:?}", job.status),
                })
            }
        };

        if assigned_worker != worker_id {
            return Err(ComputeError::WorkerNotActive(format!(
                "Job assigned to {}, not {}",
                assigned_worker, worker_id
            )));
        }

        job.status = ComputeJobStatus::Computing {
            worker: worker_id.to_string(),
        };
        self.save_job(&job)?;
        Ok(job)
    }

    /// Worker submits result with cryptographic commitment.
    ///
    /// Transitions: COMPUTING → COMPLETED
    /// Validates:
    /// - Commitment matches expected SHA-256(job_id || worker || result_hash)
    /// - Result size <= limit
    /// - Signature is valid (off-chain verification by caller)
    pub fn submit_result(&self, req: SubmitResultRequest) -> Result<ComputeJob> {
        let mut job = self
            .get_job(&req.job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(req.job_id.clone()))?;

        // Must be in COMPUTING state with this worker
        let computing_worker = match &job.status {
            ComputeJobStatus::Computing { worker } => worker.clone(),
            _ => {
                return Err(ComputeError::InvalidTransition {
                    expected: "Computing".into(),
                    got: format!("{:?}", job.status),
                })
            }
        };

        if computing_worker != req.worker_address {
            return Err(ComputeError::WorkerNotActive(req.worker_address.clone()));
        }

        // Validate result size
        if req.result_size_bytes > job.result_size_limit_bytes {
            return Err(ComputeError::ResultTooLarge {
                size: req.result_size_bytes,
                max: job.result_size_limit_bytes,
            });
        }

        // Validate commitment
        let expected_commitment =
            compute_commitment(&req.job_id, &req.worker_address, &req.result_hash);
        if expected_commitment != req.commitment_hash {
            return Err(ComputeError::CommitmentMismatch);
        }

        // Validate result hash format
        validate_hex64(&req.result_hash)?;

        job.status = ComputeJobStatus::Completed {
            worker: req.worker_address,
            result_hash: req.result_hash,
            commitment_hash: req.commitment_hash,
            submitted_at: current_ts(),
        };

        self.save_job(&job)?;
        Ok(job)
    }

    /// Verifier challenges a result if it disagrees.
    ///
    /// Transitions: COMPLETED → CHALLENGED
    /// Verifier must:
    /// - Have stake >= MIN_VERIFIER_STAKE
    /// - Post challenge deposit (10% of job fee)
    /// - Provide own commitment + signature
    pub fn challenge_result(&self, req: FileChallengeRequest) -> Result<DisputeRecord> {
        let job = self
            .get_job(&req.job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(req.job_id.clone()))?;

        // Must be COMPLETED
        let (worker_addr, _original_result_hash, _commitment_hash) = match &job.status {
            ComputeJobStatus::Completed {
                worker,
                result_hash,
                commitment_hash,
                submitted_at: _,
            } => (worker.clone(), result_hash.clone(), commitment_hash.clone()),
            _ => {
                return Err(ComputeError::InvalidTransition {
                    expected: "Completed".into(),
                    got: format!("{:?}", job.status),
                })
            }
        };

        // Check if still in challenge window
        let now = current_ts();
        let challenge_window_end = match &job.status {
            ComputeJobStatus::Completed { submitted_at, .. } => {
                submitted_at.saturating_add(job.challenge_window_secs)
            }
            _ => now,
        };

        if now > challenge_window_end {
            return Err(ComputeError::ChallengeWindowExpired);
        }

        // Verify verifier is active
        let verifier = self
            .verifiers
            .get(&req.verifier_address)?
            .ok_or_else(|| ComputeError::VerifierNotActive(req.verifier_address.clone()))?;

        if !verifier.active {
            return Err(ComputeError::VerifierNotActive(
                req.verifier_address.clone(),
            ));
        }

        // Validate hashes
        validate_hex64(&req.challenger_result_hash)?;

        // Validate commitment
        let expected_commitment = compute_commitment(
            &req.job_id,
            &req.verifier_address,
            &req.challenger_result_hash,
        );
        if expected_commitment != req.commitment_hash {
            return Err(ComputeError::CommitmentMismatch);
        }

        // Generate dispute ID
        let dispute_id = derive_dispute_id(&req.job_id, &req.verifier_address);

        // Check for duplicate dispute
        if self
            .disputes_partition
            .contains_key(&dispute_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            return Err(ComputeError::DisputeNotFound(
                "Dispute already filed".into(),
            ));
        }

        let challenge_deposit = self.settlement.calculate_challenge_deposit(job.fee_sat);

        let dispute = DisputeRecord {
            dispute_id: dispute_id.clone(),
            job_id: req.job_id.clone(),
            challenger: req.verifier_address,
            challenger_result_hash: req.challenger_result_hash,
            commitment_hash: req.commitment_hash,
            challenger_signature: vec![],
            challenge_deposit_sat: challenge_deposit,
            filed_at: now,
            evidence_deadline_ts: now.saturating_add(300), // 5 min evidence window
            resolution: None,
        };

        self.save_dispute(&dispute)?;

        // Transition job to CHALLENGED
        let mut job = job;
        job.status = ComputeJobStatus::Challenged {
            worker: worker_addr,
            verifier: dispute.challenger.clone(),
            challenge_result_hash: dispute.challenger_result_hash.clone(),
            challenged_at: now,
        };
        self.save_job(&job)?;

        Ok(dispute)
    }

    /// Resolve a dispute (fraud confirmed, false accusation, or inconclusive).
    ///
    /// Updates worker/verifier reputation, slashes stakes, records settlement.
    pub fn resolve_dispute(
        &self,
        dispute_id: &str,
        resolution: DisputeResolution,
    ) -> Result<SettlementRecord> {
        let mut dispute = self
            .get_dispute(dispute_id)?
            .ok_or_else(|| ComputeError::DisputeNotFound(dispute_id.to_string()))?;

        let job = self
            .get_job(&dispute.job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(dispute.job_id.clone()))?;

        let worker_addr = match &job.status {
            ComputeJobStatus::Challenged {
                worker,
                challenge_result_hash: _,
                ..
            } => worker.clone(),
            _ => {
                return Err(ComputeError::InvalidTransition {
                    expected: "Challenged".into(),
                    got: format!("{:?}", job.status),
                })
            }
        };

        dispute.resolution = Some(resolution.clone());
        self.save_dispute(&dispute)?;

        // Process resolution
        let settlement = match resolution {
            DisputeResolution::FraudConfirmed { .. } => {
                // Worker was caught cheating
                let worker = self
                    .workers
                    .get(&worker_addr)?
                    .ok_or_else(|| ComputeError::WorkerNotFound(worker_addr.clone()))?;

                self.workers.slash_stake(
                    &worker_addr,
                    self.settlement.calculate_worker_slash(worker.stake_sat),
                )?;
                self.workers.record_job_outcome(&worker_addr, false)?;

                self.verifiers
                    .record_challenge_outcome(&dispute.challenger, true)?;

                self.settlement.record_fraud_conviction(
                    job.job_id.clone(),
                    job.fee_sat,
                    worker.stake_sat,
                    dispute.challenge_deposit_sat,
                )?
            }

            DisputeResolution::FalseAccusation { .. } => {
                // Verifier was wrong
                let _verifier = self
                    .verifiers
                    .get(&dispute.challenger)?
                    .ok_or_else(|| ComputeError::VerifierNotFound(dispute.challenger.clone()))?;

                let slash_amt = self
                    .settlement
                    .calculate_false_accuse_slash(dispute.challenge_deposit_sat);
                self.verifiers.slash_stake(&dispute.challenger, slash_amt)?;
                self.verifiers
                    .record_challenge_outcome(&dispute.challenger, false)?;

                let worker = self
                    .workers
                    .get(&worker_addr)?
                    .ok_or_else(|| ComputeError::WorkerNotFound(worker_addr.clone()))?;

                self.workers.record_job_outcome(&worker_addr, true)?;

                self.settlement.record_false_accusation(
                    job.job_id.clone(),
                    job.fee_sat,
                    dispute.challenge_deposit_sat,
                    worker.reputation_score,
                )?
            }

            DisputeResolution::Inconclusive { .. } => {
                // No determination — both get their deposits/stakes back
                self.settlement.record_success(
                    job.job_id.clone(),
                    job.fee_sat,
                    0.5, // Neutral reputation
                )?
            }
        };

        Ok(settlement)
    }

    /// Finalize a job (challenge window expired, no challenges filed).
    ///
    /// Transitions: COMPLETED → FINALIZED
    /// Distributes worker reward.
    pub fn finalize_job(&self, job_id: &str) -> Result<SettlementRecord> {
        let mut job = self
            .get_job(job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(job_id.to_string()))?;

        // Must be COMPLETED with challenge window expired
        let (worker_addr, result_hash) = match &job.status {
            ComputeJobStatus::Completed {
                worker,
                result_hash,
                submitted_at,
                ..
            } => {
                let now = current_ts();
                let window_end = submitted_at.saturating_add(job.challenge_window_secs);
                if now <= window_end {
                    return Err(ComputeError::InvalidTransition {
                        expected: "Challenge window expired".into(),
                        got: "Still in challenge window".into(),
                    });
                }
                (worker.clone(), result_hash.clone())
            }
            _ => {
                return Err(ComputeError::InvalidTransition {
                    expected: "Completed".into(),
                    got: format!("{:?}", job.status),
                })
            }
        };

        let worker = self
            .workers
            .get(&worker_addr)?
            .ok_or_else(|| ComputeError::WorkerNotFound(worker_addr.clone()))?;

        job.status = ComputeJobStatus::Finalized {
            result_hash,
            finalized_at: current_ts(),
        };

        self.save_job(&job)?;

        // Record settlement
        let settlement = self.settlement.record_success(
            job.job_id.clone(),
            job.fee_sat,
            worker.reputation_score,
        )?;

        // Update worker reputation for success
        self.workers.record_job_outcome(&worker_addr, true)?;

        Ok(settlement)
    }

    /// Expire a job (deadline passed, no completion).
    ///
    /// Transitions: Any → EXPIRED
    pub fn expire_job(&self, job_id: &str) -> Result<SettlementRecord> {
        let mut job = self
            .get_job(job_id)?
            .ok_or_else(|| ComputeError::JobNotFound(job_id.to_string()))?;

        let now = current_ts();
        if now <= job.deadline_ts {
            return Err(ComputeError::InvalidFee("Deadline not yet reached".into()));
        }

        job.status = ComputeJobStatus::Expired;
        self.save_job(&job)?;

        // Record settlement
        self.settlement.record_expired(job.job_id.clone())
    }

    /// Get a job by ID.
    pub fn get_job(&self, job_id: &str) -> Result<Option<ComputeJob>> {
        match self
            .jobs_partition
            .get(job_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            Some(v) => {
                let (job, _) = bincode::serde::decode_from_slice::<ComputeJob, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| ComputeError::Serialization(e.to_string()))?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Get a dispute by ID.
    pub fn get_dispute(&self, dispute_id: &str) -> Result<Option<DisputeRecord>> {
        match self
            .disputes_partition
            .get(dispute_id)
            .map_err(|e| ComputeError::Storage(e.to_string()))?
        {
            Some(v) => {
                let (dispute, _) = bincode::serde::decode_from_slice::<DisputeRecord, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| ComputeError::Serialization(e.to_string()))?;
                Ok(Some(dispute))
            }
            None => Ok(None),
        }
    }

    /// List jobs for a requester.
    pub fn list_jobs_for_requester(
        &self,
        requester: &str,
        limit: usize,
    ) -> Result<Vec<ComputeJob>> {
        let mut jobs = Vec::new();
        for kv in self.jobs_partition.iter() {
            let (_, v) = kv.map_err(|e| ComputeError::Storage(e.to_string()))?;
            if let Ok((job, _)) =
                bincode::serde::decode_from_slice::<ComputeJob, _>(&v, bincode::config::standard())
            {
                if job.requester == requester {
                    jobs.push(job);
                }
            }
        }
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs.truncate(limit);
        Ok(jobs)
    }

    /// List jobs by status.
    pub fn list_jobs_by_status(
        &self,
        target_status: &str,
        limit: usize,
    ) -> Result<Vec<ComputeJob>> {
        let mut jobs = Vec::new();
        for kv in self.jobs_partition.iter() {
            let (_, v) = kv.map_err(|e| ComputeError::Storage(e.to_string()))?;
            if let Ok((job, _)) =
                bincode::serde::decode_from_slice::<ComputeJob, _>(&v, bincode::config::standard())
            {
                let status_str = match &job.status {
                    ComputeJobStatus::Submitted => "Submitted",
                    ComputeJobStatus::Assigned { .. } => "Assigned",
                    ComputeJobStatus::Computing { .. } => "Computing",
                    ComputeJobStatus::Completed { .. } => "Completed",
                    ComputeJobStatus::Challenged { .. } => "Challenged",
                    ComputeJobStatus::Finalized { .. } => "Finalized",
                    ComputeJobStatus::Cancelled => "Cancelled",
                    ComputeJobStatus::Expired => "Expired",
                };

                if status_str == target_status {
                    jobs.push(job);
                }
            }
        }
        jobs.truncate(limit);
        Ok(jobs)
    }

    /// Register a new worker for compute jobs.
    pub fn register_worker(&self, req: RegisterWorkerRequest) -> Result<WorkerRegistration> {
        self.workers.register(req.worker_id, req.initial_stake_sat)
    }

    /// Get a worker registration by ID.
    pub fn get_worker(&self, worker_id: &str) -> Result<Option<WorkerRegistration>> {
        self.workers.get(worker_id)
    }

    /// List active workers.
    pub fn list_active_workers(&self, limit: usize) -> Result<Vec<WorkerRegistration>> {
        self.workers.list_active(limit)
    }

    /// Register a new verifier for disputes.
    pub fn register_verifier(&self, req: RegisterVerifierRequest) -> Result<VerifierRegistration> {
        self.verifiers
            .register(req.verifier_id, req.initial_stake_sat)
    }

    /// List recent settlements.
    pub fn list_recent_settlements(&self, limit: usize) -> Result<Vec<SettlementRecord>> {
        self.settlement.list_recent(limit)
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    fn save_job(&self, job: &ComputeJob) -> Result<()> {
        let value = bincode::serde::encode_to_vec(job, bincode::config::standard())
            .map_err(|e| ComputeError::Serialization(e.to_string()))?;
        self.jobs_partition
            .insert(&job.job_id, value)
            .map_err(|e| ComputeError::Storage(e.to_string()))
    }

    fn save_dispute(&self, dispute: &DisputeRecord) -> Result<()> {
        let value = bincode::serde::encode_to_vec(dispute, bincode::config::standard())
            .map_err(|e| ComputeError::Serialization(e.to_string()))?;
        self.disputes_partition
            .insert(&dispute.dispute_id, value)
            .map_err(|e| ComputeError::Storage(e.to_string()))
    }
}

// ─ Cryptographic Helpers ──────────────────────────────────────────────────

fn compute_commitment(job_id: &str, actor_address: &str, result_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(b"|");
    hasher.update(actor_address.as_bytes());
    hasher.update(b"|");
    hasher.update(result_hash.as_bytes());
    hex::encode(hasher.finalize())
}

fn derive_job_id(model_hash: &str, requester: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(model_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(requester.as_bytes());
    hex::encode(hasher.finalize())
}

fn derive_dispute_id(job_id: &str, challenger: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(b"|");
    hasher.update(challenger.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_hex64(s: &str) -> Result<()> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ComputeError::InvalidHash(s.to_string()));
    }
    Ok(())
}

fn current_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
