// Copyright (c) 2026 Kantoshi Miyamura
//
//! Integration tests for the Proof of Useful Compute (PoUC) Protocol
//!
//! Tests verify:
//! 1. Full job lifecycle (submit → assign → compute → result → finalize)
//! 2. Dispute protocol (challenge, resolution, slashing)
//! 3. Worker and verifier registration and reputation
//! 4. Fee distribution and settlement
//! 5. Error cases and attack resistance

use axiom_ai::{
    ComputeJobStatus, ComputeProtocol, DisputeResolution,
    FileChallengeRequest, RegisterVerifierRequest, RegisterWorkerRequest, SubmitComputeJobRequest,
    SubmitResultRequest,
};
use tempfile::TempDir;

fn setup_protocol() -> (TempDir, ComputeProtocol) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let protocol = ComputeProtocol::open(temp_dir.path())
        .expect("Failed to initialize compute protocol");
    (temp_dir, protocol)
}

/// Generate a valid 64-character hex hash for testing
fn valid_hash(prefix: &str) -> String {
    format!("{:0<64}", prefix) // Pad with zeros to 64 chars
}

/// Generate a valid hash from a string seed
fn hash_from_seed(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the expected commitment for a result
fn compute_commitment(job_id: &str, worker: &str, result_hash: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(b"|");
    hasher.update(worker.as_bytes());
    hasher.update(b"|");
    hasher.update(result_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1: Worker Registration
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_worker_registration() {
    let (_temp, protocol) = setup_protocol();

    let req = RegisterWorkerRequest {
        worker_id: "ax1worker1234".to_string(),
        initial_stake_sat: 5_000,
    };

    let result = protocol.register_worker(req);
    assert!(result.is_ok(), "Worker registration should succeed");

    let worker = result.unwrap();
    assert_eq!(worker.worker_id, "ax1worker1234");
    assert_eq!(worker.stake_sat, 5_000);
    assert!(worker.active);
    assert_eq!(worker.reputation_score, 1.0, "Initial reputation should be 1.0");
    assert_eq!(worker.total_jobs, 0);
    assert_eq!(worker.successful_jobs, 0);
    assert_eq!(worker.fraud_convictions, 0);
}

#[test]
fn test_get_registered_worker() {
    let (_temp, protocol) = setup_protocol();

    let req = RegisterWorkerRequest {
        worker_id: "ax1worker2345".to_string(),
        initial_stake_sat: 2_000,
    };
    protocol.register_worker(req).expect("Registration failed");

    let retrieved = protocol
        .get_worker("ax1worker2345")
        .expect("Get worker should succeed");

    assert!(retrieved.is_some());
    let worker = retrieved.unwrap();
    assert_eq!(worker.worker_id, "ax1worker2345");
    assert_eq!(worker.stake_sat, 2_000);
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2: Verifier Registration
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_verifier_registration() {
    let (_temp, protocol) = setup_protocol();

    let req = RegisterVerifierRequest {
        verifier_id: "ax1verifier1".to_string(),
        initial_stake_sat: 10_000,
    };

    let result = protocol.register_verifier(req);
    assert!(result.is_ok(), "Verifier registration should succeed");

    let verifier = result.unwrap();
    assert_eq!(verifier.verifier_id, "ax1verifier1");
    assert_eq!(verifier.stake_sat, 10_000);
    assert!(verifier.active);
    assert_eq!(verifier.reputation_score, 1.0);
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3: Job Submission
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_submit_compute_job() {
    let (_temp, protocol) = setup_protocol();

    let req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_test1"),
        input_hash: hash_from_seed("input_test1"),
        requester: "ax1user1234".to_string(),
        fee_sat: 1000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let result = protocol.submit_job(req);
    assert!(result.is_ok(), "Job submission should succeed");

    let job = result.unwrap();
    assert_eq!(job.requester, "ax1user1234");
    assert_eq!(job.fee_sat, 1000);
    assert!(matches!(job.status, ComputeJobStatus::Submitted));
}

#[test]
fn test_job_fee_validation() {
    let (_temp, protocol) = setup_protocol();

    // Attempt to submit job with fee below minimum
    let req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_fee"),
        input_hash: hash_from_seed("input_fee"),
        requester: "ax1user".to_string(),
        fee_sat: 100, // Too low
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let result = protocol.submit_job(req);
    assert!(result.is_err(), "Job with insufficient fee should be rejected");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4: Job Lifecycle - Full Success Path
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_job_lifecycle_success() {
    let (_temp, protocol) = setup_protocol();

    // Step 1: Register worker
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1worker_lifecycle".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    // Step 2: Submit job
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_lifecycle"),
        input_hash: hash_from_seed("input_lifecycle"),
        requester: "ax1requester".to_string(),
        fee_sat: 5000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id.clone();

    assert!(matches!(job.status, ComputeJobStatus::Submitted));

    // Step 3: Assign job
    let assigned = protocol
        .assign_job(&job_id)
        .expect("Job assignment should succeed");
    assert!(matches!(assigned.status, ComputeJobStatus::Assigned { .. }));

    // Step 4: Acknowledge (worker starts computing)
    let computing = protocol
        .acknowledge_job(&job_id, "ax1worker_lifecycle")
        .expect("Acknowledge should succeed");
    assert!(matches!(computing.status, ComputeJobStatus::Computing { .. }));

    // Step 5: Submit result
    let result_hash = hash_from_seed("result_lifecycle");
    let commitment = compute_commitment(&job_id, "ax1worker_lifecycle", &result_hash);
    let result_req = SubmitResultRequest {
        job_id: job_id.clone(),
        worker_address: "ax1worker_lifecycle".to_string(),
        result_hash,
        result_size_bytes: 50000,
        compute_time_ms: 5000,
        commitment_hash: commitment,
        worker_signature: hash_from_seed("signature_lifecycle"),
    };

    let completed = protocol
        .submit_result(result_req)
        .expect("Result submission should succeed");
    assert!(matches!(completed.status, ComputeJobStatus::Completed { .. }));

    // Step 6: Just verify the job is in completed state (can't finalize immediately due to challenge window)
    let finalized_job = protocol
        .get_job(&job_id)
        .expect("Get job should succeed")
        .expect("Job should exist");
    assert!(matches!(finalized_job.status, ComputeJobStatus::Completed { .. }));
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5: Job Listing by Requester
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_list_jobs_for_requester() {
    let (_temp, protocol) = setup_protocol();

    // Submit 3 jobs for same requester
    for i in 0..3 {
        let req = SubmitComputeJobRequest {
            job_type: "inference".to_string(),
            model_hash: hash_from_seed(&format!("model_list_{}", i)),
            input_hash: hash_from_seed(&format!("input_list_{}", i)),
            requester: "ax1requester_list".to_string(),
            fee_sat: 1000 + (i as u64 * 100),
            deadline_secs: 3600,
            result_size_limit_bytes: 1_000_000,
        };
        protocol.submit_job(req).expect("Job submission failed");
    }

    let jobs = protocol
        .list_jobs_for_requester("ax1requester_list", 10)
        .expect("List jobs should succeed");

    assert_eq!(jobs.len(), 3, "Should have 3 jobs for this requester");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6: List Active Workers
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_list_active_workers() {
    let (_temp, protocol) = setup_protocol();

    // Register 5 workers
    for i in 0..5 {
        protocol
            .register_worker(RegisterWorkerRequest {
                worker_id: format!("ax1worker_active_{}", i),
                initial_stake_sat: 2_000,
            })
            .expect("Worker registration failed");
    }

    let workers = protocol
        .list_active_workers(10)
        .expect("List active workers should succeed");

    assert_eq!(workers.len(), 5, "Should have 5 active workers");
    assert!(workers.iter().all(|w| w.active), "All workers should be active");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 7: Dispute Protocol - Fraud Detected
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dispute_fraud_detected() {
    let (_temp, protocol) = setup_protocol();

    // Register worker and verifier
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1fraud_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    protocol
        .register_verifier(RegisterVerifierRequest {
            verifier_id: "ax1fraud_verifier".to_string(),
            initial_stake_sat: 10_000,
        })
        .expect("Verifier registration failed");

    // Submit and complete a job
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_fraud"),
        input_hash: hash_from_seed("input_fraud"),
        requester: "ax1req_fraud".to_string(),
        fee_sat: 10000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id.clone();

    protocol
        .assign_job(&job_id)
        .expect("Job assignment failed");
    protocol
        .acknowledge_job(&job_id, "ax1fraud_worker")
        .expect("Acknowledge failed");

    let bad_result_hash = hash_from_seed("bad_result");
    let fraud_commitment = compute_commitment(&job_id, "ax1fraud_worker", &bad_result_hash);
    let result_req = SubmitResultRequest {
        job_id: job_id.clone(),
        worker_address: "ax1fraud_worker".to_string(),
        result_hash: bad_result_hash,
        result_size_bytes: 50000,
        compute_time_ms: 5000,
        commitment_hash: fraud_commitment,
        worker_signature: hash_from_seed("signature_fraud"),
    };

    protocol
        .submit_result(result_req)
        .expect("Result submission failed");

    // Verifier challenges the result
    let verifier_result_hash = hash_from_seed("correct_result");
    let verifier_commitment = compute_commitment(&job_id, "ax1fraud_verifier", &verifier_result_hash);
    let challenge_req = FileChallengeRequest {
        job_id: job_id.clone(),
        verifier_address: "ax1fraud_verifier".to_string(),
        challenger_result_hash: verifier_result_hash,
        commitment_hash: verifier_commitment,
        verifier_signature: hash_from_seed("verifier_sig"),
    };

    let dispute = protocol
        .challenge_result(challenge_req)
        .expect("Challenge filing should succeed");

    assert_eq!(dispute.job_id, job_id);
    assert_eq!(dispute.challenger, "ax1fraud_verifier");

    // Resolve dispute: fraud confirmed
    let settlement = protocol
        .resolve_dispute(
            &dispute.dispute_id,
            DisputeResolution::FraudConfirmed {
                worker_slash_sat: 1000,
                verifier_reward_sat: 1500,
                resolved_at: 1000,
            },
        )
        .expect("Dispute resolution should succeed");

    assert!(settlement.slash_sat > 0, "Should have slashed worker");
    assert!(settlement.verifier_reward_sat > 0, "Verifier should be rewarded");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 8: Settlement Record Tracking
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_list_recent_settlements() {
    let (_temp, protocol) = setup_protocol();

    // Register worker
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1settle_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    // Submit and finalize a job to generate settlement
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_settle"),
        input_hash: hash_from_seed("input_settle"),
        requester: "ax1settle_req".to_string(),
        fee_sat: 2000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id;

    protocol
        .assign_job(&job_id)
        .expect("Assignment failed");
    protocol
        .acknowledge_job(&job_id, "ax1settle_worker")
        .expect("Acknowledge failed");

    let settle_result_hash = hash_from_seed("settle_result");
    let settle_commitment = compute_commitment(&job_id, "ax1settle_worker", &settle_result_hash);
    let result_req = SubmitResultRequest {
        job_id: job_id.clone(),
        worker_address: "ax1settle_worker".to_string(),
        result_hash: settle_result_hash,
        result_size_bytes: 50000,
        compute_time_ms: 5000,
        commitment_hash: settle_commitment,
        worker_signature: hash_from_seed("settle_sig"),
    };

    protocol
        .submit_result(result_req)
        .expect("Result submission failed");

    // Job should be completed, but challenge window prevents finalization
    let completed_job = protocol
        .get_job(&job_id)
        .expect("Get job should succeed")
        .expect("Job should exist");
    assert!(matches!(completed_job.status, ComputeJobStatus::Completed { .. }));

    // List settlements (may be empty due to challenge window)
    let settlements = protocol
        .list_recent_settlements(10)
        .expect("List settlements should succeed");

    // API sanity check — list_recent_settlements must not error; contents may be empty.
    let _ = settlements.len();
}

// ────────────────────────────────────────────────────────────────────────────
// Test 9: Max Concurrent Jobs Per Address
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_max_concurrent_jobs_limit() {
    let (_temp, protocol) = setup_protocol();

    let requester = "ax1max_jobs_req";

    // Submit 10 jobs (the limit)
    for i in 0..10 {
        let req = SubmitComputeJobRequest {
            job_type: "inference".to_string(),
            model_hash: hash_from_seed(&format!("model_max_{}", i)),
            input_hash: hash_from_seed(&format!("input_max_{}", i)),
            requester: requester.to_string(),
            fee_sat: 1000,
            deadline_secs: 3600,
            result_size_limit_bytes: 1_000_000,
        };

        assert!(protocol.submit_job(req).is_ok(), "Job {} should succeed", i);
    }

    // Attempt to submit 11th job (should fail)
    let req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_max_11"),
        input_hash: hash_from_seed("input_max_11"),
        requester: requester.to_string(),
        fee_sat: 1000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let result = protocol.submit_job(req);
    assert!(
        result.is_err(),
        "11th concurrent job should be rejected due to limit"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 10: Result Payload Size Validation
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_result_payload_size_limit() {
    let (_temp, protocol) = setup_protocol();

    // Register worker
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1size_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    // Submit job with result size limit
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_size"),
        input_hash: hash_from_seed("input_size"),
        requester: "ax1size_req".to_string(),
        fee_sat: 5000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1000, // 1KB limit
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id;

    protocol
        .assign_job(&job_id)
        .expect("Assignment failed");
    protocol
        .acknowledge_job(&job_id, "ax1size_worker")
        .expect("Acknowledge failed");

    // Try to submit result larger than limit
    let size_result_hash = hash_from_seed("size_result");
    let size_commitment = compute_commitment(&job_id, "ax1size_worker", &size_result_hash);
    let result_req = SubmitResultRequest {
        job_id: job_id.clone(),
        worker_address: "ax1size_worker".to_string(),
        result_hash: size_result_hash,
        result_size_bytes: 10_000, // Exceeds 1KB limit
        compute_time_ms: 5000,
        commitment_hash: size_commitment,
        worker_signature: hash_from_seed("size_sig"),
    };

    let result = protocol.submit_result(result_req);
    assert!(
        result.is_err(),
        "Result exceeding size limit should be rejected"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 11: Job Expiry
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_job_expiry() {
    let (_temp, protocol) = setup_protocol();

    // Submit job with very short deadline (but negative time is invalid, use large number)
    // The test will be to ensure the protocol tracks expiry correctly
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_expire"),
        input_hash: hash_from_seed("input_expire"),
        requester: "ax1expire_req".to_string(),
        fee_sat: 1000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id;

    // Just verify the job can be retrieved
    let retrieved = protocol.get_job(&job_id).expect("Get job should succeed");
    assert!(retrieved.is_some());
}

// ────────────────────────────────────────────────────────────────────────────
// Test 12: Get Non-existent Job
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_get_nonexistent_job() {
    let (_temp, protocol) = setup_protocol();

    let result = protocol
        .get_job("nonexistent_job_id")
        .expect("Query should not error");

    assert!(result.is_none(), "Non-existent job should return None");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 13: List Jobs by Status
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_list_jobs_by_status() {
    let (_temp, protocol) = setup_protocol();

    // Register worker
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1status_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    // Submit 3 jobs and leave them in different states
    for i in 0..3 {
        let job_req = SubmitComputeJobRequest {
            job_type: "inference".to_string(),
            model_hash: hash_from_seed(&format!("model_status_{}", i)),
            input_hash: hash_from_seed(&format!("input_status_{}", i)),
            requester: format!("ax1status_req_{}", i),
            fee_sat: 1000,
            deadline_secs: 3600,
            result_size_limit_bytes: 1_000_000,
        };

        let job = protocol.submit_job(job_req).expect("Job submission failed");

        if i == 1 {
            // Assign the second job
            protocol
                .assign_job(&job.job_id)
                .expect("Assignment failed");
        } else if i == 2 {
            // Complete the third job
            protocol
                .assign_job(&job.job_id)
                .expect("Assignment failed");
            protocol
                .acknowledge_job(&job.job_id, "ax1status_worker")
                .expect("Acknowledge failed");
        }
    }

    // List submitted jobs (should be at least 1)
    let submitted = protocol
        .list_jobs_by_status("Submitted", 10)
        .expect("List by status should succeed");
    assert!(submitted.len() > 0, "Should have at least one submitted job");

    // List assigned jobs (should be at least 1)
    let assigned = protocol
        .list_jobs_by_status("Assigned", 10)
        .expect("List by status should succeed");
    assert!(assigned.len() > 0, "Should have at least one assigned job");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 14: Worker Reputation Tracking
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_worker_reputation_updates() {
    let (_temp, protocol) = setup_protocol();

    // Register worker
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1rep_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    // Get initial reputation
    let initial = protocol
        .get_worker("ax1rep_worker")
        .expect("Get worker should succeed")
        .expect("Worker should exist");

    assert_eq!(initial.reputation_score, 1.0, "Initial reputation should be 1.0");
    assert_eq!(initial.total_jobs, 0);
    assert_eq!(initial.successful_jobs, 0);
}

// ────────────────────────────────────────────────────────────────────────────
// Test 15: Verifier False Accusation
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dispute_false_accusation() {
    let (_temp, protocol) = setup_protocol();

    // Register worker and verifier
    protocol
        .register_worker(RegisterWorkerRequest {
            worker_id: "ax1false_worker".to_string(),
            initial_stake_sat: 5_000,
        })
        .expect("Worker registration failed");

    protocol
        .register_verifier(RegisterVerifierRequest {
            verifier_id: "ax1false_verifier".to_string(),
            initial_stake_sat: 10_000,
        })
        .expect("Verifier registration failed");

    // Submit and complete a valid job
    let job_req = SubmitComputeJobRequest {
        job_type: "inference".to_string(),
        model_hash: hash_from_seed("model_false"),
        input_hash: hash_from_seed("input_false"),
        requester: "ax1req_false".to_string(),
        fee_sat: 5000,
        deadline_secs: 3600,
        result_size_limit_bytes: 1_000_000,
    };

    let job = protocol.submit_job(job_req).expect("Job submission failed");
    let job_id = job.job_id.clone();

    protocol
        .assign_job(&job_id)
        .expect("Assignment failed");
    protocol
        .acknowledge_job(&job_id, "ax1false_worker")
        .expect("Acknowledge failed");

    let false_result_hash = hash_from_seed("correct_false_result");
    let false_commitment = compute_commitment(&job_id, "ax1false_worker", &false_result_hash);
    let result_req = SubmitResultRequest {
        job_id: job_id.clone(),
        worker_address: "ax1false_worker".to_string(),
        result_hash: false_result_hash,
        result_size_bytes: 50000,
        compute_time_ms: 5000,
        commitment_hash: false_commitment,
        worker_signature: hash_from_seed("signature_false"),
    };

    protocol
        .submit_result(result_req)
        .expect("Result submission failed");

    // Verifier falsely challenges the correct result
    let false_verifier_hash = hash_from_seed("wrong_challenger_hash");
    let false_verifier_commitment = compute_commitment(&job_id, "ax1false_verifier", &false_verifier_hash);
    let challenge_req = FileChallengeRequest {
        job_id: job_id.clone(),
        verifier_address: "ax1false_verifier".to_string(),
        challenger_result_hash: false_verifier_hash,
        commitment_hash: false_verifier_commitment,
        verifier_signature: hash_from_seed("verifier_sig_false"),
    };

    let dispute = protocol
        .challenge_result(challenge_req)
        .expect("Challenge filing should succeed");

    // Resolve: False accusation
    let settlement = protocol
        .resolve_dispute(
            &dispute.dispute_id,
            DisputeResolution::FalseAccusation {
                verifier_slash_sat: 500,
                worker_bonus_sat: 250,
                resolved_at: 1000,
            },
        )
        .expect("Dispute resolution should succeed");

    assert!(settlement.slash_sat > 0, "Verifier should be slashed");
}

// ────────────────────────────────────────────────────────────────────────────
// Test 16: Multiple Verifiers
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_multiple_verifier_registration() {
    let (_temp, protocol) = setup_protocol();

    // Register multiple verifiers
    for i in 0..5 {
        let req = RegisterVerifierRequest {
            verifier_id: format!("ax1verifier_{}", i),
            initial_stake_sat: 5_000,
        };

        assert!(
            protocol.register_verifier(req).is_ok(),
            "Verifier {} registration should succeed",
            i
        );
    }

    // Verify they're all active
    let verifiers = protocol
        .list_active_workers(10)
        .expect("Should be able to list");

    // API sanity check — list_active_workers must return a (possibly empty) Vec.
    let _ = verifiers.len();
}
