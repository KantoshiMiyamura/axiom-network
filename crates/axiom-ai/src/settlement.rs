// Copyright (c) 2026 Kantoshi Miyamura
//
//! Settlement Engine — Reward Calculation and Distribution
//!
//! Computes fair rewards and slash amounts based on protocol rules.
//! Records settlement outcomes for audit trail.

use crate::compute_types::*;
use fjall::{Config, PartitionCreateOptions};
use std::path::Path;

/// Settlement engine with reward calculation and settlement recording.
pub struct SettlementEngine {
    _keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl SettlementEngine {
    /// Open (or create) the settlement engine at `<data_dir>/ai_settlements/`.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_settlements");
        let keyspace = Config::new(path).open().map_err(|e| ComputeError::Storage(e.to_string()))?;
        let partition = keyspace
            .open_partition("settlements", PartitionCreateOptions::default())
            .map_err(|e| ComputeError::Storage(e.to_string()))?;
        Ok(SettlementEngine {
            _keyspace: keyspace,
            partition,
        })
    }

    /// Calculate worker reward based on fee and reputation.
    ///
    /// Base reward: 80% of fee
    /// Reputation bonus: +2% for each 0.1 above 0.5 reputation (max +10%)
    pub fn calculate_worker_reward(&self, fee_sat: u64, reputation_score: f64) -> u64 {
        let base_reward = (fee_sat as f64 * WORKER_REWARD_BPS as f64 / 10000.0) as u64;

        // Reputation bonus: up to +10% of base
        let bonus_factor = if reputation_score > 0.9 {
            1.10
        } else if reputation_score > 0.7 {
            1.05
        } else {
            1.0
        };

        ((base_reward as f64) * bonus_factor) as u64
    }

    /// Calculate verifier reward for successful verification (no fraud).
    ///
    /// Reward: 5% of fee
    pub fn calculate_verifier_sample_reward(&self, fee_sat: u64) -> u64 {
        ((fee_sat as f64 * VERIFIER_SAMPLE_BPS as f64) / 10000.0) as u64
    }

    /// Calculate verifier reward for catching fraud.
    ///
    /// Reward: 15% of fee + returned challenge deposit
    pub fn calculate_verifier_fraud_reward(&self, fee_sat: u64, challenge_deposit_sat: u64) -> u64 {
        let fraud_reward = ((fee_sat as f64 * VERIFIER_FRAUD_CATCH_BPS as f64) / 10000.0) as u64;
        fraud_reward.saturating_add(challenge_deposit_sat)
    }

    /// Calculate challenge deposit required from verifier.
    ///
    /// Deposit: 10% of job fee
    pub fn calculate_challenge_deposit(&self, fee_sat: u64) -> u64 {
        ((fee_sat as f64 * CHALLENGE_DEPOSIT_BPS as f64) / 10000.0) as u64
    }

    /// Calculate slash amount for worker fraud.
    ///
    /// Slash: 20% of worker stake
    pub fn calculate_worker_slash(&self, worker_stake_sat: u64) -> u64 {
        ((worker_stake_sat as f64 * FRAUD_WORKER_SLASH_BPS as f64) / 10000.0) as u64
    }

    /// Calculate slash amount for verifier false accusation.
    ///
    /// Slash: 50% of challenge deposit
    pub fn calculate_false_accuse_slash(&self, challenge_deposit_sat: u64) -> u64 {
        ((challenge_deposit_sat as f64 * FALSE_ACCUSE_SLASH_BPS as f64) / 10000.0) as u64
    }

    /// Calculate protocol fee.
    ///
    /// Fee: 5% of job fee
    pub fn calculate_protocol_fee(&self, fee_sat: u64) -> u64 {
        ((fee_sat as f64 * PROTOCOL_FEE_BPS as f64) / 10000.0) as u64
    }

    /// Record a successful settlement (no dispute).
    pub fn record_success(
        &self,
        job_id: String,
        fee_sat: u64,
        worker_reputation: f64,
    ) -> Result<SettlementRecord> {
        let worker_reward = self.calculate_worker_reward(fee_sat, worker_reputation);
        let protocol_fee = self.calculate_protocol_fee(fee_sat);

        let settlement = SettlementRecord {
            job_id: job_id.clone(),
            worker_reward_sat: worker_reward,
            verifier_reward_sat: 0, // No verifier for successful jobs
            protocol_fee_sat: protocol_fee,
            slash_sat: 0,
            settled_at: current_ts(),
            outcome: SettlementOutcome::Success,
        };

        self.save(&settlement)?;
        Ok(settlement)
    }

    /// Record fraud conviction settlement.
    pub fn record_fraud_conviction(
        &self,
        job_id: String,
        fee_sat: u64,
        worker_stake_sat: u64,
        challenge_deposit_sat: u64,
    ) -> Result<SettlementRecord> {
        let worker_slash = self.calculate_worker_slash(worker_stake_sat);
        let verifier_reward = self.calculate_verifier_fraud_reward(fee_sat, challenge_deposit_sat);
        let protocol_fee = self.calculate_protocol_fee(fee_sat);

        let settlement = SettlementRecord {
            job_id: job_id.clone(),
            worker_reward_sat: 0, // Fraudster gets nothing
            verifier_reward_sat: verifier_reward,
            protocol_fee_sat: protocol_fee,
            slash_sat: worker_slash,
            settled_at: current_ts(),
            outcome: SettlementOutcome::FraudConvicted,
        };

        self.save(&settlement)?;
        Ok(settlement)
    }

    /// Record false accusation settlement.
    pub fn record_false_accusation(
        &self,
        job_id: String,
        fee_sat: u64,
        challenge_deposit_sat: u64,
        worker_reputation: f64,
    ) -> Result<SettlementRecord> {
        let verifier_slash = self.calculate_false_accuse_slash(challenge_deposit_sat);
        let worker_reward = self.calculate_worker_reward(fee_sat, worker_reputation);
        let worker_bonus = verifier_slash; // Slashed amount goes to worker as compensation
        let protocol_fee = self.calculate_protocol_fee(fee_sat);

        let settlement = SettlementRecord {
            job_id: job_id.clone(),
            worker_reward_sat: worker_reward.saturating_add(worker_bonus),
            verifier_reward_sat: 0, // Accuser gets nothing
            protocol_fee_sat: protocol_fee,
            slash_sat: verifier_slash,
            settled_at: current_ts(),
            outcome: SettlementOutcome::FalseAccusation,
        };

        self.save(&settlement)?;
        Ok(settlement)
    }

    /// Record job cancellation (fee partially returned).
    pub fn record_cancelled(&self, job_id: String) -> Result<SettlementRecord> {
        let settlement = SettlementRecord {
            job_id: job_id.clone(),
            worker_reward_sat: 0,
            verifier_reward_sat: 0,
            protocol_fee_sat: 0,
            slash_sat: 0,
            settled_at: current_ts(),
            outcome: SettlementOutcome::Cancelled,
        };

        self.save(&settlement)?;
        Ok(settlement)
    }

    /// Record job expiration (deadline missed, partial refund).
    pub fn record_expired(&self, job_id: String) -> Result<SettlementRecord> {
        let settlement = SettlementRecord {
            job_id: job_id.clone(),
            worker_reward_sat: 0,
            verifier_reward_sat: 0,
            protocol_fee_sat: 0,
            slash_sat: 0,
            settled_at: current_ts(),
            outcome: SettlementOutcome::Expired,
        };

        self.save(&settlement)?;
        Ok(settlement)
    }

    /// Retrieve a settlement record by job ID.
    pub fn get(&self, job_id: &str) -> Result<Option<SettlementRecord>> {
        match self.partition.get(job_id).map_err(|e| ComputeError::Storage(e.to_string()))? {
            Some(v) => {
                let (settlement, _) = bincode::serde::decode_from_slice::<SettlementRecord, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| ComputeError::Serialization(e.to_string()))?;
                Ok(Some(settlement))
            }
            None => Ok(None),
        }
    }

    /// List recent settlements, newest-first.
    pub fn list_recent(&self, limit: usize) -> Result<Vec<SettlementRecord>> {
        let mut settlements = Vec::new();
        for kv in self.partition.iter() {
            let (_, v) = kv.map_err(|e| ComputeError::Storage(e.to_string()))?;
            if let Ok((settlement, _)) = bincode::serde::decode_from_slice::<SettlementRecord, _>(
                &v,
                bincode::config::standard(),
            ) {
                settlements.push(settlement);
            }
        }

        settlements.sort_by(|a, b| b.settled_at.cmp(&a.settled_at));
        settlements.truncate(limit);
        Ok(settlements)
    }

    // ── Internal Helpers ──────────────────────────────────────────────

    fn save(&self, settlement: &SettlementRecord) -> Result<()> {
        let value = bincode::serde::encode_to_vec(settlement, bincode::config::standard())
            .map_err(|e| ComputeError::Serialization(e.to_string()))?;
        self.partition
            .insert(&settlement.job_id, value)
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

    fn open_engine() -> (TempDir, SettlementEngine) {
        let tmp = TempDir::new().unwrap();
        let engine = SettlementEngine::open(tmp.path()).unwrap();
        (tmp, engine)
    }

    #[test]
    fn test_worker_reward_base() {
        let (_tmp, engine) = open_engine();
        // 1000 sat fee, 0.9 reputation
        let reward = engine.calculate_worker_reward(1000, 0.9);
        // 80% = 800 sat, 0.9 rep gives 5% bonus = 840 sat
        assert_eq!(reward, 840);
    }

    #[test]
    fn test_verifier_sample_reward() {
        let (_tmp, engine) = open_engine();
        let reward = engine.calculate_verifier_sample_reward(1000);
        // 5% = 50 sat
        assert_eq!(reward, 50);
    }

    #[test]
    fn test_challenge_deposit() {
        let (_tmp, engine) = open_engine();
        let deposit = engine.calculate_challenge_deposit(1000);
        // 10% = 100 sat
        assert_eq!(deposit, 100);
    }

    #[test]
    fn test_worker_slash() {
        let (_tmp, engine) = open_engine();
        let slash = engine.calculate_worker_slash(10_000);
        // 20% = 2000 sat
        assert_eq!(slash, 2000);
    }

    #[test]
    fn test_protocol_fee() {
        let (_tmp, engine) = open_engine();
        let fee = engine.calculate_protocol_fee(1000);
        // 5% = 50 sat
        assert_eq!(fee, 50);
    }

    #[test]
    fn test_record_success() {
        let (_tmp, engine) = open_engine();
        let settlement = engine.record_success("job_1".into(), 1000, 0.95).unwrap();

        assert_eq!(settlement.job_id, "job_1");
        assert!(settlement.worker_reward_sat > 0);
        assert_eq!(settlement.outcome, SettlementOutcome::Success);
    }

    #[test]
    fn test_record_fraud() {
        let (_tmp, engine) = open_engine();
        let settlement =
            engine.record_fraud_conviction("job_1".into(), 1000, 10_000, 100).unwrap();

        assert_eq!(settlement.job_id, "job_1");
        assert_eq!(settlement.worker_reward_sat, 0); // Fraudster gets 0
        assert!(settlement.verifier_reward_sat > 0); // Verifier gets 15% + deposit
        assert_eq!(settlement.outcome, SettlementOutcome::FraudConvicted);
    }

    #[test]
    fn test_get_settlement() {
        let (_tmp, engine) = open_engine();
        engine.record_success("job_1".into(), 1000, 1.0).unwrap();

        let fetched = engine.get("job_1").unwrap().unwrap();
        assert_eq!(fetched.job_id, "job_1");
    }

    #[test]
    fn test_list_recent() {
        let (_tmp, engine) = open_engine();
        engine.record_success("job_1".into(), 1000, 1.0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100)); // Ensure different timestamps
        engine.record_success("job_2".into(), 2000, 0.9).unwrap();

        let settlements = engine.list_recent(10).unwrap();
        assert_eq!(settlements.len(), 2);
        // Verify both jobs are present
        let job_ids: Vec<_> = settlements.iter().map(|s| s.job_id.as_str()).collect();
        assert!(job_ids.contains(&"job_1"));
        assert!(job_ids.contains(&"job_2"));
    }
}
