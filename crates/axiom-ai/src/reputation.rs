// Copyright (c) 2026 Kantoshi Miyamura

//! Model reputation registry and provider stake — Phase AI-3.
//!
//! ## Reputation
//!
//! After a job completes, the requester can rate it on a 1–5 scale.
//! Ratings accumulate per model hash.  The aggregate reputation score is:
//!
//!   `score = (avg_rating × successful_completions) / (total_completions + 1)`
//!
//! …giving higher scores to models with both quality ratings and volume.
//! A model with zero ratings has score 0.
//!
//! ## Provider Stake
//!
//! Providers may stake AXM satoshis as a trust signal.  Higher stake raises
//! the provider's weight in ranked listings.  Stake is additive — subsequent
//! `stake` calls add to the existing balance.
//!
//! Both tables live in the same fjall keyspace at `<data_dir>/ai_reputation/`.

use crate::types::ReputationScore;
use fjall::{Config, PartitionCreateOptions};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Types stored in this module ───────────────────────────────────────────────

/// Accumulated rating data stored for each model hash.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RatingAccumulator {
    /// Total number of ratings submitted.
    pub count: u64,
    /// Sum of all ratings (1–5 each).
    pub sum: u64,
    /// Number of completed jobs for this model.
    pub completions: u64,
}

/// Provider stake record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStake {
    /// Axiom address of the provider.
    pub provider: String,
    /// Total AXM satoshis staked.
    pub staked_sat: u64,
    /// Unix timestamp of the most recent stake operation.
    pub last_updated: u64,
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    #[error("storage error: {0}")]
    Storage(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("rating out of range — must be 1–5, got {0}")]
    InvalidRating(u8),

    #[error("address {0} has already rated model {1}")]
    DuplicateRating(String, String),
}

pub type Result<T> = std::result::Result<T, ReputationError>;

// ── Registry ──────────────────────────────────────────────────────────────────

/// Thread-safe reputation and stake registry at `<data_dir>/ai_reputation/`.
pub struct ReputationRegistry {
    _keyspace: fjall::Keyspace,
    /// Partition storing `RatingAccumulator` keyed by model_hash.
    ratings: fjall::PartitionHandle,
    /// Partition storing `ProviderStake` keyed by provider address.
    stakes: fjall::PartitionHandle,
    /// Partition storing per-rater deduplication keys: "{rater_address}:{model_hash}" → 1.
    /// Prevents Sybil reputation inflation via repeated self-ratings.
    raters: fjall::PartitionHandle,
}

impl ReputationRegistry {
    /// Open (or create) the registry.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let path = data_dir.as_ref().join("ai_reputation");
        let keyspace = Config::new(path).open()?;
        let ratings = keyspace.open_partition("ratings", PartitionCreateOptions::default())?;
        let stakes = keyspace.open_partition("stakes", PartitionCreateOptions::default())?;
        let raters = keyspace.open_partition("raters", PartitionCreateOptions::default())?;
        Ok(ReputationRegistry {
            _keyspace: keyspace,
            ratings,
            stakes,
            raters,
        })
    }

    // ── Rating operations ────────────────────────────────────────────────────

    /// Submit a rating (1–5) for a model.
    ///
    /// Each `rater_address` may rate a given model at most once. Passing an
    /// empty string bypasses the deduplication check (legacy/anonymous).
    ///
    /// SECURITY: Without deduplication an attacker can self-rate their own model
    /// thousands of times, reaching rank #1 with no legitimate users.
    pub fn rate_model(
        &self,
        model_hash: &str,
        rating: u8,
        rater_address: &str,
    ) -> Result<ReputationScore> {
        if !(1..=5).contains(&rating) {
            return Err(ReputationError::InvalidRating(rating));
        }

        // Deduplicate: each address may rate a model at most once.
        if !rater_address.is_empty() {
            let dedup_key = format!("{}:{}", rater_address, model_hash);
            if self.raters.get(dedup_key.as_bytes())?.is_some() {
                return Err(ReputationError::DuplicateRating(
                    rater_address.to_string(),
                    model_hash.to_string(),
                ));
            }
            self.raters.insert(dedup_key.as_bytes(), b"1")?;
        }

        let mut acc = self.load_accumulator(model_hash)?;
        acc.count += 1;
        acc.sum += rating as u64;

        self.save_accumulator(model_hash, &acc)?;
        Ok(compute_score(model_hash, &acc))
    }

    /// Record a job completion for a model (increments the completion count).
    ///
    /// Called internally when a job transitions to `Completed`.
    pub fn record_completion(&self, model_hash: &str) -> Result<()> {
        let mut acc = self.load_accumulator(model_hash)?;
        acc.completions += 1;
        self.save_accumulator(model_hash, &acc)
    }

    /// Get the current reputation score for a model.
    pub fn get_score(&self, model_hash: &str) -> Result<ReputationScore> {
        let acc = self.load_accumulator(model_hash)?;
        Ok(compute_score(model_hash, &acc))
    }

    /// Return up to `limit` models sorted by reputation score descending.
    pub fn ranked_models(&self, limit: usize) -> Result<Vec<ReputationScore>> {
        let mut scores = Vec::new();

        for kv in self.ratings.iter() {
            let (k, v) = kv?;
            let model_hash = String::from_utf8_lossy(&k).into_owned();
            if let Ok((acc, _)) = bincode::serde::decode_from_slice::<RatingAccumulator, _>(
                &v,
                bincode::config::standard(),
            ) {
                scores.push(compute_score(&model_hash, &acc));
            }
        }

        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scores.truncate(limit);
        Ok(scores)
    }

    // ── Stake operations ─────────────────────────────────────────────────────

    /// Add `amount_sat` to a provider's stake.  Creates the record if absent.
    pub fn add_stake(&self, provider: &str, amount_sat: u64) -> Result<ProviderStake> {
        let mut stake = self.load_stake(provider)?.unwrap_or(ProviderStake {
            provider: provider.to_string(),
            staked_sat: 0,
            last_updated: 0,
        });

        stake.staked_sat = stake.staked_sat.saturating_add(amount_sat);
        stake.last_updated = now_secs();

        let value = bincode::serde::encode_to_vec(&stake, bincode::config::standard())
            .map_err(|e| ReputationError::Serialization(e.to_string()))?;
        self.stakes.insert(provider, value)?;

        Ok(stake)
    }

    /// Get a provider's current stake (returns zero-stake record if not found).
    pub fn get_stake(&self, provider: &str) -> Result<ProviderStake> {
        Ok(self.load_stake(provider)?.unwrap_or(ProviderStake {
            provider: provider.to_string(),
            staked_sat: 0,
            last_updated: 0,
        }))
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn load_accumulator(&self, model_hash: &str) -> Result<RatingAccumulator> {
        match self.ratings.get(model_hash)? {
            Some(v) => bincode::serde::decode_from_slice::<RatingAccumulator, _>(
                &v,
                bincode::config::standard(),
            )
            .map(|(a, _)| a)
            .map_err(|e| ReputationError::Serialization(e.to_string())),
            None => Ok(RatingAccumulator::default()),
        }
    }

    fn save_accumulator(&self, model_hash: &str, acc: &RatingAccumulator) -> Result<()> {
        let value = bincode::serde::encode_to_vec(acc, bincode::config::standard())
            .map_err(|e| ReputationError::Serialization(e.to_string()))?;
        self.ratings.insert(model_hash, value)?;
        Ok(())
    }

    fn load_stake(&self, provider: &str) -> Result<Option<ProviderStake>> {
        match self.stakes.get(provider)? {
            Some(v) => bincode::serde::decode_from_slice::<ProviderStake, _>(
                &v,
                bincode::config::standard(),
            )
            .map(|(s, _)| Some(s))
            .map_err(|e| ReputationError::Serialization(e.to_string())),
            None => Ok(None),
        }
    }
}

// ── Score formula ─────────────────────────────────────────────────────────────

fn compute_score(model_hash: &str, acc: &RatingAccumulator) -> ReputationScore {
    let avg_rating = if acc.count > 0 {
        acc.sum as f64 / acc.count as f64
    } else {
        0.0
    };

    // score = avg_rating × completions / (completions + 1)
    // Approaches avg_rating as completions → ∞; stays near 0 for untested models.
    let score = avg_rating * acc.completions as f64 / (acc.completions as f64 + 1.0);

    ReputationScore {
        model_hash: model_hash.to_string(),
        total_ratings: acc.count,
        avg_rating,
        completions: acc.completions,
        score,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const MODEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROVIDER: &str = "axm_provider_address";

    fn open_registry() -> (TempDir, ReputationRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = ReputationRegistry::open(tmp.path()).unwrap();
        (tmp, reg)
    }

    // ── Reputation ────────────────────────────────────────────────────────────

    #[test]
    fn test_get_score_no_data_returns_zeros() {
        let (_tmp, reg) = open_registry();
        let score = reg.get_score(MODEL).unwrap();
        assert_eq!(score.total_ratings, 0);
        assert_eq!(score.completions, 0);
        assert_eq!(score.score, 0.0);
    }

    #[test]
    fn test_rate_model_updates_score() {
        let (_tmp, reg) = open_registry();
        reg.record_completion(MODEL).unwrap(); // 1 completion
        let score = reg.rate_model(MODEL, 5, "").unwrap();

        assert_eq!(score.total_ratings, 1);
        assert_eq!(score.avg_rating, 5.0);
        assert!(score.score > 0.0);
    }

    #[test]
    fn test_rating_out_of_range_rejected() {
        let (_tmp, reg) = open_registry();
        assert!(matches!(
            reg.rate_model(MODEL, 0, ""),
            Err(ReputationError::InvalidRating(0))
        ));
        assert!(matches!(
            reg.rate_model(MODEL, 6, ""),
            Err(ReputationError::InvalidRating(6))
        ));
    }

    #[test]
    fn test_avg_rating_averages_correctly() {
        let (_tmp, reg) = open_registry();
        reg.rate_model(MODEL, 4, "").unwrap();
        reg.rate_model(MODEL, 2, "").unwrap();
        let score = reg.get_score(MODEL).unwrap();
        assert_eq!(score.total_ratings, 2);
        assert!((score.avg_rating - 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_score_increases_with_completions() {
        let (_tmp, reg) = open_registry();
        reg.rate_model(MODEL, 5, "").unwrap();

        reg.record_completion(MODEL).unwrap();
        let score1 = reg.get_score(MODEL).unwrap().score;

        reg.record_completion(MODEL).unwrap();
        let score2 = reg.get_score(MODEL).unwrap().score;

        assert!(score2 > score1, "more completions should increase score");
    }

    #[test]
    fn test_ranked_models_sorted_desc() {
        let (_tmp, reg) = open_registry();
        let hash_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let hash_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        // MODEL: high rating, many completions
        reg.record_completion(MODEL).unwrap();
        reg.record_completion(MODEL).unwrap();
        reg.rate_model(MODEL, 5, "").unwrap();
        reg.rate_model(MODEL, 5, "").unwrap();

        // hash_b: medium rating
        reg.record_completion(hash_b).unwrap();
        reg.rate_model(hash_b, 3, "").unwrap();

        // hash_c: no ratings
        reg.record_completion(hash_c).unwrap();

        let ranked = reg.ranked_models(10).unwrap();
        assert_eq!(ranked.len(), 3);
        assert!(ranked[0].score >= ranked[1].score);
        assert!(ranked[1].score >= ranked[2].score);
    }

    #[test]
    fn test_ranked_models_empty() {
        let (_tmp, reg) = open_registry();
        let ranked = reg.ranked_models(10).unwrap();
        assert!(ranked.is_empty());
    }

    // ── Stake ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_stake_missing_returns_zero() {
        let (_tmp, reg) = open_registry();
        let stake = reg.get_stake(PROVIDER).unwrap();
        assert_eq!(stake.staked_sat, 0);
        assert_eq!(stake.provider, PROVIDER);
    }

    #[test]
    fn test_add_stake_accumulates() {
        let (_tmp, reg) = open_registry();
        reg.add_stake(PROVIDER, 1_000).unwrap();
        reg.add_stake(PROVIDER, 2_000).unwrap();
        let stake = reg.get_stake(PROVIDER).unwrap();
        assert_eq!(stake.staked_sat, 3_000);
    }

    #[test]
    fn test_stake_persists_across_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let reg = ReputationRegistry::open(tmp.path()).unwrap();
            reg.add_stake(PROVIDER, 5_000).unwrap();
        }
        let reg2 = ReputationRegistry::open(tmp.path()).unwrap();
        assert_eq!(reg2.get_stake(PROVIDER).unwrap().staked_sat, 5_000);
    }

    #[test]
    fn test_stake_saturates_on_overflow() {
        let (_tmp, reg) = open_registry();
        reg.add_stake(PROVIDER, u64::MAX).unwrap();
        let stake = reg.add_stake(PROVIDER, 1).unwrap(); // would overflow
        assert_eq!(stake.staked_sat, u64::MAX); // saturating_add
    }
}
