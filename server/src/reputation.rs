//! User reputation tracking and decay system

use crate::db::Database;
use tracing::info;

/// Reputation events and their point values
pub struct ReputationConfig {
    pub job_completed: i64,
    pub job_failed: i64,
    pub dispute_won: i64,
    pub dispute_lost: i64,
    pub verified_work: i64,
    pub spam_warning: i64,
    pub ban_lifted: i64,
    pub monthly_decay_percent: i64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        ReputationConfig {
            job_completed: 10,
            job_failed: -5,
            dispute_won: 15,
            dispute_lost: -10,
            verified_work: 5,
            spam_warning: -3,
            ban_lifted: 2,
            monthly_decay_percent: 5,
        }
    }
}

/// Award reputation points for an event
pub async fn award_reputation(
    db: &Database,
    address: &str,
    points: i64,
    reason: &str,
) -> anyhow::Result<()> {
    info!(
        "Awarding {} reputation points to {} for: {}",
        points, address, reason
    );

    db.update_user_reputation(address, points).await?;
    Ok(())
}

/// Apply monthly reputation decay
pub async fn apply_monthly_decay(
    db: &Database,
    decay_percentage: i64,
) -> anyhow::Result<u64> {
    info!(
        "Applying {}% monthly reputation decay to all users",
        decay_percentage
    );

    let affected = db.apply_reputation_decay(decay_percentage).await?;
    info!("Applied decay to {} users", affected);

    Ok(affected)
}

/// Get reputation level description
pub fn get_reputation_level(score: i64) -> &'static str {
    match score {
        0..=10 => "Newcomer",
        11..=50 => "Contributor",
        51..=100 => "Trusted",
        101..=200 => "Expert",
        201..=500 => "Veteran",
        _ => "Legendary",
    }
}

/// Calculate reputation multiplier for bonuses
pub fn get_reputation_multiplier(score: i64) -> f64 {
    match score {
        0..=50 => 1.0,
        51..=100 => 1.1,
        101..=200 => 1.2,
        201..=500 => 1.3,
        _ => 1.5,
    }
}

/// Determine if user should be deactivated (low reputation)
pub fn should_deactivate(score: i64) -> bool {
    score < -50
}
