//! Database connection and management

use crate::config::Config;
use sqlx::postgres::PgPool;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

/// Database connection pool and operations
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create new database connection pool
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&config.database_url)
            .await?;

        Ok(Database { pool })
    }

    /// Run database migrations from server/migrations/ directory.
    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        info!("Database migrations applied successfully");
        Ok(())
    }

    /// Get connection pool reference
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Health check - verify database connectivity
    pub async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }

    /// Get user by address
    pub async fn get_user(&self, address: &str) -> anyhow::Result<Option<UserRow>> {
        let user = sqlx::query_as::<_, UserRow>(
            "SELECT address, reputation_score, roles, is_banned, created_at, updated_at FROM users WHERE address = $1"
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Create new user session
    #[allow(clippy::too_many_arguments)]
    pub async fn create_session(
        &self,
        session_id: &str,
        address: &str,
        token_hash: &str,
        refresh_token_hash: &str,
        expires_at: i64,
        ip_address: &str,
        user_agent: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO sessions (id, address, token_hash, refresh_token_hash, created_at, expires_at, ip_address, user_agent, last_activity)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind(session_id)
        .bind(address)
        .bind(token_hash)
        .bind(refresh_token_hash)
        .bind(chrono::Utc::now().timestamp())
        .bind(expires_at)
        .bind(ip_address)
        .bind(user_agent)
        .bind(chrono::Utc::now().timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<SessionRow>> {
        let session = sqlx::query_as::<_, SessionRow>(
            "SELECT id, address, token_hash, refresh_token_hash, created_at, expires_at, ip_address, user_agent, revoked, revoked_at FROM sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE sessions SET revoked = true, revoked_at = $1 WHERE id = $2")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Log audit event
    pub async fn log_audit(
        &self,
        address: Option<&str>,
        action: &str,
        status: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO audit_logs (timestamp, address, action, status, ip_address, user_agent, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(now)
        .bind(address)
        .bind(action)
        .bind(status)
        .bind(ip_address)
        .bind(user_agent)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Create new message
    #[allow(clippy::too_many_arguments)]
    pub async fn create_message(
        &self,
        id: &str,
        channel: &str,
        author: &str,
        content: &str,
        content_hash: &str,
        parent_id: Option<&str>,
        timestamp: i64,
        signature: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO messages (id, channel, author, content, content_hash, parent_id, timestamp, signature, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        )
        .bind(id)
        .bind(channel)
        .bind(author)
        .bind(content)
        .bind(content_hash)
        .bind(parent_id)
        .bind(timestamp)
        .bind(signature)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get messages in channel
    pub async fn list_messages(
        &self,
        channel: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<MessageRow>> {
        let messages = sqlx::query_as::<_, MessageRow>(
            "SELECT * FROM messages WHERE channel = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3",
        )
        .bind(channel)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(messages)
    }

    /// Get single message by ID
    pub async fn get_message(&self, id: &str) -> anyhow::Result<Option<MessageRow>> {
        let message = sqlx::query_as::<_, MessageRow>("SELECT * FROM messages WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(message)
    }

    /// Create new job
    #[allow(clippy::too_many_arguments)]
    pub async fn create_job(
        &self,
        id: &str,
        channel: &str,
        requester: &str,
        title: &str,
        description: &str,
        reward_sat: i64,
        deadline: i64,
        max_workers: i32,
        work_type: &str,
        requirements: Vec<String>,
        timestamp: i64,
        signature: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO jobs (id, channel, requester, title, description, reward_sat, deadline, max_workers, work_type, requirements, timestamp, signature, state, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
        )
        .bind(id)
        .bind(channel)
        .bind(requester)
        .bind(title)
        .bind(description)
        .bind(reward_sat)
        .bind(deadline)
        .bind(max_workers)
        .bind(work_type)
        .bind(requirements)
        .bind(timestamp)
        .bind(signature)
        .bind("open")
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get jobs in a channel with optional filtering
    pub async fn list_jobs(
        &self,
        channel: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<JobRow>> {
        let jobs = sqlx::query_as::<_, JobRow>(
            "SELECT * FROM jobs WHERE channel = $1 ORDER BY deadline ASC LIMIT $2 OFFSET $3",
        )
        .bind(channel)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(jobs)
    }

    /// Get single job by ID
    pub async fn get_job(&self, id: &str) -> anyhow::Result<Option<JobRow>> {
        let job = sqlx::query_as::<_, JobRow>("SELECT * FROM jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(job)
    }

    /// Update job state
    pub async fn update_job_state(&self, id: &str, new_state: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE jobs SET state = $1, updated_at = $2 WHERE id = $3")
            .bind(new_state)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Create work submission
    #[allow(clippy::too_many_arguments)]
    pub async fn create_work_submission(
        &self,
        id: &str,
        job_id: &str,
        worker: &str,
        submission_data: &str,
        data_hash: &str,
        timestamp: i64,
        signature: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO work_submissions (id, job_id, worker, submission_data, data_hash, timestamp, signature, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        )
        .bind(id)
        .bind(job_id)
        .bind(worker)
        .bind(submission_data)
        .bind(data_hash)
        .bind(timestamp)
        .bind(signature)
        .bind("pending_review")
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get single work submission
    pub async fn get_work_submission(&self, id: &str) -> anyhow::Result<Option<WorkSubmissionRow>> {
        let submission =
            sqlx::query_as::<_, WorkSubmissionRow>("SELECT * FROM work_submissions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(submission)
    }

    /// Get submissions for a job
    pub async fn list_work_submissions(
        &self,
        job_id: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<WorkSubmissionRow>> {
        let submissions = sqlx::query_as::<_, WorkSubmissionRow>(
            "SELECT * FROM work_submissions WHERE job_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(job_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(submissions)
    }

    /// Create new dispute
    #[allow(clippy::too_many_arguments)]
    pub async fn create_dispute(
        &self,
        id: &str,
        job_id: &str,
        work_id: &str,
        initiator: &str,
        reason: &str,
        evidence: &str,
        evidence_hash: &str,
        timestamp: i64,
        signature: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO disputes (id, job_id, work_id, initiator, reason, evidence, evidence_hash, timestamp, signature, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .bind(id)
        .bind(job_id)
        .bind(work_id)
        .bind(initiator)
        .bind(reason)
        .bind(evidence)
        .bind(evidence_hash)
        .bind(timestamp)
        .bind(signature)
        .bind("open")
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List disputes
    pub async fn list_disputes(&self, limit: i64, offset: i64) -> anyhow::Result<Vec<DisputeRow>> {
        let disputes = sqlx::query_as::<_, DisputeRow>(
            "SELECT * FROM disputes ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(disputes)
    }

    /// Get single dispute
    pub async fn get_dispute(&self, id: &str) -> anyhow::Result<Option<DisputeRow>> {
        let dispute = sqlx::query_as::<_, DisputeRow>("SELECT * FROM disputes WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(dispute)
    }

    /// Update dispute status
    pub async fn update_dispute_status(&self, id: &str, new_status: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE disputes SET status = $1, updated_at = $2 WHERE id = $3")
            .bind(new_status)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Create moderation action
    #[allow(clippy::too_many_arguments)]
    pub async fn create_moderation_action(
        &self,
        id: &str,
        action: &str,
        target: &str,
        target_type: &str,
        reason: &str,
        duration_secs: Option<i64>,
        moderator: &str,
        timestamp: i64,
        signature: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let expires_at = duration_secs.map(|d| now + d);

        sqlx::query(
            "INSERT INTO moderation_actions (id, action, target, target_type, reason, duration_secs, expires_at, moderator, timestamp, signature, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
        )
        .bind(id)
        .bind(action)
        .bind(target)
        .bind(target_type)
        .bind(reason)
        .bind(duration_secs)
        .bind(expires_at)
        .bind(moderator)
        .bind(timestamp)
        .bind(signature)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List moderation actions
    pub async fn list_moderation_actions(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<ModerationActionRow>> {
        let actions = sqlx::query_as::<_, ModerationActionRow>(
            "SELECT * FROM moderation_actions ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(actions)
    }

    /// Get moderation action by ID
    pub async fn get_moderation_action(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<ModerationActionRow>> {
        let action = sqlx::query_as::<_, ModerationActionRow>(
            "SELECT * FROM moderation_actions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(action)
    }

    /// List audit logs
    pub async fn list_audit_logs(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<AuditLogRow>> {
        let logs = sqlx::query_as::<_, AuditLogRow>(
            "SELECT timestamp, address, action, status, ip_address, created_at FROM audit_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    /// Update user roles
    pub async fn update_user_roles(&self, address: &str, roles: Vec<String>) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE users SET roles = $1, updated_at = $2 WHERE address = $3")
            .bind(roles)
            .bind(now)
            .bind(address)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Ban user
    pub async fn ban_user(&self, address: &str, reason: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE users SET is_banned = true, ban_reason = $1, updated_at = $2 WHERE address = $3"
        )
        .bind(reason)
        .bind(now)
        .bind(address)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Unban user
    pub async fn unban_user(&self, address: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE users SET is_banned = false, ban_reason = NULL, updated_at = $1 WHERE address = $2"
        )
        .bind(now)
        .bind(address)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Create or register new user
    pub async fn create_or_get_user(&self, address: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users (address, reputation_score, roles, is_banned, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (address) DO NOTHING"
        )
        .bind(address)
        .bind(0i64)
        .bind(vec!["member".to_string()])
        .bind(false)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store public key for an address (binds key on first auth)
    pub async fn store_public_key(
        &self,
        address: &str,
        public_key_hex: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET public_key_hex = $1, updated_at = $2 WHERE address = $3")
            .bind(public_key_hex)
            .bind(chrono::Utc::now().timestamp())
            .bind(address)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get stored public key for an address
    pub async fn get_public_key(&self, address: &str) -> anyhow::Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT public_key_hex FROM users WHERE address = $1")
                .bind(address)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.and_then(|r| r.0))
    }

    /// Get session by refresh token hash (for token refresh)
    pub async fn get_session_by_refresh_token_hash(
        &self,
        hash: &str,
    ) -> anyhow::Result<Option<SessionRow>> {
        let session = sqlx::query_as::<_, SessionRow>(
            "SELECT id, address, token_hash, refresh_token_hash, created_at, expires_at, ip_address, user_agent, revoked, revoked_at FROM sessions WHERE refresh_token_hash = $1"
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    /// Rotate refresh token for a session
    pub async fn rotate_refresh_token(
        &self,
        session_id: &str,
        new_refresh_hash: &str,
        new_token_hash: &str,
        new_expires_at: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE sessions SET refresh_token_hash = $1, token_hash = $2, expires_at = $3, last_activity = $4 WHERE id = $5"
        )
        .bind(new_refresh_hash)
        .bind(new_token_hash)
        .bind(new_expires_at)
        .bind(chrono::Utc::now().timestamp())
        .bind(session_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update user reputation
    pub async fn update_user_reputation(&self, address: &str, delta: i64) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE users SET reputation_score = reputation_score + $1, updated_at = $2 WHERE address = $3"
        )
        .bind(delta)
        .bind(now)
        .bind(address)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Apply reputation decay to all users
    /// Reduces reputation by percentage based on days since last update
    pub async fn apply_reputation_decay(&self, decay_percentage: i64) -> anyhow::Result<u64> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE users SET reputation_score = (reputation_score * (100 - $1)) / 100, updated_at = $2 WHERE reputation_score > 0"
        )
        .bind(decay_percentage)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get users with low reputation (potential deactivation)
    pub async fn get_low_reputation_users(
        &self,
        min_reputation: i64,
    ) -> anyhow::Result<Vec<UserRow>> {
        let users = sqlx::query_as::<_, UserRow>(
            "SELECT * FROM users WHERE reputation_score < $1 AND is_banned = FALSE",
        )
        .bind(min_reputation)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    // ── Challenge persistence ────────────────────────────────────────────

    /// Store a challenge in the database.
    pub async fn store_challenge(
        &self,
        nonce: &str,
        challenge_hash: &str,
        address: &str,
        user_agent: &str,
        created_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO challenges (nonce, challenge_hash, address, user_agent, created_at, expires_at, used)
             VALUES ($1, $2, $3, $4, $5, $6, FALSE)
             ON CONFLICT (nonce) DO NOTHING"
        )
        .bind(nonce)
        .bind(challenge_hash)
        .bind(address)
        .bind(user_agent)
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a challenge by nonce and mark it as used atomically.
    /// Returns None if the nonce doesn't exist, is expired, or was already used.
    pub async fn consume_challenge(&self, nonce: &str) -> anyhow::Result<Option<ChallengeRow>> {
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query_as::<_, ChallengeRow>(
            "UPDATE challenges
             SET used = TRUE, used_at = $1
             WHERE nonce = $2 AND used = FALSE AND expires_at > $3
             RETURNING nonce, challenge_hash, address, user_agent, created_at, expires_at, used, used_at"
        )
        .bind(now)
        .bind(nonce)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Remove expired challenges from the database.
    pub async fn cleanup_expired_challenges(&self) -> anyhow::Result<u64> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query("DELETE FROM challenges WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    // ── Distributed security: IP bans ───────────────────────────────────

    /// Check if an IP is banned (shared across all instances).
    pub async fn is_ip_banned(&self, ip: &str) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT expires_at FROM ip_bans WHERE ip_address = $1::INET
             AND (expires_at = 0 OR expires_at > $2)",
        )
        .bind(ip)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    /// Ban an IP address (upsert — updates expiry if already banned).
    pub async fn ban_ip(
        &self,
        ip: &str,
        reason: &str,
        expires_at: i64,
        created_by: Option<&str>,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO ip_bans (ip_address, reason, expires_at, created_at, created_by)
             VALUES ($1::INET, $2, $3, $4, $5)
             ON CONFLICT (ip_address) DO UPDATE SET
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at,
                created_at = EXCLUDED.created_at,
                created_by = EXCLUDED.created_by",
        )
        .bind(ip)
        .bind(reason)
        .bind(expires_at)
        .bind(now)
        .bind(created_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Unban an IP address.
    pub async fn unban_ip(&self, ip: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM ip_bans WHERE ip_address = $1::INET")
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record an auth failure and return the new count. Atomically increments
    /// across instances using INSERT ... ON CONFLICT UPDATE.
    pub async fn record_auth_failure(&self, ip: &str, window_secs: i64) -> anyhow::Result<i32> {
        let now = chrono::Utc::now().timestamp();
        let window_start_cutoff = now - window_secs;

        // Atomically upsert: insert new or increment existing (reset if window expired)
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO auth_failure_counters (ip_address, failure_count, window_start, updated_at)
             VALUES ($1::INET, 1, $2, $2)
             ON CONFLICT (ip_address) DO UPDATE SET
                failure_count = CASE
                    WHEN auth_failure_counters.window_start < $3 THEN 1
                    ELSE auth_failure_counters.failure_count + 1
                END,
                window_start = CASE
                    WHEN auth_failure_counters.window_start < $3 THEN $2
                    ELSE auth_failure_counters.window_start
                END,
                updated_at = $2
             RETURNING failure_count"
        )
        .bind(ip)
        .bind(now)
        .bind(window_start_cutoff)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    /// Reset auth failure counter for an IP (on successful auth).
    pub async fn reset_auth_failures(&self, ip: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM auth_failure_counters WHERE ip_address = $1::INET")
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clean up expired IP bans and stale auth failure counters.
    pub async fn cleanup_ip_security(&self) -> anyhow::Result<(u64, u64)> {
        let now = chrono::Utc::now().timestamp();

        let bans = sqlx::query("DELETE FROM ip_bans WHERE expires_at > 0 AND expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();

        let stale_window = now - 600; // 10 minutes
        let counters = sqlx::query("DELETE FROM auth_failure_counters WHERE window_start < $1")
            .bind(stale_window)
            .execute(&self.pool)
            .await?
            .rows_affected();

        Ok((bans, counters))
    }

    // ── Distributed security: signature replay protection ───────────────

    /// Check if a signature has been used and record it atomically.
    /// Returns `true` if this is the first use (allowed), `false` if replay.
    pub async fn check_and_record_signature(
        &self,
        sig_prefix: &str,
        address: &str,
        action: &str,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();

        // INSERT fails silently on conflict (signature already used)
        let result = sqlx::query(
            "INSERT INTO used_signatures (sig_prefix, address, action, used_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (sig_prefix) DO NOTHING",
        )
        .bind(sig_prefix)
        .bind(address)
        .bind(action)
        .bind(now)
        .execute(&self.pool)
        .await?;

        // rows_affected = 1 means insert succeeded (first use)
        // rows_affected = 0 means conflict (replay)
        Ok(result.rows_affected() > 0)
    }

    /// Remove signatures older than the retention window.
    pub async fn cleanup_used_signatures(&self, retention_secs: i64) -> anyhow::Result<u64> {
        let cutoff = chrono::Utc::now().timestamp() - retention_secs;
        let result = sqlx::query("DELETE FROM used_signatures WHERE used_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ── Distributed security: rate limiting ─────────────────────────────

    /// Atomically increment a rate limit counter and return the new count.
    /// Resets the counter if the window has expired.
    pub async fn check_rate_limit(
        &self,
        key: &str,
        max_count: i32,
        window_secs: i32,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let window_start_cutoff = now - window_secs as i64;

        let row: (i32,) = sqlx::query_as(
            "INSERT INTO rate_limit_counters (key, counter, window_start, window_secs)
             VALUES ($1, 1, $2, $3)
             ON CONFLICT (key) DO UPDATE SET
                counter = CASE
                    WHEN rate_limit_counters.window_start < $4 THEN 1
                    ELSE rate_limit_counters.counter + 1
                END,
                window_start = CASE
                    WHEN rate_limit_counters.window_start < $4 THEN $2
                    ELSE rate_limit_counters.window_start
                END
             RETURNING counter",
        )
        .bind(key)
        .bind(now)
        .bind(window_secs)
        .bind(window_start_cutoff)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 <= max_count)
    }

    /// Clean up expired rate limit entries.
    pub async fn cleanup_rate_limits(&self) -> anyhow::Result<u64> {
        let now = chrono::Utc::now().timestamp();
        // Delete entries whose window is older than 2x their window_secs
        let result = sqlx::query(
            "DELETE FROM rate_limit_counters WHERE window_start + (window_secs * 2) < $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ── Distributed security: JWT revocation ────────────────────────────

    /// Check if a session (JWT) has been revoked by checking the sessions table.
    /// This is the distributed replacement for the in-memory HashSet.
    pub async fn is_session_revoked(&self, session_id: &str) -> anyhow::Result<bool> {
        let row: Option<(bool,)> = sqlx::query_as("SELECT revoked FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some((revoked,)) => Ok(revoked),
            None => Ok(true), // session not found = treat as revoked (fail closed)
        }
    }

    /// Revoke all active sessions for an address (e.g., on ban).
    pub async fn revoke_all_sessions_for_address(&self, address: &str) -> anyhow::Result<u64> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE sessions SET revoked = true, revoked_at = $1
             WHERE address = $2 AND revoked = false",
        )
        .bind(now)
        .bind(address)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// User database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub address: String,
    pub reputation_score: i64,
    pub roles: Vec<String>,
    pub is_banned: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Session database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: String,
    pub address: String,
    pub token_hash: String,
    pub refresh_token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ip_address: String,
    pub user_agent: String,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
}

/// Message database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRow {
    pub id: String,
    pub channel: String,
    pub author: Option<String>,
    pub content: String,
    pub content_hash: String,
    pub parent_id: Option<String>,
    pub timestamp: i64,
    pub signature: String,
    pub is_edited: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Job database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobRow {
    pub id: String,
    pub channel: String,
    pub requester: Option<String>,
    pub title: String,
    pub description: String,
    pub reward_sat: i64,
    pub deadline: i64,
    pub max_workers: i32,
    pub state: String,
    pub work_type: String,
    pub requirements: Vec<String>,
    pub assigned_workers: Vec<String>,
    pub timestamp: i64,
    pub signature: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Work submission database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkSubmissionRow {
    pub id: String,
    pub job_id: String,
    pub worker: Option<String>,
    pub submission_data: String,
    pub data_hash: String,
    pub timestamp: i64,
    pub signature: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Dispute database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DisputeRow {
    pub id: String,
    pub job_id: String,
    pub work_id: String,
    pub initiator: Option<String>,
    pub reason: String,
    pub evidence: String,
    pub evidence_hash: Option<String>,
    pub timestamp: i64,
    pub signature: String,
    pub status: String,
    pub resolution: Option<String>,
    pub resolver: Option<String>,
    pub resolved_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Moderation action database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ModerationActionRow {
    pub id: String,
    pub action: String,
    pub target: String,
    pub target_type: String,
    pub reason: String,
    pub duration_secs: Option<i64>,
    pub expires_at: Option<i64>,
    pub moderator: Option<String>,
    pub timestamp: i64,
    pub signature: String,
    pub created_at: i64,
}

/// Audit log database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditLogRow {
    pub timestamp: i64,
    pub address: Option<String>,
    pub action: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub created_at: i64,
}

/// Challenge database row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChallengeRow {
    pub nonce: String,
    pub challenge_hash: String,
    pub address: String,
    pub user_agent: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
    pub used_at: Option<i64>,
}
