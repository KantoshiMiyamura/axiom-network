-- Distributed security tables for multi-instance deployment.
-- Moves IP bans, signature replay tracking, and rate limiting from
-- in-memory stores to PostgreSQL so all instances share state.

-- ============================================================================
-- IP Bans (shared across instances)
-- ============================================================================

CREATE TABLE IF NOT EXISTS ip_bans (
    ip_address INET PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT 'auto',
    expires_at BIGINT NOT NULL,           -- 0 = permanent
    created_at BIGINT NOT NULL,
    created_by VARCHAR(42)                -- address of admin who banned, NULL = auto-ban
);

CREATE INDEX IF NOT EXISTS idx_ip_bans_expires ON ip_bans (expires_at) WHERE expires_at > 0;

COMMENT ON TABLE ip_bans IS 'IP-level bans shared across all server instances';
COMMENT ON COLUMN ip_bans.expires_at IS '0 = permanent, otherwise unix timestamp';

-- ============================================================================
-- Auth failure counters (for auto-ban across instances)
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth_failure_counters (
    ip_address INET PRIMARY KEY,
    failure_count INT NOT NULL DEFAULT 0,
    window_start BIGINT NOT NULL,         -- start of the current 5-minute window
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_failures_window ON auth_failure_counters (window_start);

COMMENT ON TABLE auth_failure_counters IS 'Per-IP auth failure counters for auto-ban';

-- ============================================================================
-- Used signatures (replay protection across instances)
-- ============================================================================

CREATE TABLE IF NOT EXISTS used_signatures (
    sig_prefix VARCHAR(64) PRIMARY KEY,   -- first 64 hex chars of signature
    address VARCHAR(42) NOT NULL,         -- who submitted it
    action VARCHAR(50) NOT NULL,          -- message_posted, job_posted, etc.
    used_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_used_sigs_used_at ON used_signatures (used_at);
CREATE INDEX IF NOT EXISTS idx_used_sigs_address ON used_signatures (address);

COMMENT ON TABLE used_signatures IS 'Tracks used ML-DSA-87 signatures to prevent replay';

-- ============================================================================
-- Distributed rate limit counters
-- ============================================================================

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    key VARCHAR(255) PRIMARY KEY,         -- "global", "ip:1.2.3.4", "user:axiom1..."
    counter INT NOT NULL DEFAULT 0,
    window_start BIGINT NOT NULL,         -- unix epoch second for the window start
    window_secs INT NOT NULL DEFAULT 60   -- window duration
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limit_counters (window_start);

COMMENT ON TABLE rate_limit_counters IS 'Distributed rate limit counters shared across instances';
COMMENT ON COLUMN rate_limit_counters.key IS 'Format: global, ip:<addr>, user:<addr>';
