-- Axiom Community Platform - Initial Database Schema
-- Date: 2026-03-28
-- Database: PostgreSQL 15+

-- ============================================================================
-- Extensions
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- ============================================================================
-- Users Table (on-chain identity)
-- ============================================================================

CREATE TABLE users (
    address VARCHAR(42) PRIMARY KEY,
    reputation_score BIGINT DEFAULT 0,
    roles TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_users_reputation ON users(reputation_score DESC);
CREATE INDEX idx_users_banned ON users(is_banned) WHERE is_banned = TRUE;

COMMENT ON TABLE users IS 'User profiles linked to blockchain addresses';
COMMENT ON COLUMN users.address IS 'Axiom blockchain address (axiom1...)';
COMMENT ON COLUMN users.roles IS 'User roles: member, worker, verifier, moderator, core_dev';
COMMENT ON COLUMN users.reputation_score IS 'On-chain reputation score';

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    address VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at BIGINT,
    revoked_reason TEXT,
    last_activity BIGINT NOT NULL
);

CREATE INDEX idx_sessions_address ON sessions(address);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_active ON sessions(revoked) WHERE revoked = FALSE;
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity DESC);

COMMENT ON TABLE sessions IS 'Authentication sessions with tokens';
COMMENT ON COLUMN sessions.token_hash IS 'SHA-256 hash of JWT token';
COMMENT ON COLUMN sessions.refresh_token_hash IS 'SHA-256 hash of refresh token';
COMMENT ON COLUMN sessions.ip_address IS 'Client IP address (for binding)';

-- ============================================================================
-- Messages Table
-- ============================================================================

CREATE TABLE messages (
    id VARCHAR(64) PRIMARY KEY,
    channel VARCHAR(100) NOT NULL,
    author VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE SET NULL,
    content TEXT NOT NULL,
    content_hash VARCHAR(64) NOT NULL UNIQUE,
    parent_id VARCHAR(64) REFERENCES messages(id) ON DELETE CASCADE,
    timestamp BIGINT NOT NULL,
    signature TEXT NOT NULL,
    is_edited BOOLEAN DEFAULT FALSE,
    edit_history JSONB DEFAULT '[]'::JSONB,
    reaction_counts JSONB DEFAULT '{}'::JSONB,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_messages_channel ON messages(channel);
CREATE INDEX idx_messages_author ON messages(author);
CREATE INDEX idx_messages_timestamp ON messages(timestamp DESC);
CREATE INDEX idx_messages_parent ON messages(parent_id);
CREATE INDEX idx_messages_channel_time ON messages(channel, timestamp DESC);

COMMENT ON TABLE messages IS 'Channel messages (signed, immutable content)';
COMMENT ON COLUMN messages.content_hash IS 'SHA-3-256 hash of content (prevents tampering)';
COMMENT ON COLUMN messages.reaction_counts IS 'JSON: {"emoji": count, ...}';

-- ============================================================================
-- Jobs Table
-- ============================================================================

CREATE TABLE jobs (
    id VARCHAR(64) PRIMARY KEY,
    channel VARCHAR(100) NOT NULL,
    requester VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    reward_sat BIGINT NOT NULL CHECK (reward_sat > 0),
    deadline BIGINT NOT NULL,
    max_workers INT NOT NULL CHECK (max_workers > 0),
    state VARCHAR(20) NOT NULL DEFAULT 'open',
    work_type VARCHAR(50) NOT NULL,
    requirements TEXT[] DEFAULT ARRAY[]::TEXT[],
    assigned_workers TEXT[] DEFAULT ARRAY[]::TEXT[],
    timestamp BIGINT NOT NULL,
    signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_jobs_channel ON jobs(channel);
CREATE INDEX idx_jobs_state ON jobs(state);
CREATE INDEX idx_jobs_deadline ON jobs(deadline);
CREATE INDEX idx_jobs_requester ON jobs(requester);
CREATE INDEX idx_jobs_state_deadline ON jobs(state, deadline) WHERE state = 'open';

COMMENT ON TABLE jobs IS 'Job postings and work coordination';
COMMENT ON COLUMN jobs.state IS 'open, assigned, in_progress, completed, disputed, settled';
COMMENT ON COLUMN jobs.assigned_workers IS 'Array of worker addresses assigned to this job';

-- ============================================================================
-- Work Submissions Table
-- ============================================================================

CREATE TABLE work_submissions (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    worker VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE SET NULL,
    submission_data TEXT NOT NULL,
    data_hash VARCHAR(64) NOT NULL,
    timestamp BIGINT NOT NULL,
    signature TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending_review',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_work_submissions_job ON work_submissions(job_id);
CREATE INDEX idx_work_submissions_worker ON work_submissions(worker);
CREATE INDEX idx_work_submissions_status ON work_submissions(status);

COMMENT ON TABLE work_submissions IS 'Work submitted for jobs (encrypted data)';
COMMENT ON COLUMN work_submissions.status IS 'pending_review, approved, disputed, rejected';

-- ============================================================================
-- Disputes Table
-- ============================================================================

CREATE TABLE disputes (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    work_id VARCHAR(64) NOT NULL REFERENCES work_submissions(id) ON DELETE CASCADE,
    initiator VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    evidence_hash VARCHAR(64),
    timestamp BIGINT NOT NULL,
    signature TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    resolution JSONB,
    resolver VARCHAR(42) REFERENCES users(address),
    resolved_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_disputes_job ON disputes(job_id);
CREATE INDEX idx_disputes_initiator ON disputes(initiator);
CREATE INDEX idx_disputes_status ON disputes(status) WHERE status = 'open';

COMMENT ON TABLE disputes IS 'Work disputes and resolution';
COMMENT ON COLUMN disputes.status IS 'open, in_review, resolved, settled';
COMMENT ON COLUMN disputes.resolution IS 'JSON: {outcome, decision, resolver_notes}';

-- ============================================================================
-- Moderation Actions Table
-- ============================================================================

CREATE TABLE moderation_actions (
    id VARCHAR(64) PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    target VARCHAR(42) NOT NULL,
    target_type VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    duration_secs BIGINT,
    expires_at BIGINT,
    moderator VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE SET NULL,
    timestamp BIGINT NOT NULL,
    signature TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX idx_moderation_target ON moderation_actions(target);
CREATE INDEX idx_moderation_action ON moderation_actions(action);
CREATE INDEX idx_moderation_moderator ON moderation_actions(moderator);
CREATE INDEX idx_moderation_expires ON moderation_actions(expires_at) WHERE expires_at IS NOT NULL;

COMMENT ON TABLE moderation_actions IS 'Moderation: delete_message, mute_user, ban_user';
COMMENT ON COLUMN moderation_actions.duration_secs IS 'NULL means permanent';

-- ============================================================================
-- Audit Log Table
-- ============================================================================

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    address VARCHAR(42),
    action VARCHAR(100) NOT NULL,
    details JSONB,
    status VARCHAR(20),
    ip_address INET,
    user_agent TEXT,
    created_at BIGINT NOT NULL
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_address ON audit_logs(address) WHERE address IS NOT NULL;
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail (no secrets stored)';
COMMENT ON COLUMN audit_logs.details IS 'JSON with action context (no passwords, keys)';

-- ============================================================================
-- Reputation History Table
-- ============================================================================

CREATE TABLE reputation_history (
    id BIGSERIAL PRIMARY KEY,
    address VARCHAR(42) NOT NULL REFERENCES users(address) ON DELETE CASCADE,
    previous_score BIGINT NOT NULL,
    new_score BIGINT NOT NULL,
    delta BIGINT NOT NULL,
    reason TEXT NOT NULL,
    related_job_id VARCHAR(64),
    timestamp BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX idx_reputation_address ON reputation_history(address);
CREATE INDEX idx_reputation_timestamp ON reputation_history(timestamp DESC);
CREATE INDEX idx_reputation_reason ON reputation_history(reason);

COMMENT ON TABLE reputation_history IS 'Reputation score change tracking';

-- ============================================================================
-- Channel Configuration Table (optional, for future expansion)
-- ============================================================================

CREATE TABLE channels (
    name VARCHAR(100) PRIMARY KEY,
    description TEXT,
    creator VARCHAR(42) REFERENCES users(address) ON DELETE SET NULL,
    is_private BOOLEAN DEFAULT FALSE,
    moderation_rules JSONB,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_channels_private ON channels(is_private);
CREATE INDEX idx_channels_created ON channels(created_at DESC);

COMMENT ON TABLE channels IS 'Channel configuration and metadata';

-- ============================================================================
-- Constraints and Triggers
-- ============================================================================

-- Prevent self-referencing parent messages
ALTER TABLE messages
ADD CONSTRAINT no_self_reply
CHECK (parent_id IS NULL OR parent_id != id);

-- Ensure job deadline is in the future
ALTER TABLE jobs
ADD CONSTRAINT future_deadline
CHECK (deadline > created_at);

-- ============================================================================
-- Views (useful for queries)
-- ============================================================================

CREATE VIEW active_sessions AS
SELECT
    id,
    address,
    ip_address,
    created_at,
    expires_at,
    last_activity
FROM sessions
WHERE revoked = FALSE
    AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT;

COMMENT ON VIEW active_sessions IS 'Currently active, non-revoked sessions';

CREATE VIEW open_jobs AS
SELECT
    id,
    channel,
    requester,
    title,
    reward_sat,
    deadline,
    max_workers,
    array_length(assigned_workers, 1) as worker_count
FROM jobs
WHERE state = 'open'
    AND deadline > EXTRACT(EPOCH FROM NOW())::BIGINT;

COMMENT ON VIEW open_jobs IS 'Available jobs not yet completed or expired';

-- ============================================================================
-- Permissions (row-level security can be added later)
-- ============================================================================

-- NOTE: For production, consider adding Row-Level Security (RLS)
-- to prevent users from accessing other users' data inappropriately.
-- This would require PostgreSQL RLS policies to be implemented per table.

-- ============================================================================
-- Initialization
-- ============================================================================

-- Create a system user for internal operations
INSERT INTO users (
    address,
    roles,
    created_at,
    updated_at
) VALUES (
    'axiom1system0000000000000000000000000000000000',
    ARRAY['core_dev'],
    EXTRACT(EPOCH FROM NOW())::BIGINT,
    EXTRACT(EPOCH FROM NOW())::BIGINT
);

COMMENT ON DATABASE postgres IS 'Axiom Community Platform Database';
