-- Add public key column to users table for ML-DSA-87 signature verification
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_hex TEXT;

-- Create challenges table for persistent challenge storage
CREATE TABLE IF NOT EXISTS challenges (
    nonce VARCHAR(128) PRIMARY KEY,
    challenge_hash VARCHAR(128) NOT NULL,
    address VARCHAR(128) NOT NULL,
    user_agent TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges (expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_address ON challenges (address);
