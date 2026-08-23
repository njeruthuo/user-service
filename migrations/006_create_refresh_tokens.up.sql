CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- SHA-256 hex digest of the issued token, never the token itself.
    token_hash TEXT NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Revoking or listing every token belonging to one user.
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- Sweeping expired rows.
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
