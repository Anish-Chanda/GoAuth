CREATE TABLE Users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- stores password details for users who signup with emailpass method
CREATE TABLE Password_Creds (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES Users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- table used to stoer refresh tokens
CREATE TABLE Refresh_Tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES Users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    last_used TEXT NOT NULL DEFAULT (datetime('now'))
);


-- create indexes on email, refresh token and user id
CREATE INDEX idx_users_email ON Users(email);
CREATE INDEX idx_refresh_tokens_token ON Refresh_Tokens(token);
CREATE INDEX idx_users_id ON Users(id);