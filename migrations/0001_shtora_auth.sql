CREATE TABLE IF NOT EXISTS shtora_sessions (
  id TEXT PRIMARY KEY NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS shtora_sessions_user_created
  ON shtora_sessions (user_id, created_at_ms, id);

CREATE TABLE IF NOT EXISTS shtora_rate_limits (
  key_hash TEXT PRIMARY KEY NOT NULL,
  window_start_ms INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK (count > 0)
);

CREATE TABLE IF NOT EXISTS shtora_action_tokens (
  purpose TEXT NOT NULL,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (purpose, token_hash)
);

CREATE INDEX IF NOT EXISTS shtora_action_tokens_expiry
  ON shtora_action_tokens (expires_at_ms);
CREATE INDEX IF NOT EXISTS shtora_action_tokens_user_purpose
  ON shtora_action_tokens (purpose, user_id);

-- Preferred cleanup path: schedule cleanupD1AuthState(db, { rateLimitMaxWindowSeconds }).
-- It uses bounded batches for expired sessions/action tokens and completed rate-limit windows.
-- Manual equivalent for rate counters:
-- DELETE FROM shtora_rate_limits WHERE window_start_ms < :now_ms - :max_window_ms;
-- Set :max_window_ms to the longest configured rate-limit window in milliseconds.
-- Manual equivalent for action tokens and sessions:
-- DELETE FROM shtora_action_tokens WHERE expires_at_ms <= :now_ms;
-- DELETE FROM shtora_sessions WHERE expires_at_ms <= :now_ms;
-- Apply 0002_session_expiry_index.sql and 0003_rate_limit_expiry_index.sql for cleanup indexes.
