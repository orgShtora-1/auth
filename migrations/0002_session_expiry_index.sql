CREATE INDEX IF NOT EXISTS shtora_sessions_expiry
  ON shtora_sessions (expires_at_ms);
