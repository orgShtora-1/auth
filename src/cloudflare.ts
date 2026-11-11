import type {
  AuthActionTokenStore,
  AuthIdentifier,
  AuthRateLimiter,
  AuthRequestRateLimitAction,
  AuthRequestRateLimiter,
  SessionStore,
  StoredSession,
} from "./types.js";

interface D1Result<Row> {
  results?: Row[];
  success?: boolean;
  meta?: { changes?: number };
}

type D1Value = string | number | boolean | null | ArrayBuffer | ArrayBufferView;

interface D1PreparedStatement {
  bind(...values: D1Value[]): D1PreparedStatement;
  first<Row = Record<string, unknown>>(): Promise<Row | null>;
  all<Row = Record<string, unknown>>(): Promise<D1Result<Row>>;
  run(): Promise<D1Result<never>>;
}

/** The subset of Cloudflare's D1 binding used by these adapters. */
export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}

export type D1ActionTokenStore = AuthActionTokenStore;

export function createD1ActionTokenStore(db: D1Database): D1ActionTokenStore {
  return {
    async create({ purpose, userId, tokenHash, expiresAtMs }) {
      await db.batch([
        db.prepare(
          "DELETE FROM shtora_action_tokens WHERE purpose = ? AND user_id = ?",
        ).bind(purpose, userId),
        db.prepare(
          "INSERT INTO shtora_action_tokens (purpose, user_id, token_hash, expires_at_ms) VALUES (?, ?, ?, ?)",
        ).bind(purpose, userId, tokenHash, expiresAtMs),
      ]);
    },
    async consume({ purpose, tokenHash, nowMs }) {
      const row = await db.prepare(
        "DELETE FROM shtora_action_tokens WHERE purpose = ? AND token_hash = ? AND expires_at_ms > ? RETURNING user_id",
      ).bind(purpose, tokenHash, nowMs).first<{ user_id: string }>();
      return row ? { userId: row.user_id } : null;
    },
    async deleteExpired({ nowMs, limit }) {
      validateCleanupInput(nowMs, limit);
      await db.prepare(
        "DELETE FROM shtora_action_tokens WHERE rowid IN " +
        "(SELECT rowid FROM shtora_action_tokens WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)",
      ).bind(nowMs, limit).run();
    },
  };
}

export function createD1SessionStore(db: D1Database): SessionStore {
  return {
    async create(session) {
      await db.prepare(
        "INSERT INTO shtora_sessions (id, token_hash, user_id, created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)",
      ).bind(session.id, session.tokenHash, session.userId, session.createdAtMs, session.expiresAtMs).run();
    },
    async findByTokenHash(tokenHash) {
      const row = await db.prepare(
        "SELECT id, token_hash, user_id, created_at_ms, expires_at_ms FROM shtora_sessions WHERE token_hash = ? LIMIT 1",
      ).bind(tokenHash).first<SessionRow>();
      return row ? toStoredSession(row) : null;
    },
    async deleteByTokenHash(tokenHash) {
      await db.prepare("DELETE FROM shtora_sessions WHERE token_hash = ?").bind(tokenHash).run();
    },
    async listByUserId(userId) {
      const result = await db.prepare(
        "SELECT id, token_hash, user_id, created_at_ms, expires_at_ms FROM shtora_sessions " +
        "WHERE user_id = ? AND expires_at_ms > ? ORDER BY created_at_ms, id",
      ).bind(userId, Date.now()).all<SessionRow>();
      return (result.results ?? []).map(toStoredSession);
    },
    async deleteByIdForUser(id, userId) {
      await db.prepare("DELETE FROM shtora_sessions WHERE id = ? AND user_id = ?").bind(id, userId).run();
    },
    async deleteByUserId(userId) {
      await db.prepare("DELETE FROM shtora_sessions WHERE user_id = ?").bind(userId).run();
    },
    async deleteExpired({ nowMs, limit }) {
      validateCleanupInput(nowMs, limit);
      await db.prepare(
        "DELETE FROM shtora_sessions WHERE rowid IN " +
        "(SELECT rowid FROM shtora_sessions WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)",
      ).bind(nowMs, limit).run();
    },
  };
}

type SessionRow = {
  id: string;
  token_hash: string;
  user_id: string;
  created_at_ms: number;
  expires_at_ms: number;
};

function toStoredSession(row: SessionRow): StoredSession {
  return {
    id: row.id,
    tokenHash: row.token_hash,
    userId: row.user_id,
    createdAtMs: row.created_at_ms,
    expiresAtMs: row.expires_at_ms,
  };
}

export interface D1RateLimitWindow {
  limit: number;
  windowSeconds: number;
}

export interface D1RateLimiterOptions {
  identifier: D1RateLimitWindow;
  ip: D1RateLimitWindow;
  /** Epoch milliseconds; injectable to make window boundaries deterministic in tests. */
  now?: () => number;
}

interface CounterRow {
  count: number;
  window_start_ms: number;
}

export function createD1RateLimiter(db: D1Database, options: D1RateLimiterOptions): AuthRateLimiter {
  validateWindow("identifier", options.identifier);
  validateWindow("ip", options.ip);
  const now = options.now ?? Date.now;

  return {
    async check({ action, identifier, ip }: { action: string; identifier: AuthIdentifier; ip: string }) {
      const dimensions = [
        { name: `identifier:${identifier.type}`, raw: identifier.value, config: options.identifier },
        { name: "ip", raw: ip, config: options.ip },
      ] as const;
      const digests = await Promise.all(dimensions.map(({ name, raw }) => hashKey(`${action}\0${name}\0${raw}`)));
      const timestamp = now();
      const windows = dimensions.map(({ config }) => Math.floor(timestamp / (config.windowSeconds * 1000)) * config.windowSeconds * 1000);
      const statements = dimensions.map((_, index) => db.prepare(
        "INSERT INTO shtora_rate_limits (key_hash, window_start_ms, count) VALUES (?, ?, 1) " +
        "ON CONFLICT(key_hash) DO UPDATE SET " +
        "count = CASE WHEN shtora_rate_limits.window_start_ms < excluded.window_start_ms THEN 1 ELSE shtora_rate_limits.count + 1 END, " +
        "window_start_ms = MAX(shtora_rate_limits.window_start_ms, excluded.window_start_ms) RETURNING count, window_start_ms",
      ).bind(digests[index]!, windows[index]!));
      const results = await db.batch<CounterRow>(statements);
      let retryAfterSeconds = 0;
      for (let index = 0; index < dimensions.length; index += 1) {
        const row = results[index]?.results?.[0];
        if (!row || typeof row.count !== "number" || typeof row.window_start_ms !== "number") {
          throw new Error("D1 rate limiter did not return a counter value");
        }
        const dimension = dimensions[index]!;
        if (row.count > dimension.config.limit) {
          const durationMs = dimension.config.windowSeconds * 1000;
          const remainingMs = row.window_start_ms + durationMs - timestamp;
          retryAfterSeconds = Math.max(retryAfterSeconds, Math.ceil(remainingMs / 1000), 1);
        }
      }
      return retryAfterSeconds > 0
        ? { allowed: false, retryAfterSeconds }
        : { allowed: true };
    },
  };
}
function validateWindow(name: string, value: D1RateLimitWindow): void {
  if (!Number.isSafeInteger(value.limit) || value.limit < 1) {
    throw new RangeError(`${name} rate limit must be a positive safe integer`);
  }
  if (!Number.isSafeInteger(value.windowSeconds) || value.windowSeconds < 1 ||
      value.windowSeconds > Math.floor(Number.MAX_SAFE_INTEGER / 1000)) {
    throw new RangeError(`${name} rate limit windowSeconds must be a positive safe integer whose milliseconds are safe`);
  }
}

export interface D1RequestRateLimiterOptions {
  limit: number;
  windowSeconds: number;
  /** Epoch milliseconds; injectable to make window boundaries deterministic in tests. */
  now?: () => number;
}

export function createD1RequestRateLimiter(
  db: D1Database,
  options: D1RequestRateLimiterOptions,
): AuthRequestRateLimiter {
  validateWindow("request", options);
  const now = options.now ?? Date.now;
  const durationMs = options.windowSeconds * 1000;

  return {
    async check({ action, ip }: { action: AuthRequestRateLimitAction; ip: string }) {
      const timestamp = now();
      const windowStart = Math.floor(timestamp / durationMs) * durationMs;
      const row = await db.prepare(
        "INSERT INTO shtora_rate_limits (key_hash, window_start_ms, count) VALUES (?, ?, 1) " +
        "ON CONFLICT(key_hash) DO UPDATE SET " +
        "count = CASE WHEN shtora_rate_limits.window_start_ms < excluded.window_start_ms THEN 1 ELSE shtora_rate_limits.count + 1 END, " +
        "window_start_ms = MAX(shtora_rate_limits.window_start_ms, excluded.window_start_ms) RETURNING count, window_start_ms",
      ).bind(await hashKey(`${action}\0request\0${ip}`), windowStart).first<CounterRow>();
      if (!row || typeof row.count !== "number" || typeof row.window_start_ms !== "number") {
        throw new Error("D1 request rate limiter did not return a counter value");
      }
      if (row.count <= options.limit) return { allowed: true };
      const remainingMs = row.window_start_ms + durationMs - timestamp;
      return { allowed: false, retryAfterSeconds: Math.max(Math.ceil(remainingMs / 1000), 1) };
    },
  };
}

function validateCleanupInput(nowMs: number, limit: number): void {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new RangeError("nowMs must be a non-negative safe integer");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new RangeError("limit must be between 1 and 1000");
  }
}

export interface D1AuthCleanupOptions {
  /** Epoch milliseconds; injectable to make cleanup deterministic in tests. */
  nowMs?: number;
  /** Longest configured rate-limit window, used to retain active counters. */
  rateLimitMaxWindowSeconds: number;
  /** Rows removed per table per call. Defaults to 500; capped at 1000. */
  batchSize?: number;
}

export async function cleanupD1AuthState(
  db: D1Database,
  options: D1AuthCleanupOptions,
): Promise<void> {
  const nowMs = options.nowMs ?? Date.now();
  const batchSize = options.batchSize ?? 500;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new RangeError("nowMs must be a non-negative safe integer");
  validateWindow("rate-limit cleanup", { limit: 1, windowSeconds: options.rateLimitMaxWindowSeconds });
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) {
    throw new RangeError("batchSize must be between 1 and 1000");
  }
  const rateLimitCutoff = nowMs - options.rateLimitMaxWindowSeconds * 1000;
  await db.batch([
    db.prepare(
      "DELETE FROM shtora_sessions WHERE rowid IN " +
      "(SELECT rowid FROM shtora_sessions WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)",
    ).bind(nowMs, batchSize),
    db.prepare(
      "DELETE FROM shtora_action_tokens WHERE rowid IN " +
      "(SELECT rowid FROM shtora_action_tokens WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)",
    ).bind(nowMs, batchSize),
    db.prepare(
      "DELETE FROM shtora_rate_limits WHERE rowid IN " +
      "(SELECT rowid FROM shtora_rate_limits WHERE window_start_ms < ? ORDER BY window_start_ms LIMIT ?)",
    ).bind(rateLimitCutoff, batchSize),
  ]);
}

async function hashKey(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
