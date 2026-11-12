import { describe, expect, test } from "bun:test";
import {
  createAuth,
  type AuthActionTokenStore,
  type AuthApi,
  type AuthOptions,
  type AuthUser,
  type SessionStore,
  type StoredSession,
  type TotpRecord,
  type TotpStore,
  type UserStore,
} from "../src/index.js";
import { base32Decode, verifyTotp } from "../src/totp.js";

interface TestUser extends AuthUser {
  readonly passwordHash?: string;
}

const origin = "https://app.example.test";
const password = "Valid-password-123";

async function hotpSha1(secretBase32: string, counter: number, digits: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setUint32(4, counter);
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secretBase32) as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes as unknown as ArrayBuffer));
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

async function currentTotpCode(secretBase32: string, periodSeconds: number, digits: number): Promise<string> {
  const step = Math.floor(Date.now() / 1000 / periodSeconds);
  return hotpSha1(secretBase32, step, digits);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

interface TotpFixture {
  auth: AuthApi;
  sessions: Map<string, StoredSession>;
  totpRecords: Map<string, TotpRecord>;
  challengeTokens: Map<string, { userId: string; expiresAtMs: number }>;
  registerAndLogin(): Promise<string>;
}

function setup(options: Partial<AuthOptions<TestUser>> = {}): TotpFixture {
  const byEmail = new Map<string, TestUser>();
  const byId = new Map<string, TestUser>();
  const sessions = new Map<string, StoredSession>();
  const totpRecords = new Map<string, TotpRecord>();
  const consumedRecovery = new Set<string>();
  const challengeTokens = new Map<string, { userId: string; expiresAtMs: number }>();

  const users: UserStore<TestUser> = {
    async findByIdentifier({ value }) {
      return byEmail.get(value) ?? null;
    },
    async findByEmail(email) {
      return byEmail.get(email) ?? null;
    },
    async findById(id) {
      return byId.get(id) ?? null;
    },
    async create({ email }) {
      if (!email || byEmail.has(email)) return { created: false };
      const user: TestUser = { id: `user-${byId.size + 1}`, email, passwordHash: "not-a-real-hash" };
      byEmail.set(email, user);
      byId.set(user.id, user);
      return { created: true, user };
    },
  };
  const sessionStore: SessionStore = {
    async create(session) { sessions.set(session.tokenHash, session); },
    async findByTokenHash(tokenHash) { return sessions.get(tokenHash) ?? null; },
    async deleteByTokenHash(tokenHash) { sessions.delete(tokenHash); },
    async listByUserId(userId) { return [...sessions.values()].filter((session) => session.userId === userId); },
    async deleteByIdForUser(id, userId) {
      for (const [hash, session] of sessions) {
        if (session.id === id && session.userId === userId) sessions.delete(hash);
      }
    },
    async deleteByUserId(userId) {
      for (const [hash, session] of sessions) {
        if (session.userId === userId) sessions.delete(hash);
      }
    },
    async deleteExpired() {},
  };
  const totpStore: TotpStore = {
    async get(userId) { return totpRecords.get(userId) ?? null; },
    async set(userId, record) { totpRecords.set(userId, record); },
    async delete(userId) { totpRecords.delete(userId); },
    async consumeRecoveryCode(userId, codeHash) {
      const key = `${userId}:${codeHash}`;
      const record = totpRecords.get(userId);
      if (!record?.recoveryCodeHashes.includes(codeHash) || consumedRecovery.has(key)) return false;
      consumedRecovery.add(key);
      totpRecords.set(userId, { ...record, recoveryCodeHashes: record.recoveryCodeHashes.filter((hash) => hash !== codeHash) });
      return true;
    },
  };
  const challengeStore: AuthActionTokenStore = {
    async create({ userId, tokenHash, expiresAtMs }) {
      challengeTokens.set(tokenHash, { userId, expiresAtMs });
    },
    async consume({ tokenHash, nowMs }) {
      const entry = challengeTokens.get(tokenHash);
      if (!entry || entry.expiresAtMs <= nowMs) return null;
      challengeTokens.delete(tokenHash);
      return { userId: entry.userId };
    },
    async deleteExpired() {},
  };
  const auth = createAuth<TestUser>({
    users,
    credentials: {
      async verify(input) {
        return input.user?.passwordHash === "not-a-real-hash" && input.password === password;
      },
    },
    sessions: sessionStore,
    totp: { store: totpStore, challengeTokens: challengeStore, issuer: "Example App" },
    ...options,
  });

  return {
    auth,
    sessions,
    totpRecords,
    challengeTokens,
    async registerAndLogin(): Promise<string> {
      const registration = await auth.handle(request("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: "person@example.test", password }),
      }));
      expect(registration.status).toBe(202);
      const loginResponse = await auth.handle(request("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: "person@example.test", password }),
      }));
      expect(loginResponse.status).toBe(200);
      const cookie = loginResponse.headers.get("set-cookie")!;
      return cookie.match(/__Host-shtora\.session=([a-f0-9]{64})/)![1]!;
    },
  };
}

function request(path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  if (init.method === "POST") {
    headers.set("Content-Type", "application/json");
    headers.set("Origin", origin);
  }
  return new Request(`${origin}${path}`, { ...init, headers });
}

interface EnrollResult {
  otpauthUri: string;
  secret: string;
  recoveryCodes: string[];
}

async function enrollTotp(state: TotpFixture, cookie: string): Promise<EnrollResult> {
  const response = await state.auth.handle(request("/api/auth/totp/enroll", {
    method: "POST",
    headers: { Cookie: `__Host-shtora.session=${cookie}` },
  }));
  expect(response.status).toBe(200);
  return await response.json() as EnrollResult;
}

async function confirmTotp(state: TotpFixture, cookie: string, code: string): Promise<Response> {
  return state.auth.handle(request("/api/auth/totp/confirm", {
    method: "POST",
    headers: { Cookie: `__Host-shtora.session=${cookie}` },
    body: JSON.stringify({ code }),
  }));
}

async function activateTotp(state: TotpFixture, cookie: string, secret: string): Promise<void> {
  const code = await currentTotpCode(secret, 30, 6);
  expect((await confirmTotp(state, cookie, code)).status).toBe(204);
}

async function loginChallenge(state: TotpFixture): Promise<{ challengeToken: string; setCookie: string | null }> {
  const response = await state.auth.handle(request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: "person@example.test", password }),
  }));
  expect(response.status).toBe(200);
  const body = await response.json() as { challengeToken: string };
  return { challengeToken: body.challengeToken, setCookie: response.headers.get("set-cookie") };
}

describe("TOTP two-factor authentication", () => {
  test("enroll returns an otpauth URI, Base32 secret, and single-use recovery codes", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();

    const result = await enrollTotp(state, cookie);

    expect(result.otpauthUri.startsWith("otpauth://totp/Example%20App:person%40example.test")).toBe(true);
    expect(result.otpauthUri).toContain("algorithm=SHA1");
    expect(result.otpauthUri).toContain("digits=6");
    expect(result.otpauthUri).toContain("period=30");
    expect(result.secret).toMatch(/^[A-Z2-7]{52}$/);
    expect(result.recoveryCodes).toHaveLength(10);
    for (const code of result.recoveryCodes) expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
  });

  test("enroll stores an unconfirmed record with hashed recovery codes", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();

    const { recoveryCodes } = await enrollTotp(state, cookie);

    const record = state.totpRecords.get("user-1")!;
    expect(record.confirmed).toBe(false);
    expect(record.secret).toMatch(/^[A-Z2-7]{52}$/);
    expect(record.recoveryCodeHashes).toHaveLength(10);
    for (const hash of record.recoveryCodeHashes) expect(hash).toMatch(/^[a-f0-9]{64}$/);
    const expectedHash = await sha256Hex(recoveryCodes[0]!.replace(/-/g, ""));
    expect(record.recoveryCodeHashes).toContain(expectedHash);
  });

  test("confirm activates TOTP only with a valid current code", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);

    const wrong = await confirmTotp(state, cookie, "000000");
    expect(wrong.status).toBe(400);
    expect(state.totpRecords.get("user-1")!.confirmed).toBe(false);

    expect((await confirmTotp(state, cookie, await currentTotpCode(secret, 30, 6))).status).toBe(204);
    expect(state.totpRecords.get("user-1")!.confirmed).toBe(true);
  });

  test("enroll rejects an already confirmed enrollment", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);

    const repeated = await state.auth.handle(request("/api/auth/totp/enroll", {
      method: "POST",
      headers: { Cookie: `__Host-shtora.session=${cookie}` },
    }));

    expect(repeated.status).toBe(400);
  });

  test("login of a confirmed TOTP user returns a one-time challenge instead of a session", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);
    state.sessions.clear();

    const { challengeToken, setCookie } = await loginChallenge(state);

    expect(setCookie).toBeNull();
    expect(challengeToken).toMatch(/^[a-f0-9]{64}$/);
    expect(state.challengeTokens.size).toBe(1);
  });

  test("verify consumes the challenge once and issues a session for a valid code", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);
    const { challengeToken } = await loginChallenge(state);

    const verified = await state.auth.handle(request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ challengeToken, code: await currentTotpCode(secret, 30, 6) }),
    }));

    expect(verified.status).toBe(200);
    expect(verified.headers.get("set-cookie")).toContain("__Host-shtora.session=");
    expect(state.challengeTokens.size).toBe(0);
  });

  test("verify rejects a bad code without allowing challenge reuse", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);
    const { challengeToken } = await loginChallenge(state);

    const wrong = await state.auth.handle(request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ challengeToken, code: "000000" }),
    }));
    expect(wrong.status).toBe(401);

    const reused = await state.auth.handle(request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ challengeToken, code: "000000" }),
    }));
    expect(reused.status).toBe(400);
    expect(await reused.json()).toEqual({ error: "invalid_token" });
  });

  test("verify accepts an unused recovery code and consumes it", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret, recoveryCodes } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);
    const { challengeToken } = await loginChallenge(state);
    const code = recoveryCodes[0]!;

    const verified = await state.auth.handle(request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ challengeToken, code }),
    }));

    expect(verified.status).toBe(200);
    expect(state.totpRecords.get("user-1")!.recoveryCodeHashes).not.toContain(await sha256Hex(code.replace(/-/g, "")));

    const secondChallenge = await loginChallenge(state);
    const replay = await state.auth.handle(request("/api/auth/totp/verify", {
      method: "POST",
      body: JSON.stringify({ challengeToken: secondChallenge.challengeToken, code }),
    }));
    expect(replay.status).toBe(401);
  });

  test("disable removes the confirmed record with a valid code", async () => {
    const state = setup();
    const cookie = await state.registerAndLogin();
    const { secret } = await enrollTotp(state, cookie);
    await activateTotp(state, cookie, secret);

    const disabled = await state.auth.handle(request("/api/auth/totp/disable", {
      method: "POST",
      headers: { Cookie: `__Host-shtora.session=${cookie}` },
      body: JSON.stringify({ code: await currentTotpCode(secret, 30, 6) }),
    }));

    expect(disabled.status).toBe(204);
    expect(state.totpRecords.get("user-1")).toBeUndefined();
  });

  test("totp session routes reject a missing session", async () => {
    const state = setup();

    for (const route of ["/api/auth/totp/enroll", "/api/auth/totp/confirm", "/api/auth/totp/disable"]) {
      const response = await state.auth.handle(request(route, {
        method: "POST",
        body: JSON.stringify({ code: "000000" }),
      }));
      expect(response.status).toBe(401);
    }
  });

  test("createAuth rejects invalid TOTP configuration", () => {
    const store: TotpStore = { async get() { return null; }, async set() {}, async delete() {}, async consumeRecoveryCode() { return false; } };
    const challengeTokens: AuthActionTokenStore = { async create() {}, async consume() { return null; }, async deleteExpired() {} };
    const base = { store, challengeTokens };
    expect(() => setup({ totp: { ...base, issuer: "" } })).toThrow("totp.issuer must be a non-empty string");
    expect(() => setup({ totp: { ...base, issuer: "App", digits: 7 as unknown as 6 } })).toThrow("totp.digits must be 6 or 8");
    expect(() => setup({ totp: { ...base, issuer: "App", periodSeconds: 0 } })).toThrow("totp.periodSeconds must be a positive integer");
    expect(() => setup({ totp: { ...base, issuer: "App", skew: 11 } })).toThrow("totp.skew must be an integer between 0 and 10");
    expect(() => setup({ totp: { ...base, issuer: "App", recoveryCodeCount: 0 } })).toThrow("totp.recoveryCodeCount must be an integer between 1 and 100");
  });
});

describe("TOTP primitives", () => {
  test("verifyTotp matches the RFC 4226 test vector at time step zero", async () => {
    const valid = await verifyTotp({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      token: "755224",
      digits: 6,
      periodSeconds: 30,
      skew: 0,
      nowMs: 0,
    });
    expect(valid).toBe(true);
  });

  test("verifyTotp accepts the previous step within skew and rejects malformed tokens", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const stepZero = await hotpSha1(secret, 0, 6);
    const withSkew = await verifyTotp({ secret, token: stepZero, digits: 6, periodSeconds: 30, skew: 1, nowMs: 31_000 });
    expect(withSkew).toBe(true);
    const withoutSkew = await verifyTotp({ secret, token: stepZero, digits: 6, periodSeconds: 30, skew: 0, nowMs: 31_000 });
    expect(withoutSkew).toBe(false);
    const malformed = await verifyTotp({ secret, token: "abc", digits: 6, periodSeconds: 30, skew: 1, nowMs: 0 });
    expect(malformed).toBe(false);
  });
});
