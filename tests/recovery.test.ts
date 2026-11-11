import { describe, expect, test } from "bun:test";
import {
  createAuth,
  type AuthActionTokenStore,
  type AuthUser,
  type SessionStore,
  type StoredSession,
  type UserStore,
} from "../src/index.js";

interface TestUser extends AuthUser {
  verified: boolean;
}

const origin = "https://app.example.test";
const password = "Initial-password-123";

function setup(options: {
  verification?: boolean;
  reset?: boolean;
  sendFailure?: boolean;
} = {}) {
  const usersByEmail = new Map<string, TestUser>();
  const usersById = new Map<string, TestUser>();
  const passwords = new Map<string, string>();
  const sessions = new Map<string, StoredSession>();
  const tokens = new Map<string, { userId: string; expiresAtMs: number }>();
  const delivered: Array<{ email: string; token: string; expiresAtMs: number }> = [];
  const errors: string[] = [];
  const actionTokens: AuthActionTokenStore = {
    async create({ purpose, userId, tokenHash, expiresAtMs }) {
      for (const [key, entry] of tokens) {
        if (key.startsWith(`${purpose}:`) && entry.userId === userId) tokens.delete(key);
      }
      tokens.set(`${purpose}:${tokenHash}`, { userId, expiresAtMs });
    },
    async consume({ purpose, tokenHash, nowMs }) {
      const key = `${purpose}:${tokenHash}`;
      const entry = tokens.get(key);
      if (!entry || entry.expiresAtMs <= nowMs) return null;
      tokens.delete(key);
      return { userId: entry.userId };
    },
    async deleteExpired({ nowMs, limit }) {
      let removed = 0;
      for (const [key, entry] of tokens) {
        if (entry.expiresAtMs <= nowMs && removed < limit) {
          tokens.delete(key);
          removed += 1;
        }
      }
    },
  };
  const users: UserStore<TestUser> = {
    async findByEmail(email) { return usersByEmail.get(email) ?? null; },
    async findById(id) { return usersById.get(id) ?? null; },
    async create({ email, password: newPassword }) {
      if (usersByEmail.has(email)) return { created: false };
      const user = { id: `user-${usersById.size + 1}`, email, verified: false };
      usersByEmail.set(email, user);
      usersById.set(user.id, user);
      passwords.set(user.id, newPassword);
      return { created: true, user };
    },
  };
  const sessionStore: SessionStore = {
    async create(session) { sessions.set(session.tokenHash, session); },
    async findByTokenHash(tokenHash) { return sessions.get(tokenHash) ?? null; },
    async deleteByTokenHash(tokenHash) { sessions.delete(tokenHash); },
    async listByUserId(userId) { return [...sessions.values()].filter((session) => session.userId === userId); },
    async deleteByIdForUser(id, userId) {
      for (const [tokenHash, session] of sessions) {
        if (session.id === id && session.userId === userId) sessions.delete(tokenHash);
      }
    },
    async deleteByUserId(userId) {
      for (const [tokenHash, session] of sessions) {
        if (session.userId === userId) sessions.delete(tokenHash);
      }
    },
    async deleteExpired({ nowMs, limit }) {
      let removed = 0;
      for (const [tokenHash, session] of sessions) {
        if (session.expiresAtMs <= nowMs && removed < limit) {
          sessions.delete(tokenHash);
          removed += 1;
        }
      }
    },
  };
  const delivery = {
    async send(message: typeof delivered[number]) {
      if (options.sendFailure) throw new Error("mail delivery failed");
      delivered.push(message);
    },
  };
  const auth = createAuth<TestUser>({
    users,
    credentials: {
      async verify({ user, password: candidate }) {
        return user !== null && passwords.get(user.id) === candidate;
      },
    },
    sessions: sessionStore,
    ...(options.verification ? {
      emailVerification: {
        ...delivery,
        tokens: actionTokens,
        isVerified: (user: TestUser) => user.verified,
        async markVerified(userId: string) { const user = usersById.get(userId); if (user) user.verified = true; },
      },
    } : {}),
    ...(options.reset ? {
      passwordReset: {
        ...delivery,
        tokens: actionTokens,
        async setPassword({ userId, password: newPassword }) { passwords.set(userId, newPassword); },
      },
    } : {}),
    onError({ operation }) { errors.push(operation); },
  });
  return { auth, usersByEmail, sessions, tokens, delivered, errors };
}

function send(auth: ReturnType<typeof createAuth>, path: string, body: object) {
  return auth.handle(new Request(`${origin}/api/auth/${path}`, {
    method: "POST",
    headers: { Origin: origin, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }));
}

function sessionRequest(auth: ReturnType<typeof createAuth>, candidate: string) {
  return send(auth, "login", { email: "person@example.test", password: candidate });
}

async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function register(auth: ReturnType<typeof createAuth>) {
  return send(auth, "register", { email: "person@example.test", password });
}

describe("email verification and password recovery", () => {
  test("registration requires one-time email verification before login", async () => {
    const state = setup({ verification: true });
    expect((await register(state.auth)).status).toBe(202);
    const token = state.delivered[0]!.token;
    const storedTokenHash = await digest(token);
    expect(state.tokens.has(`email-verification:${storedTokenHash}`)).toBe(true);
    expect([...state.tokens.keys()]).not.toContain(token);
    expect((await sessionRequest(state.auth, password)).status).toBe(401);

    expect((await send(state.auth, "email-verification/confirm", { token })).status).toBe(204);
    expect((await sessionRequest(state.auth, password)).status).toBe(200);
  });

  test("verification requests return the same response for existing and unknown emails", async () => {
    const state = setup({ verification: true });
    await register(state.auth);
    const existing = await send(state.auth, "email-verification/request", { email: "person@example.test" });
    const unknown = await send(state.auth, "email-verification/request", { email: "missing@example.test" });
    expect(existing.status).toBe(202);
    expect(await existing.text()).toBe(await unknown.text());
    expect(state.delivered).toHaveLength(2);
  });

  test("password reset consumes its token and revokes all active sessions", async () => {
    const state = setup({ reset: true });
    await register(state.auth);
    expect((await sessionRequest(state.auth, password)).status).toBe(200);
    expect(state.sessions.size).toBe(1);
    const existing = await send(state.auth, "password-reset/request", { email: "person@example.test" });
    const unknown = await send(state.auth, "password-reset/request", { email: "missing@example.test" });
    expect(existing.status).toBe(202);
    expect(await existing.text()).toBe(await unknown.text());
    const oldToken = state.delivered[0]!.token;
    await send(state.auth, "password-reset/request", { email: "person@example.test" });
    const token = state.delivered[1]!.token;

    expect((await send(state.auth, "password-reset/confirm", { token: oldToken, password: "Old-reset-456" })).status).toBe(400);
    expect((await send(state.auth, "password-reset/confirm", { token, password: "New-password-456" })).status).toBe(204);
    expect(state.sessions.size).toBe(0);
    expect((await sessionRequest(state.auth, password)).status).toBe(401);
    expect((await sessionRequest(state.auth, "New-password-456")).status).toBe(200);
    expect((await send(state.auth, "password-reset/confirm", { token, password: "Another-password-789" })).status).toBe(400);
  });

  test("delivery failures preserve generic registration responses and are observed", async () => {
    const state = setup({ verification: true, sendFailure: true });
    expect((await register(state.auth)).status).toBe(202);
    expect(state.errors).toContain("email-verification.send");
  });
  test("cleanup removes expired action tokens and keeps live tokens", async () => {
    const state = setup({ reset: true });
    const now = Date.now();
    state.tokens.set("password-reset:expired", { userId: "user-1", expiresAtMs: now - 1 });
    state.tokens.set("password-reset:live", { userId: "user-1", expiresAtMs: now + 60_000 });
    await state.auth.cleanupExpired();
    expect([...state.tokens.keys()]).toEqual(["password-reset:live"]);
  });
});