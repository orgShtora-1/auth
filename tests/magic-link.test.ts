import { describe, expect, test } from "bun:test";
import {
  createAuth,
  type AuthActionTokenDelivery,
  type AuthActionTokenPurpose,
  type AuthActionTokenStore,
  type AuthApi,
  type AuthOptions,
  type AuthUser,
  type EmailVerificationOptions,
  type SessionStore,
  type StoredSession,
  type UserStore,
} from "../src/index.js";

interface TestUser extends AuthUser {
  readonly passwordHash?: string;
  verified?: boolean;
}

const origin = "https://app.example.test";
const password = "Valid-password-123";
const EMAIL = "person@example.test";

interface DeliveredMessage {
  email: string;
  token: string;
  expiresAtMs: number;
}

interface ActionEntry {
  purpose: AuthActionTokenPurpose;
  userId: string;
  expiresAtMs: number;
}

interface MagicLinkFixture {
  auth: AuthApi;
  sent: DeliveredMessage[];
  actionTokens: Map<string, ActionEntry>;
  byId: Map<string, TestUser>;
  emailAllowed: { value: boolean };
  register(): Promise<void>;
}

type SetupOptions = Omit<Partial<AuthOptions<TestUser>>, "emailVerification"> & {
  emailVerification?: Pick<EmailVerificationOptions<TestUser>, "isVerified" | "markVerified">;
};

function setup(startVerified = true, options: SetupOptions = {}): MagicLinkFixture {
  const byEmail = new Map<string, TestUser>();
  const byId = new Map<string, TestUser>();
  const sessions = new Map<string, StoredSession>();
  const actionTokens = new Map<string, ActionEntry>();
  const emailAllowed = { value: true };
  const sent: DeliveredMessage[] = [];

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
      const user: TestUser = { id: `user-${byId.size + 1}`, email, passwordHash: "not-a-real-hash", verified: startVerified };
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
  const tokens: AuthActionTokenStore = {
    async create({ purpose, userId, tokenHash, expiresAtMs }) {
      actionTokens.set(tokenHash, { purpose, userId, expiresAtMs });
    },
    async consume({ purpose, tokenHash, nowMs }) {
      const entry = actionTokens.get(tokenHash);
      if (!entry || entry.purpose !== purpose || entry.expiresAtMs <= nowMs) return null;
      actionTokens.delete(tokenHash);
      return { userId: entry.userId };
    },
    async deleteExpired() {},
  };
  const delivery: AuthActionTokenDelivery = {
    async send(message) {
      sent.push(message);
    },
  };
  const auth = createAuth<TestUser>({
    users,
    credentials: {
      async verify(input) {
        return input.user?.passwordHash === "not-a-real-hash" && input.password === password;
      },
    },
    sessions: sessionStore,
    magicLink: { tokens, delivery },
    emailPolicy: { async allow() { return emailAllowed.value; } },
    ...options,
    emailVerification: options.emailVerification ? {
      ...options.emailVerification,
      tokens,
      send: delivery.send,
    } : undefined,
  });

  return {
    auth,
    sent,
    actionTokens,
    byId,
    emailAllowed,
    async register(): Promise<void> {
      const response = await auth.handle(request("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: EMAIL, password }),
      }));
      expect(response.status).toBe(202);
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

async function magicLinkRequest(state: MagicLinkFixture, email: string): Promise<Response> {
  return state.auth.handle(request("/api/auth/magic-link/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  }));
}

async function magicLinkConfirm(state: MagicLinkFixture, token: string): Promise<Response> {
  return state.auth.handle(request("/api/auth/magic-link/confirm", {
    method: "POST",
    body: JSON.stringify({ token }),
  }));
}

function extractSessionToken(setCookie: string | null): string | null {
  if (!setCookie) return null;
  return setCookie.match(/__Host-shtora\.session=([a-f0-9]{64})/)![1]!;
}

describe("magic link login", () => {
  test("request returns the same 202 body for known and unknown emails", async () => {
    const state = setup();

    const before = await magicLinkRequest(state, "missing@example.test");
    expect(before.status).toBe(202);
    expect(await before.json()).toEqual({ status: "accepted" });
    expect(state.sent).toHaveLength(0);
    expect(state.actionTokens.size).toBe(0);

    await state.register();
    const after = await magicLinkRequest(state, EMAIL);
    expect(after.status).toBe(202);
    expect(await after.json()).toEqual({ status: "accepted" });
    expect(state.sent).toHaveLength(1);
    const message = state.sent[0]!;
    expect(message.email).toBe(EMAIL);
    expect(message.token).toMatch(/^[a-f0-9]{64}$/);
    expect(message.expiresAtMs).toBeGreaterThan(Date.now());
    expect(state.actionTokens.size).toBe(1);
  });

  test("confirm creates a session for a valid magic link token", async () => {
    const state = setup();
    await state.register();
    await magicLinkRequest(state, EMAIL);
    const token = state.sent[0]!.token;

    const confirmed = await magicLinkConfirm(state, token);

    expect(confirmed.status).toBe(200);
    const body = await confirmed.json() as { user: { id: string; email: string } };
    expect(body.user.email).toBe(EMAIL);
    const sessionToken = extractSessionToken(confirmed.headers.get("set-cookie"));
    expect(sessionToken).toMatch(/^[a-f0-9]{64}$/);

    const session = await state.auth.handle(new Request(`${origin}/api/auth/session`, {
      headers: { Cookie: `__Host-shtora.session=${sessionToken}` },
    }));
    expect(session.status).toBe(200);
    const sessionBody = await session.json() as { user: { email: string } };
    expect(sessionBody.user.email).toBe(EMAIL);
  });

  test("confirm rejects invalid tokens and tokens are one-use", async () => {
    const state = setup();
    await state.register();
    await magicLinkRequest(state, EMAIL);
    const token = state.sent[0]!.token;

    const unknown = await magicLinkConfirm(state, "a".repeat(64));
    expect(unknown.status).toBe(400);
    expect(await unknown.json()).toEqual({ error: "invalid_token" });

    const first = await magicLinkConfirm(state, token);
    expect(first.status).toBe(200);

    const replay = await magicLinkConfirm(state, token);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_token" });
  });

  test("confirm rejects unverified users when email verification is enabled", async () => {
    const state = setup(false, {
      emailVerification: {
        isVerified: (user) => user.verified === true,
        markVerified: async (userId) => {
          const user = state.byId.get(userId);
          if (user) user.verified = true;
        },
      },
    });
    await state.register();
    await magicLinkRequest(state, EMAIL);
    const token = state.sent[state.sent.length - 1]!.token;

    const rejected = await magicLinkConfirm(state, token);
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toEqual({ error: "invalid_token" });
    expect(state.byId.get("user-1")!.verified).toBe(false);

    // Re-issue: the first token was consumed by the failed confirm.
    await magicLinkRequest(state, EMAIL);
    const secondToken = state.sent[state.sent.length - 1]!.token;
    const user = state.byId.get("user-1")!;
    user.verified = true;

    const confirmed = await magicLinkConfirm(state, secondToken);
    expect(confirmed.status).toBe(200);
    expect(extractSessionToken(confirmed.headers.get("set-cookie"))).toMatch(/^[a-f0-9]{64}$/);
  });

  test("request sends no delivery when an email policy rejects the address", async () => {
    const state = setup();
    await state.register();
    state.emailAllowed.value = false;

    const response = await magicLinkRequest(state, EMAIL);

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ status: "accepted" });
    expect(state.sent).toHaveLength(0);
    expect(state.actionTokens.size).toBe(0);
  });
});
