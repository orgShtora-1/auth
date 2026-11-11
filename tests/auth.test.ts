import { describe, expect, test } from "bun:test";
import { createAuth, type AuthApi, type AuthOptions, type AuthUser, type SessionStore, type StoredSession, type UserStore } from "../src/index.js";

type TestUser = AuthUser;

const origin = "https://app.example.test";
const credentialsBody = (email = "person@example.test", password = "Valid-password-123"): string =>
  JSON.stringify({ email, password });

function setup(overrides: Partial<AuthOptions<TestUser>> = {}) {
  const byEmail = new Map<string, TestUser>();
  const byId = new Map<string, TestUser>();
  const sessions = new Map<string, StoredSession>();
  const verifierInputs: Array<{ email: string; password: string; user: TestUser | null }> = [];
  let allowedPassword = "Valid-password-123";

  const users: UserStore<TestUser> = {
    async findByEmail(email) {
      return byEmail.get(email) ?? null;
    },
    async findById(id) {
      return byId.get(id) ?? null;
    },
    async create({ email }) {
      if (byEmail.has(email)) return { created: false };
      const user = { id: `user-${byEmail.size + 1}`, email };
      byEmail.set(email, user);
      byId.set(user.id, user);
      return { created: true, user };
    },
  };
  const sessionStore: SessionStore = {
    async create(session) {
      sessions.set(session.tokenHash, session);
    },
    async findByTokenHash(tokenHash) {
      return sessions.get(tokenHash) ?? null;
    },
    async deleteByTokenHash(tokenHash) {
      sessions.delete(tokenHash);
    },
    async listByUserId(userId) {
      return [...sessions.values()].filter((session) => session.userId === userId);
    },
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
    async deleteExpired({ nowMs, limit }) {
      let removed = 0;
      for (const [hash, session] of sessions) {
        if (session.expiresAtMs <= nowMs && removed < limit) {
          sessions.delete(hash);
          removed += 1;
        }
      }
    },
  };
  const auth = createAuth<TestUser>({
    users,
    credentials: {
      async verify(input) {
        verifierInputs.push(input);
        return input.password === allowedPassword;
      },
    },
    sessions: sessionStore,
    ...overrides,
  });

  return {
    auth,
    byEmail,
    sessions,
    verifierInputs,
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

async function register(auth: AuthApi, email = "person@example.test") {
  return auth.handle(
    request("/api/auth/register", {
      method: "POST",
      body: credentialsBody(email),
    }),
  );
}

async function login(auth: AuthApi, email = "person@example.test") {
  return auth.handle(
    request("/api/auth/login", {
      method: "POST",
      body: credentialsBody(email),
    }),
  );
}

describe("@shtora/auth", () => {
  test("registers normalized email without returning or storing credentials", async () => {
    const { auth, byEmail } = setup();
    const response = await auth.handle(
      request("/api/auth/register", {
        method: "POST",
        body: credentialsBody(" Person@Example.Test "),
      }),
    );

    expect(response.status).toBe(400);
    expect(byEmail.size).toBe(0);

    const accepted = await register(auth, "PERSON@example.test");
    expect(accepted.status).toBe(202);
    const responseBody = await accepted.text();
    expect(JSON.parse(responseBody)).toEqual({ status: "accepted" });
    expect(responseBody).not.toContain("Valid-password-123");
    expect(byEmail.has("person@example.test")).toBe(true);
  });

  test("uses the same registration response for duplicate and blocked emails", async () => {
    const blocked = setup({
      emailPolicy: { async allow({ value }) { return value !== "blocked@example.test"; } },
    });
    const first = await register(blocked.auth);
    const duplicate = await register(blocked.auth);
    const denied = await register(blocked.auth, "blocked@example.test");

    expect([first.status, duplicate.status, denied.status]).toEqual([202, 202, 202]);
    const bodies = await Promise.all([first.text(), duplicate.text(), denied.text()]);
    expect(bodies[0]).toBe(bodies[1]);
    expect(bodies[1]).toBe(bodies[2]);
    expect(blocked.byEmail.size).toBe(1);
  });

  test("verifies missing accounts and returns identical login failures", async () => {
    const { auth, verifierInputs } = setup();
    await register(auth);
    const unknown = await login(auth, "missing@example.test");
    const wrong = await auth.handle(
      request("/api/auth/login", {
        method: "POST",
        body: credentialsBody("person@example.test", "wrong-password"),
      }),
    );

    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(await unknown.text()).toBe(await wrong.text());
    expect(verifierInputs.some((input) => input.user === null)).toBe(true);
    expect((await auth.handle(request("/api/auth/session"))).status).toBe(401);
  });

  test("stores only a SHA-256 token digest and authenticates via the secure cookie", async () => {
    const { auth, sessions } = setup();
    await register(auth);
    const response = await login(auth);
    const cookie = response.headers.get("set-cookie") ?? "";
    const token = cookie.match(/__Host-shtora\.session=([a-f0-9]{64})/)?.[1];

    expect(response.status).toBe(200);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).not.toContain("Domain=");
    expect(token).toBeDefined();
    expect(sessions.size).toBe(1);
    expect([...sessions.keys()][0]).not.toBe(token);
    expect(await response.json()).toEqual({ user: { id: "user-1", email: "person@example.test" } });

    const sessionResponse = await auth.handle(
      request("/api/auth/session", { headers: { Cookie: `__Host-shtora.session=${token}` } }),
    );
    expect(sessionResponse.status).toBe(200);
    expect(await sessionResponse.json()).toEqual({
      user: { id: "user-1", email: "person@example.test" },
    });
  });

  test("revokes sessions on logout and clears the matching cookie", async () => {
    const { auth, sessions } = setup();
    await register(auth);
    const signedIn = await login(auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    expect(sessions.size).toBe(1);

    const response = await auth.handle(
      request("/api/auth/logout", {
        method: "POST",
        headers: { Cookie: `__Host-shtora.session=${token}` },
      }),
    );
    expect(response.status).toBe(204);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(sessions.size).toBe(0);
    expect(
      await auth.getSession(request("/api/auth/session", { headers: { Cookie: `__Host-shtora.session=${token}` } })),
    ).toBeNull();
  });

  test("rejects duplicate or malformed session cookies", async () => {
    const { auth } = setup();
    for (const cookie of [
      "__Host-shtora.session=bad",
      `__Host-shtora.session=${"a".repeat(64)}; __Host-shtora.session=${"b".repeat(64)}`,
      `other=${"a".repeat(16_385)}`,
    ]) {
      const response = await auth.handle(request("/api/auth/session", { headers: { Cookie: cookie } }));
      expect(response.status).toBe(401);
    }
  });

  test("rejects expired sessions even when the store returns them", async () => {
    const { auth, sessions } = setup();
    const token = "a".repeat(64);
    const digest = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))),
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
    sessions.set(digest, { id: "session-1", tokenHash: digest, userId: "user-1", createdAtMs: Date.now() - 2000, expiresAtMs: Date.now() - 1000 });

    const response = await auth.handle(
      request("/api/auth/session", { headers: { Cookie: `__Host-shtora.session=${token}` } }),
    );
    expect(response.status).toBe(401);
    expect(sessions.size).toBe(0);
  });

  test("applies IP policy only to the caller-provided trusted IP resolver", async () => {
    const seen: string[] = [];
    const { auth } = setup({
      resolveClientIp(request) {
        return request.headers.get("x-test-client-ip");
      },
      ipPolicy: { async allow({ value }) { seen.push(value); return value !== "203.0.113.8"; } },
    });
    const blocked = await auth.handle(
      request("/api/auth/login", {
        method: "POST",
        headers: { "x-test-client-ip": "203.0.113.8", "x-forwarded-for": "198.51.100.9" },
        body: credentialsBody(),
      }),
    );
    expect(blocked.status).toBe(401);
    expect(seen).toEqual(["203.0.113.8"]);
  });
  test("rejects malformed JSON, invalid UTF-8, and invalid or oversized content lengths", async () => {
    const { auth } = setup({ maxRequestBytes: 64 });
    const endpoint = `${origin}/api/auth/register`;
    const headers = { Origin: origin, "Content-Type": "application/json" };
    const requests = [
      new Request(endpoint, { method: "POST", headers, body: "{" }),
      new Request(endpoint, { method: "POST", headers, body: new Uint8Array([0xff]).buffer }),
      new Request(endpoint, {
        method: "POST",
        headers: { ...headers, "Content-Length": "invalid" },
        body: "{}",
      }),
      new Request(endpoint, {
        method: "POST",
        headers: { ...headers, "Content-Length": "65" },
        body: "{}",
      }),
    ];
    const responses = await Promise.all(requests.map((request) => auth.handle(request)));

    expect(responses.map(({ status }) => status)).toEqual([400, 400, 400, 413]);
  });


  test("rejects cross-origin state changes, missing origin, and oversized bodies", async () => {
    const { auth } = setup({ maxRequestBytes: 32 });
    const crossOrigin = await auth.handle(
      new Request(`${origin}/api/auth/register`, {
        method: "POST",
        headers: { Origin: "https://attacker.example", "Content-Type": "application/json" },
        body: credentialsBody(),
      }),
    );
    const missingOrigin = await auth.handle(
      new Request(`${origin}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: credentialsBody(),
      }),
    );
    const oversized = await auth.handle(
      request("/api/auth/register", {
        method: "POST",
        body: credentialsBody("person@example.test", "long-password-that-is-over-the-limit"),
      }),
    );

    expect(crossOrigin.status).toBe(403);
    expect(missingOrigin.status).toBe(403);
    expect(oversized.status).toBe(413);
  });

  test("matches the request Host when a runtime rewrites the Request URL origin", async () => {
    const { auth } = setup();
    const response = await auth.handle(
      new Request("https://internal.example.test/api/auth/register", {
        method: "POST",
        headers: {
          Origin: origin,
          Host: "app.example.test",
          "Content-Type": "application/json",
        },
        body: credentialsBody(),
      }),
    );

    expect(response.status).toBe(202);
  });

  test("rejects ambiguous Host and Origin headers", async () => {
    const { auth } = setup();
    const headers = {
      "Content-Type": "application/json",
      Host: "app.example.test, attacker.example.test",
      Origin: origin,
    };
    const ambiguousHost = await auth.handle(
      new Request("https://internal.example.test/api/auth/register", {
        method: "POST",
        headers,
        body: credentialsBody(),
      }),
    );
    const ambiguousOrigin = await auth.handle(
      new Request("https://internal.example.test/api/auth/register", {
        method: "POST",
        headers: { ...headers, Host: "app.example.test", Origin: `${origin}, https://attacker.example` },
        body: credentialsBody(),
      }),
    );

    expect(ambiguousHost.status).toBe(403);
    expect(ambiguousOrigin.status).toBe(403);
  });

  test("requires a caller-supplied resolver and allows explicit origin opt-out", async () => {
    expect(() => setup({ ipPolicy: { async allow() { return true; } } })).toThrow(
      "resolveClientIp is required",
    );
    const { auth } = setup({ requireOrigin: false });
    const response = await auth.handle(
      new Request(`${origin}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: credentialsBody(),
      }),
    );
    expect(response.status).toBe(202);
  });

  test("rejects unsupported content types and unknown routes", async () => {
    const { auth } = setup();
    const unsupported = await auth.handle(
      new Request(`${origin}/api/auth/login`, {
        method: "POST",
        headers: { Origin: origin, "Content-Type": "text/plain" },
        body: "email=a&password=b",
      }),
    );
    expect(unsupported.status).toBe(415);
    expect((await auth.handle(request("/api/auth/not-a-route"))).status).toBe(404);
    expect((await auth.handle(request("/api/auth/login", { method: "GET" }))).status).toBe(405);
  });
  test("rate limits before policies and exposes Retry-After", async () => {
    const { auth, byEmail } = setup({
      resolveClientIp: () => "192.0.2.1",
      rateLimiter: { async check() { return { allowed: false, retryAfterSeconds: 9 }; } },
    });
    const result = await register(auth);
    expect(result.status).toBe(429);
    expect(result.headers.get("retry-after")).toBe("9");
    expect(byEmail.size).toBe(0);
  });

  test("lists and revokes owned sessions without exposing token hashes", async () => {
    const { auth, sessions } = setup();
    await register(auth);
    const signedIn = await login(auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    const headers = { Cookie: `__Host-shtora.session=${token}`, Origin: origin };
    const listing = await auth.handle(request("/api/auth/sessions", { headers }));
    const body = await listing.json() as { sessions: Array<Record<string, unknown>> };
    expect(listing.status).toBe(200);
    expect(body.sessions).toHaveLength(1);
    expect(body.sessions[0]).not.toHaveProperty("tokenHash");
    expect((await auth.handle(request("/api/auth/sessions/foreign", { method: "DELETE", headers }))).status).toBe(204);
    expect(sessions.size).toBe(1);
    expect((await auth.handle(request("/api/auth/sessions", { method: "DELETE", headers }))).status).toBe(204);
    expect(sessions.size).toBe(0);
  });

  test("enforces allowed host before route handling", async () => {
    const { auth } = setup({ allowedHosts: ["app.example.test"] });
    const result = await auth.handle(new Request(`${origin}/api/auth/register`, {
      method: "POST",
      headers: { Host: "evil.example.test", Origin: origin, "Content-Type": "application/json" },
      body: credentialsBody(),
    }));
    expect(result.status).toBe(403);
  });
  test("uses default retry delay and denies missing resolved IP", async () => {
    const limited = setup({
      resolveClientIp: () => "192.0.2.1",
      rateLimiter: { async check() { return { allowed: false }; } },
    });
    const rejected = await register(limited.auth);
    expect(rejected.status).toBe(429);
    expect(rejected.headers.get("retry-after")).toBe("60");

    const missing = setup({
      resolveClientIp: () => null,
      rateLimiter: { async check() { throw new Error("must not check"); } },
    });
    expect((await register(missing.auth)).status).toBe(202);
    expect((await login(missing.auth)).status).toBe(401);
  });

  test("observes storage and policy failures, swallows observer errors, and rejects getSession", async () => {
    const observed: string[] = [];
    const error = new Error("adapter failure");
    const store = {
      async create() {},
      async findByTokenHash() { throw error; },
      async deleteByTokenHash() {},
      async listByUserId() { return []; },
      async deleteByIdForUser() {},
      async deleteExpired() {},
      async deleteByUserId() {},
    };
    const failing = setup({
      sessions: store,
      onError(event) {
        observed.push(event.operation);
        throw new Error("observer failure");
      },
    });
    const token = "a".repeat(64);
    await expect(failing.auth.getSession(request("/api/auth/session", {
      headers: { Cookie: `__Host-shtora.session=${token}` },
    }))).rejects.toBe(error);
    expect(observed).toEqual(["getSession"]);

    const policy = setup({
      emailPolicy: { async allow() { throw error; } },
      onError(event) { observed.push(event.operation); },
    });
    expect((await register(policy.auth)).status).toBe(500);
    expect(observed).toContain("register");
  });

  test("temporary policy denials block active sessions without revoking them", async () => {
    let allowed = true;
    const { auth, sessions } = setup({
      emailPolicy: { async allow() { return allowed; } },
    });
    await register(auth);
    const signedIn = await login(auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    allowed = false;
    expect(await auth.getSession(request("/api/auth/session", { headers: { Cookie: `__Host-shtora.session=${token}` } }))).toBeNull();
    expect(sessions.size).toBe(1);
  });

  test("logout retains the cookie when session deletion fails", async () => {
    const failure = new Error("delete failed");
    const observed: string[] = [];
    const { auth } = setup({
      onError(event) { observed.push(event.operation); },
      sessions: {
        async create() {},
        async findByTokenHash() { return null; },
        async deleteByTokenHash() { throw failure; },
        async listByUserId() { return []; },
        async deleteByIdForUser() {},
        async deleteExpired() {},
        async deleteByUserId() {},
      },
    });
    const result = await auth.handle(request("/api/auth/logout", {
      method: "POST",
      headers: { Cookie: `__Host-shtora.session=${"a".repeat(64)}` },
    }));
    expect(result.status).toBe(500);
    expect(result.headers.get("set-cookie")).toBeNull();
    expect(observed).toContain("logout");
  });
  test("bulk revocation clears the current session cookie", async () => {
    const { auth } = setup();
    await register(auth);
    const signedIn = await login(auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    const result = await auth.handle(request("/api/auth/sessions", {
      method: "DELETE",
      headers: { Cookie: `__Host-shtora.session=${token}`, Origin: origin },
    }));
    expect(result.status).toBe(204);
    expect(result.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  test("rejects Origin values containing paths or userinfo", async () => {
    const { auth } = setup();
    const invalidOrigins = ["https://user@app.example.test/path", `${origin}/`];
    const responses = await Promise.all(invalidOrigins.map((invalidOrigin) => auth.handle(new Request(`${origin}/api/auth/register`, {
      method: "POST",
      headers: { Origin: invalidOrigin, "Content-Type": "application/json" },
      body: credentialsBody(),
    }))));
    expect(responses.map(({ status }) => status)).toEqual([403, 403]);
  });
  test("a policy failure on getSession is observed before rejection", async () => {
    let shouldFail = false;
    const seen: string[] = [];
    const setupAuth = setup({
      emailPolicy: { async allow() { if (shouldFail) throw new Error("policy failed"); return true; } },
      onError(event) { seen.push(event.operation); },
    });
    await register(setupAuth.auth);
    const signedIn = await login(setupAuth.auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    shouldFail = true;
    await expect(setupAuth.auth.getSession(request("/api/auth/session", {
      headers: { Cookie: `__Host-shtora.session=${token}` },
    }))).rejects.toThrow("policy failed");
    expect(seen).toContain("getSession");
  });
  test("expires a session exactly at the expiry boundary", async () => {
    const { auth, sessions } = setup();
    const token = "b".repeat(64);
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const fixedNow = 1_700_000_000_000;
    const originalNow = Date.now;
    Date.now = () => fixedNow;
    try {
      sessions.set(hash, { id: "at-boundary", tokenHash: hash, userId: "user-1", createdAtMs: fixedNow - 1000, expiresAtMs: fixedNow });
      const result = await auth.getSession(request("/api/auth/session", { headers: { Cookie: `__Host-shtora.session=${token}` } }));
      expect(result).toBeNull();
      expect(sessions.size).toBe(0);
    } finally {
      Date.now = originalNow;
    }
  });
  test("cleanup removes expired sessions but preserves active ones", async () => {
    const { auth, sessions } = setup();
    const now = Date.now();
    sessions.set("expired", { id: "expired", tokenHash: "expired", userId: "user-1", createdAtMs: now - 2000, expiresAtMs: now - 1 });
    sessions.set("active", { id: "active", tokenHash: "active", userId: "user-1", createdAtMs: now, expiresAtMs: now + 60_000 });
    await auth.cleanupExpired();
    expect([...sessions.keys()]).toEqual(["active"]);
  });
  test("GET session remains readable without an Origin header", async () => {
    const { auth } = setup();
    expect((await auth.handle(request("/api/auth/session"))).status).toBe(401);
  });
  test("lists sessions without requiring Origin but rejects an invalid supplied Origin", async () => {
    const { auth } = setup();
    await register(auth);
    const signedIn = await login(auth);
    const token = signedIn.headers.get("set-cookie")?.match(/=([a-f0-9]{64})/)?.[1] as string;
    const result = await auth.handle(request("/api/auth/sessions", {
      headers: { Cookie: `__Host-shtora.session=${token}` },
    }));
    expect(result.status).toBe(200);
    expect((await result.json() as { sessions: unknown[] }).sessions).toHaveLength(1);
    const crossOrigin = await auth.handle(request("/api/auth/sessions", {
      headers: { Cookie: `__Host-shtora.session=${token}`, Origin: "https://attacker.example" },
    }));
    expect(crossOrigin.status).toBe(403);
  });

  test("issues sessions only for existing users after external verification", async () => {
    const { auth, byEmail, sessions } = setup();
    await register(auth);
    const user = byEmail.get("person@example.test");
    expect(user).toBeDefined();
    const created = await auth.createSessionResponse(request("/api/auth/session"), user!.id);
    expect(created.status).toBe(200);
    expect(sessions.size).toBe(1);

    const unknown = await auth.createSessionResponse(request("/api/auth/session"), "missing-user");
    expect(unknown.status).toBe(401);
    expect(sessions.size).toBe(1);
  });
});
