import { describe, expect, test } from "bun:test";
import { createOidc } from "../src/oidc.js";
import { createWebAuthn, type WebAuthnChallengeStore, type WebAuthnCredentialStore } from "../src/webauthn.js";
import type { AuthRequestRateLimiter } from "../src/types.js";

const webauthnOrigin = "https://login.example.test";

function webauthnSetup(rateLimiter: AuthRequestRateLimiter = { async check() { return { allowed: true }; } }) {
  const entries = new Map<string, {
    purpose: "registration" | "authentication";
    userId: string | null;
    value: string;
    expiresAtMs: number;
  }>();
  const challenges: WebAuthnChallengeStore = {
    async create(challenge) { entries.set(challenge.id, challenge); },
    async consume({ id, purpose, userId, nowMs }) {
      const entry = entries.get(id);
      if (!entry || entry.purpose !== purpose || entry.userId !== userId || entry.expiresAtMs <= nowMs) return null;
      entries.delete(id);
      return { value: entry.value };
    },
    async deleteExpired({ nowMs, limit }) {
      let removed = 0;
      for (const [id, entry] of entries) {
        if (entry.expiresAtMs <= nowMs && removed < limit) {
          entries.delete(id);
          removed += 1;
        }
      }
    },
  };
  const credentials: WebAuthnCredentialStore = {
    async listByUserId() { return []; },
    async findById() { return null; },
    async create() { return false; },
    async updateCounter() { return false; },
  };
  const handler = createWebAuthn({
    expectedOrigin: webauthnOrigin,
    rpID: "example.test",
    rpName: "Example",
    challenges,
    credentials,
    async resolveRegistrationUser() { return null; },
    async resolveClientIp() { return "192.0.2.10"; },
    rateLimiter,
    auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
  });
  return { handler, entries, challenges, credentials };
}

describe("optional protocol module boundaries", () => {
  test("WebAuthn issues a challenge only for the configured origin", async () => {
    const { handler, entries } = webauthnSetup();
    const blocked = await handler.handle(new Request(`${webauthnOrigin}/webauthn/authentication/options`, {
      method: "POST",
      headers: { Origin: "https://attacker.example.test" },
    }));
    expect(blocked.status).toBe(403);
    expect(entries.size).toBe(0);

    const allowed = await handler.handle(new Request(`${webauthnOrigin}/webauthn/authentication/options`, {
      method: "POST",
      headers: { Origin: webauthnOrigin },
    }));
    const body = await allowed.json() as { transactionId?: string; options?: { challenge?: string } };
    expect(allowed.status).toBe(200);
    expect(typeof body.transactionId).toBe("string");
    expect(typeof body.options?.challenge).toBe("string");
    expect(entries.size).toBe(1);
  });
  test("WebAuthn blocks rate-limited challenge creation and cleans expired challenges", async () => {
    const blocked = webauthnSetup({ async check() { return { allowed: false, retryAfterSeconds: 17 }; } });
    const denied = await blocked.handler.handle(new Request(`${webauthnOrigin}/webauthn/authentication/options`, {
      method: "POST",
      headers: { Origin: webauthnOrigin },
    }));
    expect(denied.status).toBe(429);
    expect(denied.headers.get("retry-after")).toBe("17");
    expect(blocked.entries.size).toBe(0);

    const setup = webauthnSetup();
    setup.entries.set("expired", {
      purpose: "authentication",
      userId: null,
      value: "stale",
      expiresAtMs: Date.now() - 1,
    });
    await setup.handler.cleanupExpired();
    expect(setup.entries.has("expired")).toBe(false);
  });

  test("WebAuthn rejects an RP ID unrelated to the configured origin", () => {
    const { challenges, credentials } = webauthnSetup();
    expect(() => createWebAuthn({
      expectedOrigin: webauthnOrigin,
      rpID: "attacker.test",
      rpName: "Example",
      challenges,
      credentials,
      async resolveRegistrationUser() { return null; },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: true }; } },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
    })).toThrow("rpID must match its host");
  });
  test("OIDC callback rejects hostile authority and duplicate state before consuming or discovering", async () => {
    let consumed = false;
    const handler = createOidc({
      issuer: "https://issuer.example.test",
      clientId: "client",
      callbackUrl: "https://login.example.test/api/oidc/callback",
      successPath: "/account",
      transactions: {
        async create() {},
        async consume() { consumed = true; return null; },
        async deleteExpired() {},
      },
      async resolveUser() { return null; },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: true }; } },
    });
    const responses = await Promise.all([
      handler(new Request("https://internal.example/api/oidc/callback?state=invalid", {
        headers: { Host: "attacker.example.test", Cookie: "__Host-shtora.oidc-state=invalid" },
      })),
      handler(new Request("https://internal.example/api/oidc/callback?state=invalid&state=invalid", {
        headers: { Host: "login.example.test", Cookie: "__Host-shtora.oidc-state=invalid" },
      })),
      handler(new Request("https://internal.example/api/oidc/callback?state=invalid", {
        headers: {
          Host: "login.example.test",
          Cookie: "__Host-shtora.oidc-state=invalid; __Host-shtora.oidc-state=invalid",
        },
      })),
    ]);
    expect(responses.map(({ status }) => status)).toEqual([400, 400, 400]);
    expect(consumed).toBe(false);
  });
  test("OIDC rate-limits starts before persistence and exposes bounded cleanup", async () => {
    let created = false;
    let cleanupLimit = 0;
    const handler = createOidc({
      issuer: "https://issuer.example.test",
      clientId: "client",
      callbackUrl: "https://login.example.test/api/oidc/callback",
      successPath: "/account",
      transactions: {
        async create() { created = true; },
        async consume() { return null; },
        async deleteExpired({ limit }) { cleanupLimit = limit; },
      },
      async resolveUser() { return null; },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: false, retryAfterSeconds: 23 }; } },
    });
    const response = await handler(new Request("https://login.example.test/start"));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("23");
    expect(created).toBe(false);
    await handler.cleanupExpired();
    expect(cleanupLimit).toBe(500);
  });
});
