import { describe, expect, mock, test } from "bun:test";
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
        headers: { Host: "attacker.example.test", Cookie: "__Host-shtora.oidc-state-invalid=invalid" },
      })),
      handler(new Request("https://internal.example/api/oidc/callback?state=invalid&state=invalid", {
        headers: { Host: "login.example.test", Cookie: "__Host-shtora.oidc-state-invalid=invalid" },
      })),
      handler(new Request("https://internal.example/api/oidc/callback?state=invalid", {
        headers: {
          Host: "login.example.test",
          Cookie: "__Host-shtora.oidc-state-invalid=invalid; __Host-shtora.oidc-state-invalid=invalid",
        },
      })),
      handler(new Request("https://login.example.test/api/oidc/callback?code=code&state=bad%3B%20evil%3Dvalue", {
        headers: { Cookie: "__Host-shtora.oidc-state-bad=bad" },
      })),
    ]);
    expect(responses.map(({ status }) => status)).toEqual([400, 400, 400, 400]);
    expect(responses[3]!.headers.get("set-cookie")).toBeNull();
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
  test("concurrent OIDC starts keep callback transactions and cookies isolated", async () => {
    const states = ["state_a", "state_b"];
    let nonceCount = 0;
    let verifierCount = 0;
    const checks: Array<{ state: string; verifier: string; expectedState: string; nonce: string }> = [];
    mock.module("openid-client", () => ({
      async discovery() { return {}; },
      randomState() { return states.shift()!; },
      randomNonce() { return `nonce_${++nonceCount}`; },
      randomPKCECodeVerifier() { return `verifier_${++verifierCount}`; },
      async calculatePKCECodeChallenge(verifier: string) { return `challenge-${verifier}`; },
      buildAuthorizationUrl(_client: unknown, parameters: Record<string, string>) {
        const url = new URL("https://issuer.example.test/authorize");
        for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, value);
        return url;
      },
      async authorizationCodeGrant(
        _client: unknown,
        callback: URL,
        validation: { pkceCodeVerifier: string; expectedState: string; expectedNonce: string },
      ) {
        checks.push({
          state: callback.searchParams.get("state")!,
          verifier: validation.pkceCodeVerifier,
          expectedState: validation.expectedState,
          nonce: validation.expectedNonce,
        });
        return { claims: () => ({ sub: "subject", iss: "https://issuer.example.test/" }) };
      },
    }));
    const transactions = new Map<string, {
      state: string;
      nonce: string;
      codeVerifier: string;
      expiresAtMs: number;
    }>();
    const consumed: string[] = [];
    const handler = createOidc({
      issuer: "https://issuer.example.test",
      clientId: "client",
      callbackUrl: "https://login.example.test/api/oidc/callback",
      successPath: "/account",
      transactions: {
        async create(transaction) { transactions.set(transaction.state, transaction); },
        async consume({ state }) {
          const transaction = transactions.get(state);
          if (!transaction) return null;
          transactions.delete(state);
          consumed.push(state);
          return transaction;
        },
        async deleteExpired() {},
      },
      async resolveUser() { return { id: "user" }; },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: true }; } },
    });
    const starts = await Promise.all([
      handler(new Request("https://login.example.test/start")),
      handler(new Request("https://login.example.test/start")),
    ]);
    const startData = starts.map((response) => {
      const location = new URL(response.headers.get("location")!);
      const cookie = response.headers.get("set-cookie")!.split(";")[0]!;
      return { state: location.searchParams.get("state")!, cookie };
    });
    const cookies = startData.map(({ cookie }) => cookie).join("; ");
    const callbacks = await Promise.all(startData.map(({ state }) =>
      handler(new Request(`https://login.example.test/api/oidc/callback?code=code&state=${state}`, {
        headers: { Host: "login.example.test", Cookie: cookies },
      })),
    ));

    expect(startData.map(({ state }) => state)).toEqual(["state_a", "state_b"]);
    expect(startData.map(({ cookie }) => cookie)).toEqual([
      "__Host-shtora.oidc-state-state_a=state_a",
      "__Host-shtora.oidc-state-state_b=state_b",
    ]);
    expect(callbacks.map(({ status }) => status)).toEqual([303, 303]);
    expect(callbacks.map((response) => response.headers.get("set-cookie")?.split(";")[0])).toEqual([
      "__Host-shtora.oidc-state-state_a=",
      "__Host-shtora.oidc-state-state_b=",
    ]);
    expect(consumed.sort()).toEqual(["state_a", "state_b"]);
    expect(checks.sort((left, right) => left.state.localeCompare(right.state))).toEqual([
      { state: "state_a", verifier: "verifier_1", expectedState: "state_a", nonce: "nonce_1" },
      { state: "state_b", verifier: "verifier_2", expectedState: "state_b", nonce: "nonce_2" },
    ]);
    expect(transactions.size).toBe(0);
  });
  test("WebAuthn pending-signup resolver completes registration without a session user", async () => {
    mock.module("@simplewebauthn/server", () => ({
      async generateRegistrationOptions(input: { userID: Uint8Array }) {
        return {
          challenge: "pending-challenge",
          rp: { name: "Example", id: "example.test" },
          userId: input.userID,
          publicKeyCredentialParameters: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {},
          timeout: 60000,
        };
      },
      async generateAuthenticationOptions() {
        return { challenge: "auth-challenge", rpId: "example.test", timeout: 60000, userVerification: "required" };
      },
      async verifyRegistrationResponse() {
        return {
          verified: true,
          registrationInfo: {
            credential: { id: "cred_pending", publicKey: "pkcs8", alg: -7, counter: 0, transports: [] },
            credentialDeviceType: "security-key",
            credentialBackedUp: false,
          },
        };
      },
      async verifyAuthenticationResponse() {
        return { verified: false, authenticationInfo: { newCounter: 0 } };
      },
    }));
    const pendingUser = { id: "pending_1", name: "pending@example.test", displayName: "Pending" };
    const entries = new Map<string, { purpose: "registration" | "authentication"; userId: string | null; value: string; expiresAtMs: number }>();
    const challenges: WebAuthnChallengeStore = {
      async create(challenge) { entries.set(challenge.id, challenge); },
      async consume({ id, purpose, userId, nowMs }) {
        const entry = entries.get(id);
        if (!entry || entry.purpose !== purpose || entry.userId !== userId || entry.expiresAtMs <= nowMs) return null;
        entries.delete(id);
        return { value: entry.value };
      },
      async deleteExpired() {},
    };
    const createdUserIds: string[] = [];
    const credentials: WebAuthnCredentialStore = {
      async listByUserId() { return []; },
      async findById() { return null; },
      async create({ userId }) { createdUserIds.push(userId); return true; },
      async updateCounter() { return false; },
    };
    const handler = createWebAuthn({
      expectedOrigin: webauthnOrigin,
      rpID: "example.test",
      rpName: "Example",
      challenges,
      credentials,
      async resolveRegistrationUser() { return null; },
      async resolvePendingRegistrationUser() { return pendingUser; },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: true }; } },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
    });

    const optionsResponse = await handler.handle(new Request(`${webauthnOrigin}/webauthn/registration/options`, {
      method: "POST",
      headers: { Origin: webauthnOrigin },
    }));
    const optionsBody = await optionsResponse.json() as { transactionId?: string; options?: { challenge?: string } };
    expect(optionsResponse.status).toBe(200);
    expect(typeof optionsBody.transactionId).toBe("string");
    expect(optionsBody.options?.challenge).toBe("pending-challenge");

    const verifyResponse = await handler.handle(new Request(`${webauthnOrigin}/webauthn/registration/verify`, {
      method: "POST",
      headers: { Origin: webauthnOrigin, "Content-Type": "application/json" },
      body: JSON.stringify({
        transactionId: optionsBody.transactionId,
        response: {
          id: "cred_pending",
          rawId: "cmVk",
          type: "public-key",
          clientDataJSON: "Y2xpZW50RGF0YQ",
          attestationObject: "YXR0ZXN0YXRpb24",
          transports: [],
        },
      }),
    }));
    expect(verifyResponse.status).toBe(200);
    expect(await verifyResponse.json()).toEqual({ verified: true });
    expect(createdUserIds).toEqual(["pending_1"]);
    expect(entries.size).toBe(0);
  });
  test("WebAuthn pending challenge cannot be consumed by a different session user", async () => {
    mock.module("@simplewebauthn/server", () => ({
      async generateRegistrationOptions(input: { userID: Uint8Array }) {
        return {
          challenge: "pending-only-challenge",
          rp: { name: "Example", id: "example.test" },
          userId: input.userID,
          publicKeyCredentialParameters: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {},
          timeout: 60000,
        };
      },
      async generateAuthenticationOptions() {
        return { challenge: "auth-challenge", rpId: "example.test", timeout: 60000, userVerification: "required" };
      },
      async verifyRegistrationResponse() {
        return {
          verified: true,
          registrationInfo: {
            credential: { id: "cred_pending", publicKey: "pkcs8", alg: -7, counter: 0, transports: [] },
            credentialDeviceType: "security-key",
            credentialBackedUp: false,
          },
        };
      },
      async verifyAuthenticationResponse() {
        return { verified: false, authenticationInfo: { newCounter: 0 } };
      },
    }));
    const pendingUser = { id: "pending_1", name: "pending@example.test", displayName: "Pending" };
    const sessionUser = { id: "session_2", name: "session@example.test", displayName: "Session" };
    let sessionActive = false;
    const entries = new Map<string, { purpose: "registration" | "authentication"; userId: string | null; value: string; expiresAtMs: number }>();
    const challenges: WebAuthnChallengeStore = {
      async create(challenge) { entries.set(challenge.id, challenge); },
      async consume({ id, purpose, userId, nowMs }) {
        const entry = entries.get(id);
        if (!entry || entry.purpose !== purpose || entry.userId !== userId || entry.expiresAtMs <= nowMs) return null;
        entries.delete(id);
        return { value: entry.value };
      },
      async deleteExpired() {},
    };
    const createdUserIds: string[] = [];
    const credentials: WebAuthnCredentialStore = {
      async listByUserId() { return []; },
      async findById() { return null; },
      async create({ userId }) { createdUserIds.push(userId); return true; },
      async updateCounter() { return false; },
    };
    const handler = createWebAuthn({
      expectedOrigin: webauthnOrigin,
      rpID: "example.test",
      rpName: "Example",
      challenges,
      credentials,
      async resolveRegistrationUser() { return sessionActive ? sessionUser : null; },
      async resolvePendingRegistrationUser() { return pendingUser; },
      async resolveClientIp() { return "192.0.2.10"; },
      rateLimiter: { async check() { return { allowed: true }; } },
      auth: { async createSessionResponse() { return new Response(null, { status: 200 }); } },
    });

    const optionsResponse = await handler.handle(new Request(`${webauthnOrigin}/webauthn/registration/options`, {
      method: "POST",
      headers: { Origin: webauthnOrigin },
    }));
    const optionsBody = await optionsResponse.json() as { transactionId?: string };
    expect(optionsResponse.status).toBe(200);
    expect(entries.values().next().value?.userId).toBe("pending_1");

    const verify = (session: boolean) => {
      sessionActive = session;
      return handler.handle(new Request(`${webauthnOrigin}/webauthn/registration/verify`, {
        method: "POST",
        headers: { Origin: webauthnOrigin, "Content-Type": "application/json" },
        body: JSON.stringify({
          transactionId: optionsBody.transactionId,
          response: {
            id: "cred_pending",
            rawId: "cmVk",
            type: "public-key",
            clientDataJSON: "Y2xpZW50RGF0YQ",
            attestationObject: "YXR0ZXN0YXRpb24",
            transports: [],
          },
        }),
      }));
    };

    const crossUser = await verify(true);
    expect(crossUser.status).toBe(400);
    expect(await crossUser.json()).toEqual({ error: "invalid_request" });
    expect(createdUserIds).toEqual([]);
    expect(entries.size).toBe(1);

    const pendingVerify = await verify(false);
    expect(pendingVerify.status).toBe(200);
    expect(await pendingVerify.json()).toEqual({ verified: true });
    expect(createdUserIds).toEqual(["pending_1"]);
  });
});
