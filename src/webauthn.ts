import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import type { AuthApi, AuthRequestRateLimitAction, AuthRequestRateLimiter, ExpiredRecordStore } from "./types.js";

export type WebAuthnChallengePurpose = "registration" | "authentication";

/** Stores must consume atomically and delete at most the requested number of expired challenges per cleanup call. */
export interface WebAuthnChallengeStore extends ExpiredRecordStore {
  create(challenge: {
    id: string;
    purpose: WebAuthnChallengePurpose;
    userId: string | null;
    value: string;
    expiresAtMs: number;
  }): Promise<void>;
  consume(input: {
    id: string;
    purpose: WebAuthnChallengePurpose;
    userId: string | null;
    nowMs: number;
  }): Promise<{ value: string } | null>;
}

/** The counter update must be atomic compare-and-set; create must enforce credential-ID uniqueness. */
export interface WebAuthnCredentialStore {
  listByUserId(userId: string): Promise<readonly WebAuthnCredential[]>;
  findById(id: string): Promise<{ userId: string; credential: WebAuthnCredential } | null>;
  create(input: { userId: string; credential: WebAuthnCredential }): Promise<boolean>;
  updateCounter(input: {
    id: string;
    expectedCounter: number;
    newCounter: number;
  }): Promise<boolean>;
}

export interface WebAuthnUser {
  /** Stable opaque application ID, encoded as UTF-8 and limited to 64 bytes. */
  id: string;
  name: string;
  displayName: string;
}

export interface WebAuthnOptions {
  /** Exact origin, including scheme and port; never inferred from an incoming request. */
  expectedOrigin: string;
  /** Exact RP ID configured by the relying party. */
  rpID: string;
  rpName: string;
  challenges: WebAuthnChallengeStore;
  credentials: WebAuthnCredentialStore;
  /** Return the authenticated application user for registration, or null. */
  resolveRegistrationUser(request: Request): Promise<WebAuthnUser | null>;
  /** Optional resolver for passkey-first signup; must resolve from server-side pending-signup state, never raw client input. */
  resolvePendingRegistrationUser?(request: Request): Promise<WebAuthnUser | null>;
  auth: Pick<AuthApi, "createSessionResponse">;
  resolveClientIp: (request: Request) => string | null | Promise<string | null>;
  rateLimiter: AuthRequestRateLimiter;
  challengeTtlMs?: number;
  onError?(input: { operation: string; error: unknown }): void | Promise<void>;
}

const defaultChallengeTtlMs = 5 * 60 * 1000;
const maxChallengeTtlMs = 15 * 60 * 1000;
const maxBodyBytes = 64 * 1024;

function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...Object.fromEntries(new Headers(headers)),
    },
  });
}

function reject(): Response {
  return json({ error: "invalid_request" }, 400);
}

function randomId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function hasSameOrigin(request: Request, expectedOrigin: string): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const parsed = new URL(origin);
    return parsed.origin === origin &&
      !parsed.username &&
      !parsed.password &&
      parsed.pathname === "/" &&
      !parsed.search &&
      !parsed.hash &&
      origin === expectedOrigin;
  } catch {
    return false;
  }
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const contentLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBodyBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || host.startsWith("127.");
}

async function report(options: WebAuthnOptions, operation: string, error: unknown): Promise<void> {
  try {
    await options.onError?.({ operation, error });
  } catch {
    // Error observers must not affect the generic public result.
  }
}

/** Creates framework-neutral WebAuthn registration and authentication HTTP handlers. */
export function createWebAuthn(options: WebAuthnOptions): {
  handle(request: Request): Promise<Response>;
  cleanupExpired(): Promise<void>;
} {
  let expectedOrigin: string;
  try {
    const parsed = new URL(options.expectedOrigin);
    const isSecureScheme = parsed.protocol === "https:";
    const isLocalHttp = parsed.protocol === "http:" && isLoopback(parsed.hostname);
    if (parsed.origin !== options.expectedOrigin || (!isSecureScheme && !isLocalHttp)) throw new TypeError();
    const hostname = parsed.hostname.toLowerCase();
    const rpID = options.rpID.toLowerCase();
    if (
      parsed.origin !== options.expectedOrigin ||
      (!isSecureScheme && !isLocalHttp) ||
      !rpID ||
      (hostname !== rpID && !hostname.endsWith(`.${rpID}`)) ||
      !options.rpName.trim()
    ) throw new TypeError();
    expectedOrigin = parsed.origin;
  } catch {
    throw new TypeError("expectedOrigin must be HTTPS (or localhost HTTP), rpID must match its host, and rpName must be non-empty");
  }
  const challengeTtlMs = options.challengeTtlMs ?? defaultChallengeTtlMs;
  if (!Number.isSafeInteger(challengeTtlMs) || challengeTtlMs < 1_000 || challengeTtlMs > maxChallengeTtlMs) {
    throw new RangeError("challengeTtlMs must be between 1000 and 900000");
  }

  async function createChallenge(purpose: WebAuthnChallengePurpose, userId: string | null, value: string): Promise<string> {
    const id = randomId();
    await options.challenges.create({
      id,
      purpose,
      userId,
      value,
      expiresAtMs: Date.now() + challengeTtlMs,
    });
    return id;
  }

  async function resolveRegistrationUserForRequest(request: Request): Promise<WebAuthnUser | null> {
    const user = await options.resolveRegistrationUser(request);
    if (user) return user;
    const pending = options.resolvePendingRegistrationUser;
    return pending ? await pending(request) : null;
  }

  async function registrationOptions(request: Request): Promise<Response> {
    const user = await resolveRegistrationUserForRequest(request);
    if (!user || !user.id || !user.name || !user.displayName) return json({ error: "unauthenticated" }, 401);
    const userID = new TextEncoder().encode(user.id);
    if (userID.byteLength > 64) throw new RangeError("WebAuthn user IDs must not exceed 64 UTF-8 bytes");
    const existing = await options.credentials.listByUserId(user.id);
    const publicKey = await generateRegistrationOptions({
      rpName: options.rpName,
      rpID: options.rpID,
      userID,
      userName: user.name,
      userDisplayName: user.displayName,
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      excludeCredentials: existing.map(({ id, transports }) => ({ id, transports })),
    });
    const transactionId = await createChallenge("registration", user.id, publicKey.challenge);
    return json({ transactionId, options: publicKey });
  }

  async function registrationVerify(request: Request): Promise<Response> {
    const body = await readJson(request);
    if (!body || typeof body.transactionId !== "string" || !body.response || typeof body.response !== "object") return reject();
    const user = await resolveRegistrationUserForRequest(request);
    if (!user) return json({ error: "unauthenticated" }, 401);
    const transaction = await options.challenges.consume({
      id: body.transactionId,
      purpose: "registration",
      userId: user.id,
      nowMs: Date.now(),
    });
    if (!transaction) return reject();
    let verification: VerifiedRegistrationResponse;
    try {
      verification = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge: transaction.value,
        expectedOrigin,
        expectedRPID: options.rpID,
        requireUserVerification: true,
      });
    } catch {
      return reject();
    }
    if (!verification.verified || !verification.registrationInfo) return reject();
    const { credential } = verification.registrationInfo;
    if (!(await options.credentials.create({ userId: user.id, credential }))) return reject();
    return json({ verified: true });
  }

  async function authenticationOptions(): Promise<Response> {
    const publicKey = await generateAuthenticationOptions({
      rpID: options.rpID,
      userVerification: "required",
    });
    const transactionId = await createChallenge("authentication", null, publicKey.challenge);
    return json({ transactionId, options: publicKey });
  }

  async function authenticationVerify(request: Request): Promise<Response> {
    const body = await readJson(request);
    if (
      !body || typeof body.transactionId !== "string" || !body.response || typeof body.response !== "object" ||
      typeof (body.response as Record<string, unknown>).id !== "string"
    ) return reject();
    const response = body.response as AuthenticationResponseJSON;
    const transaction = await options.challenges.consume({
      id: body.transactionId,
      purpose: "authentication",
      userId: null,
      nowMs: Date.now(),
    });
    if (!transaction) return reject();
    const stored = await options.credentials.findById(response.id);
    if (!stored || stored.credential.id !== response.id) return reject();
    let verification: VerifiedAuthenticationResponse;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: transaction.value,
        expectedOrigin,
        expectedRPID: options.rpID,
        credential: stored.credential,
        requireUserVerification: true,
      });
    } catch {
      return reject();
    }
    if (!verification.verified) return reject();
    const updated = await options.credentials.updateCounter({
      id: stored.credential.id,
      expectedCounter: stored.credential.counter,
      newCounter: verification.authenticationInfo.newCounter,
    });
    if (!updated) return reject();
    const session = await options.auth.createSessionResponse(request, stored.userId);
    if (session.status === 200) return session;
    return json({ error: "unauthenticated" }, session.status === 403 ? 403 : 401);
  }

  async function handle(request: Request): Promise<Response> {
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
    if (!hasSameOrigin(request, expectedOrigin)) return json({ error: "invalid_origin" }, 403);
    const path = new URL(request.url).pathname;
    const routes: Record<string, {
      operation: string;
      rateLimitAction: AuthRequestRateLimitAction;
      run: () => Promise<Response>;
    }> = {
      "/webauthn/registration/options": {
        operation: "registration.options",
        rateLimitAction: "webauthn-registration-options",
        run: () => registrationOptions(request),
      },
      "/webauthn/registration/verify": {
        operation: "registration.verify",
        rateLimitAction: "webauthn-registration-verify",
        run: () => registrationVerify(request),
      },
      "/webauthn/authentication/options": {
        operation: "authentication.options",
        rateLimitAction: "webauthn-authentication-options",
        run: authenticationOptions,
      },
      "/webauthn/authentication/verify": {
        operation: "authentication.verify",
        rateLimitAction: "webauthn-authentication-verify",
        run: () => authenticationVerify(request),
      },
    };
    const route = routes[path];
    if (!route) return json({ error: "not_found" }, 404);
    try {
      const ip = await options.resolveClientIp(request);
      const decision = ip
        ? await options.rateLimiter.check({ action: route.rateLimitAction, ip })
        : { allowed: false, retryAfterSeconds: 60 };
      if (!decision.allowed) {
        const seconds = Number.isSafeInteger(decision.retryAfterSeconds) && decision.retryAfterSeconds! > 0
          ? decision.retryAfterSeconds!
          : 60;
        return json({ error: "rate_limited" }, 429, { "Retry-After": String(seconds) });
      }
      return await route.run();
    } catch (error) {
      await report(options, route.operation, error);
      return json({ error: "internal_error" }, 500);
    }
  }

  return {
    handle,
    async cleanupExpired() {
      try {
        await options.challenges.deleteExpired({ nowMs: Date.now(), limit: 500 });
      } catch (error) {
        await report(options, "challenge.cleanup", error);
        throw error;
      }
    },
  };
}
