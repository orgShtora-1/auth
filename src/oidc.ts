import * as oidc from "openid-client";
import type { AuthApi, AuthRequestRateLimiter, AuthUser, ExpiredRecordStore } from "./types.js";

export interface OidcTransaction {
  readonly state: string;
  readonly codeVerifier: string;
  readonly nonce: string;
  readonly expiresAtMs: number;
}

/** Stores must consume atomically and delete at most the requested number of expired records per cleanup call. */
export interface OidcTransactionStore extends ExpiredRecordStore {
  create(transaction: OidcTransaction): Promise<void>;
  consume(input: { state: string; nowMs: number }): Promise<OidcTransaction | null>;
}

export interface OidcHandler {
  (request: Request): Promise<Response>;
  cleanupExpired(): Promise<void>;
}

export interface OidcConfig<User extends AuthUser> {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret?: string;
  /** Absolute, pre-registered callback URL. */
  readonly callbackUrl: string;
  /** Fixed same-origin path after success, e.g. "/account". */
  readonly successPath: string;
  readonly transactions: OidcTransactionStore;
  readonly resolveUser: (identity: { issuer: string; subject: string }) => Promise<User | null>;
  readonly auth: Pick<AuthApi, "createSessionResponse">;
  readonly resolveClientIp: (request: Request) => string | null | Promise<string | null>;
  readonly rateLimiter: AuthRequestRateLimiter;
  readonly transactionTtlSeconds?: number;
  readonly scope?: string;
  readonly onError?: (input: { operation: "start" | "callback" | "cleanup"; error: unknown }) => void | Promise<void>;
}

const cookieName = "__Host-shtora.oidc-state";
const defaultTtlSeconds = 600;

/** Creates a Web-Request handler for GET /start and GET /callback. */
export function createOidc<User extends AuthUser>(options: OidcConfig<User>): OidcHandler {
  const issuerUrl = new URL(options.issuer);
  const callbackUrl = new URL(options.callbackUrl);
  if (issuerUrl.protocol !== "https:" || issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash) {
    throw new TypeError("issuer must be an HTTPS issuer URL without credentials, query, or fragment");
  }
  if (callbackUrl.protocol !== "https:" || callbackUrl.username || callbackUrl.password || callbackUrl.search || callbackUrl.hash) {
    throw new TypeError("callbackUrl must be an HTTPS URL without credentials, query, or fragment");
  }
  if (!options.successPath.startsWith("/") || options.successPath.startsWith("//") || /[?#\\]/.test(options.successPath)) {
    throw new TypeError("successPath must be a fixed absolute same-origin path");
  }
  const ttl = options.transactionTtlSeconds ?? defaultTtlSeconds;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) throw new RangeError("transactionTtlSeconds must be between 1 and 3600");

  let configPromise: Promise<oidc.Configuration> | undefined;
  const getConfig = async (): Promise<oidc.Configuration> => {
    configPromise ??= oidc.discovery(issuerUrl, options.clientId, options.clientSecret);
    try {
      return await configPromise;
    } catch (error) {
      configPromise = undefined;
      throw error;
    }
  };
  const cookie = (state: string, maxAge: number): string =>
    `${cookieName}=${state}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
  const clearCookie = `${cookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
  const readStateCookie = (request: Request): string | null => {
    let found: string | null = null;
    for (const value of (request.headers.get("cookie") ?? "").split(";")) {
      const pair = value.trim();
      const equals = pair.indexOf("=");
      if (equals < 0 || pair.slice(0, equals) !== cookieName) continue;
      if (found !== null) return null;
      found = pair.slice(equals + 1);
    }
    return found;
  };
  const callbackRequestUrl = (request: Request): URL | null => {
    const host = request.headers.get("host");
    if (host) {
      try {
        const requestAuthority = new URL(`https://${host}`);
        if (requestAuthority.host !== callbackUrl.host || requestAuthority.username || requestAuthority.password ||
            requestAuthority.pathname !== "/" || requestAuthority.search || requestAuthority.hash) return null;
      } catch {
        return null;
      }
    }
    const incoming = new URL(request.url);
    if (incoming.pathname !== callbackUrl.pathname) return null;
    const callback = new URL(options.callbackUrl);
    const allowed = new Set(["code", "state", "iss", "error", "error_description", "error_uri", "session_state"]);
    for (const key of new Set(incoming.searchParams.keys())) {
      const values = incoming.searchParams.getAll(key);
      if (!allowed.has(key) || values.length !== 1) return null;
      callback.searchParams.set(key, values[0]!);
    }
    return callback;
  };
  const report = async (operation: "start" | "callback" | "cleanup", error: unknown) => {
    try { await options.onError?.({ operation, error }); } catch { /* observer failures do not affect the response */ }
  };
  const failure = (headers?: HeadersInit, status = 400) => new Response("Sign-in failed", {
    status,
    headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8", ...Object.fromEntries(new Headers(headers)) },
  });
  const rateLimited = async (
    action: "oidc-start" | "oidc-callback",
    request: Request,
    headers?: Headers,
  ): Promise<Response | null> => {
    try {
      const ip = await options.resolveClientIp(request);
      const decision = ip ? await options.rateLimiter.check({ action, ip }) : { allowed: false, retryAfterSeconds: 60 };
      if (decision.allowed) return null;
      const seconds = Number.isSafeInteger(decision.retryAfterSeconds) && decision.retryAfterSeconds! > 0
        ? decision.retryAfterSeconds!
        : 60;
      const responseHeaders = new Headers(headers);
      responseHeaders.set("Retry-After", String(seconds));
      return failure(responseHeaders, 429);
    } catch (error) {
      await report(action === "oidc-start" ? "start" : "callback", error);
      return failure(headers, 503);
    }
  };

  const handler = async (request: Request): Promise<Response> => {

    const current = new URL(request.url);
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET", "Cache-Control": "no-store" } });
    if (current.pathname === new URL(options.callbackUrl).pathname) {
      const headers = new Headers({ "Cache-Control": "no-store", "Set-Cookie": clearCookie });
      try {
        const limited = await rateLimited("oidc-callback", request, headers);
        if (limited) return limited;
        const callbackRequest = callbackRequestUrl(request);
        if (!callbackRequest) return failure(headers);
        const state = callbackRequest.searchParams.get("state");
        const browserState = readStateCookie(request);
        if (!state || !browserState || state !== browserState) return failure(headers);
        const transaction = await options.transactions.consume({ state, nowMs: Date.now() });
        if (!transaction || transaction.state !== state || transaction.expiresAtMs <= Date.now()) return failure(headers);
        const client = await getConfig();
        const tokens = await oidc.authorizationCodeGrant(
          client,
          callbackRequest,
          {
            pkceCodeVerifier: transaction.codeVerifier,
            expectedState: transaction.state,
            expectedNonce: transaction.nonce,
            idTokenExpected: true,
          },
          { redirect_uri: options.callbackUrl },
        );
        const claims = tokens.claims();
        if (!claims?.sub || claims.iss !== issuerUrl.href) return failure(headers);
        const user = await options.resolveUser({ issuer: claims.iss, subject: claims.sub });
        if (!user) return failure(headers);
        const sessionResponse = await options.auth.createSessionResponse(request, user.id);
        if (sessionResponse.status !== 200) {
          return failure(headers, sessionResponse.status >= 500 ? 500 : 400);
        }
        const responseHeaders = new Headers(sessionResponse.headers);
        responseHeaders.append("Set-Cookie", clearCookie);
        responseHeaders.set("Location", new URL(options.successPath, callbackUrl.origin).href);
        responseHeaders.set("Cache-Control", "no-store");
        return new Response(null, { status: 303, headers: responseHeaders });
      } catch (error) {
        await report("callback", error);
        return failure(headers);
      }
    }

    if (current.pathname !== new URL(callbackUrl.origin + "/start").pathname) {
      return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    }
    try {
      const limited = await rateLimited("oidc-start", request);
      if (limited) return limited;
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      await options.transactions.create({ state, nonce, codeVerifier, expiresAtMs: Date.now() + ttl * 1000 });
      const client = await getConfig();
      const destination = oidc.buildAuthorizationUrl(client, {
        redirect_uri: options.callbackUrl,
        scope: options.scope ?? "openid email",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });
      return new Response(null, { status: 302, headers: {
        Location: destination.href,
        "Set-Cookie": cookie(state, ttl),
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
      } });
    } catch (error) {
      await report("start", error);
      return failure();
    }
  };
  return Object.assign(handler, {
    async cleanupExpired() {
      try {
        await options.transactions.deleteExpired({ nowMs: Date.now(), limit: 500 });
      } catch (error) {
        await report("cleanup", error);
        throw error;
      }
    },
  });
}
