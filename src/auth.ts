import { clearedSessionCookie, readSessionToken, sessionCookie } from "./cookies.js";
import { createSessionToken, hashSessionToken } from "./crypto.js";
import { parseActionTokenRequest, parseCredentials, parseEmailRequest, parsePasswordReset, readJson, RequestError } from "./request.js";
import type {
  AccessPolicy,
  AuthActionTokenPurpose,
  AuthActionTokenStore,
  AuthApi,
  AuthenticatedUser,
  AuthOptions,
  AuthUser,
  AuthActionTokenDelivery,
  StoredSession,
  ExpiredRecordStore,
} from "./types.js";

const defaultBasePath = "/api/auth";
const defaultCookieName = "__Host-shtora.session";
const defaultSessionTtl = 60 * 60 * 24 * 7;
const maxSessionTtl = 60 * 60 * 24 * 365;
const defaultMaxRequestBytes = 8192;

const defaultVerificationTokenTtl = 60 * 60;
const defaultResetTokenTtl = 15 * 60;
const maxActionTokenTtl = 60 * 60 * 24;

export function createAuth<User extends AuthUser>(options: AuthOptions<User>): AuthApi {
  const basePath = options.basePath ?? defaultBasePath;
  const cookieName = options.cookieName ?? defaultCookieName;
  const sessionTtlSeconds = options.sessionTtlSeconds ?? defaultSessionTtl;
  const maxRequestBytes = options.maxRequestBytes ?? defaultMaxRequestBytes;
  const requireOrigin = options.requireOrigin ?? true;

  if (!basePath.startsWith("/") || basePath.endsWith("/") || basePath.includes("?")) {
    throw new TypeError("basePath must start with '/' and must not end with '/'");
  }
  if (!/^__Host-[A-Za-z0-9._-]+$/.test(cookieName)) {
    throw new TypeError("cookieName must use the __Host- prefix");
  }
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds < 1 || sessionTtlSeconds > maxSessionTtl) {
    throw new RangeError("sessionTtlSeconds must be between 1 and 31536000");
  }
  if (!Number.isInteger(maxRequestBytes) || maxRequestBytes < 1 || maxRequestBytes > 1024 * 1024) {
    throw new RangeError("maxRequestBytes must be between 1 and 1048576");
  }
  if ((options.ipPolicy || options.rateLimiter) && !options.resolveClientIp) {
    throw new TypeError("resolveClientIp is required when ipPolicy or rateLimiter is configured");
  }
  for (const ttl of [options.emailVerification?.tokenTtlSeconds, options.passwordReset?.tokenTtlSeconds]) {
    if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 1 || ttl > maxActionTokenTtl)) {
      throw new RangeError("tokenTtlSeconds must be between 1 and 86400");
    }
  }

  async function isAllowed(policy: AccessPolicy | undefined, value: string, request: Request): Promise<boolean> {
    return policy ? policy.allow({ value, request }) : true;
  }

  async function clientIp(request: Request): Promise<string | null> {
    const ip = await options.resolveClientIp!(request);
    return typeof ip === "string" && ip.length > 0 ? ip : null;
  }

  async function report(operation: string, error: unknown): Promise<void> {
    try {
      await options.onError?.({ operation, error });
    } catch {
      // Observers must not affect the public result.
    }
  }

  function response(body: unknown, status: number, headers?: HeadersInit): Response {
    const responseHeaders = new Headers(headers);
    responseHeaders.set("Cache-Control", "no-store");
    responseHeaders.set("Content-Type", "application/json; charset=utf-8");
    responseHeaders.set("X-Content-Type-Options", "nosniff");
    responseHeaders.set("Vary", "Cookie");
    return new Response(JSON.stringify(body), { status, headers: responseHeaders });
  }

  function errorResponse(error: unknown): Response {
    if (error instanceof RequestError) return response({ error: error.code }, error.status);
    return response({ error: "internal_error" }, 500);
  }

  function hostIsAllowed(request: Request): boolean {
    if (!options.allowedHosts) return true;
    const host = request.headers.get("host");
    if (!host || host.includes(",")) return false;
    try {
      const parsed = new URL(`https://${host}`);
      return parsed.pathname === "/" && !parsed.username && !parsed.password &&
        options.allowedHosts.some((allowed) => allowed.toLowerCase() === parsed.host.toLowerCase());
    } catch {
      return false;
    }
  }

  function originIsAllowed(request: Request): boolean {
    const origin = request.headers.get("origin");
    if (!origin) return !requireOrigin;

    try {
      const parsedOrigin = new URL(origin);
      const normalizedOrigin = parsedOrigin.origin.toLowerCase();
      if (
        parsedOrigin.username ||
        parsedOrigin.password ||
        parsedOrigin.pathname !== "/" ||
        parsedOrigin.search ||
        parsedOrigin.hash ||
        origin.toLowerCase() !== normalizedOrigin
      ) return false;

      const requestUrl = new URL(request.url);
      const host = request.headers.get("host");
      const expectedOrigin = host ? new URL(`${requestUrl.protocol}//${host}`).origin : requestUrl.origin;
      return normalizedOrigin === expectedOrigin.toLowerCase();
    } catch {
      return false;
    }
  }

  function publicUser(user: User): AuthenticatedUser {
    if (typeof user.id !== "string" || user.id.length === 0 || typeof user.email !== "string") {
      throw new TypeError("UserStore returned an invalid user");
    }
    return { id: user.id, email: user.email };
  }

  async function getSession(request: Request): Promise<AuthenticatedUser | null> {
    try {
      const token = readSessionToken(request.headers.get("cookie"), cookieName);
      if (!token) return null;
      const tokenHash = await hashSessionToken(token);
      const stored = await options.sessions.findByTokenHash(tokenHash);
      const now = Date.now();
      if (!stored || stored.tokenHash !== tokenHash || !Number.isFinite(stored.expiresAtMs) || stored.expiresAtMs <= now) {
        if (stored?.tokenHash === tokenHash) await options.sessions.deleteByTokenHash(tokenHash);
        return null;
      }

      const user = await options.users.findById(stored.userId);
      if (!user) {
        await options.sessions.deleteByTokenHash(tokenHash);
        return null;
      }
      if (options.emailVerification && !options.emailVerification.isVerified(user)) return null;
      if (!(await isAllowed(options.emailPolicy, user.email, request))) return null;
      if (options.ipPolicy) {
        const ip = await clientIp(request);
        if (!ip || !(await isAllowed(options.ipPolicy, ip, request))) return null;
      }
      return publicUser(user);
    } catch (error) {
      if (!(error instanceof RequestError)) await report("getSession", error);
      throw error;
    }
  }

  async function rateLimit(
    action: "register" | "login" | "email-verification" | "password-reset",
    email: string,
    request: Request,
  ): Promise<Response | null> {
    if (!options.rateLimiter) return null;
    const ip = await clientIp(request);
    if (!ip) {
      if (action === "login") return response({ error: "invalid_credentials" }, 401);
      return response({ status: "accepted" }, 202);
    }
    const result = await options.rateLimiter.check({ action, email, ip });
    if (result.allowed) return null;
    const seconds = Number.isInteger(result.retryAfterSeconds) && result.retryAfterSeconds! > 0
      ? result.retryAfterSeconds!
      : 60;
    return response({ error: "rate_limited" }, 429, { "Retry-After": String(seconds) });
  }

  async function issueActionToken(
    purpose: AuthActionTokenPurpose,
    userId: string,
    email: string,
    tokens: AuthActionTokenStore,
    delivery: AuthActionTokenDelivery,
    defaultTtlSeconds: number,
    operation: string,
  ): Promise<void> {
    try {
      const token = createSessionToken();
      const expiresAtMs = Date.now() + (delivery.tokenTtlSeconds ?? defaultTtlSeconds) * 1000;
      await tokens.create({ purpose, userId, tokenHash: await hashSessionToken(token), expiresAtMs });
      await delivery.send({ email, token, expiresAtMs });
    } catch (error) {
      await report(operation, error);
    }
  }

  async function passPolicies(email: string, request: Request): Promise<boolean> {
    if (!(await isAllowed(options.emailPolicy, email, request))) return false;
    if (!options.ipPolicy) return true;
    const ip = await clientIp(request);
    return ip !== null && isAllowed(options.ipPolicy, ip, request);
  }

  async function register(request: Request): Promise<Response> {
    const credentials = parseCredentials(await readJson(request, maxRequestBytes));
    const limited = await rateLimit("register", credentials.email, request);
    if (limited) return limited;
    if (!(await passPolicies(credentials.email, request))) return response({ status: "accepted" }, 202);
    const created = await options.users.create({ email: credentials.email, password: credentials.password });
    if (created.created) {
      if (!created.user) throw new TypeError("UserStore must return the created user");
      if (options.emailVerification) {
        await issueActionToken(
          "email-verification",
          created.user.id,
          created.user.email,
          options.emailVerification.tokens,
          options.emailVerification,
          defaultVerificationTokenTtl,
          "email-verification.send",
        );
      }
    }
    return response({ status: "accepted" }, 202);
  }

  async function requestEmailVerification(request: Request): Promise<Response> {
    const flow = options.emailVerification;
    if (!flow) return response({ error: "not_found" }, 404);
    const email = parseEmailRequest(await readJson(request, maxRequestBytes));
    const limited = await rateLimit("email-verification", email, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ status: "accepted" }, 202);

    const user = await options.users.findByEmail(email);
    if (user && !flow.isVerified(user)) {
      await issueActionToken(
        "email-verification",
        user.id,
        user.email,
        flow.tokens,
        flow,
        defaultVerificationTokenTtl,
        "email-verification.send",
      );
    }
    return response({ status: "accepted" }, 202);
  }

  async function confirmEmailVerification(request: Request): Promise<Response> {
    const flow = options.emailVerification;
    if (!flow) return response({ error: "not_found" }, 404);
    const token = parseActionTokenRequest(await readJson(request, maxRequestBytes));
    const consumed = await flow.tokens.consume({
      purpose: "email-verification",
      tokenHash: await hashSessionToken(token),
      nowMs: Date.now(),
    });
    if (!consumed) return response({ error: "invalid_token" }, 400);
    const user = await options.users.findById(consumed.userId);
    if (!user) return response({ error: "invalid_token" }, 400);
    await flow.markVerified(user.id);
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  async function requestPasswordReset(request: Request): Promise<Response> {
    const flow = options.passwordReset;
    if (!flow) return response({ error: "not_found" }, 404);
    const email = parseEmailRequest(await readJson(request, maxRequestBytes));
    const limited = await rateLimit("password-reset", email, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ status: "accepted" }, 202);

    const user = await options.users.findByEmail(email);
    if (user) {
      await issueActionToken(
        "password-reset",
        user.id,
        user.email,
        flow.tokens,
        flow,
        defaultResetTokenTtl,
        "password-reset.send",
      );
    }
    return response({ status: "accepted" }, 202);
  }

  async function confirmPasswordReset(request: Request): Promise<Response> {
    const flow = options.passwordReset;
    if (!flow) return response({ error: "not_found" }, 404);
    const { token, password } = parsePasswordReset(await readJson(request, maxRequestBytes));
    const consumed = await flow.tokens.consume({
      purpose: "password-reset",
      tokenHash: await hashSessionToken(token),
      nowMs: Date.now(),
    });
    if (!consumed) return response({ error: "invalid_token" }, 400);
    const user = await options.users.findById(consumed.userId);
    if (!user) return response({ error: "invalid_token" }, 400);

    await options.sessions.deleteByUserId(user.id);
    await flow.setPassword({ userId: user.id, password });
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  async function createSessionForUser(user: User): Promise<Response> {
    const token = createSessionToken();
    const tokenHash = await hashSessionToken(token);
    const now = Date.now();
    const session: StoredSession = {
      id: createSessionToken(),
      tokenHash,
      userId: user.id,
      createdAtMs: now,
      expiresAtMs: now + sessionTtlSeconds * 1000,
    };
    await options.sessions.create(session);
    return response({ user: publicUser(user) }, 200, {
      "Set-Cookie": sessionCookie(token, cookieName, sessionTtlSeconds, now),
    });
  }

  async function createSessionResponse(request: Request, userId: string): Promise<Response> {
    try {
      if (!hostIsAllowed(request)) return response({ error: "invalid_host" }, 403);
      const user = await options.users.findById(userId);
      if (
        !user ||
        (options.emailVerification && !options.emailVerification.isVerified(user)) ||
        !(await passPolicies(user.email, request))
      ) {
        return response({ error: "unauthenticated" }, 401);
      }
      return await createSessionForUser(user);
    } catch (error) {
      if (!(error instanceof RequestError)) await report("createSessionResponse", error);
      throw error;
    }
  }

  async function login(request: Request): Promise<Response> {
    const { email, password } = parseCredentials(await readJson(request, maxRequestBytes));
    const limited = await rateLimit("login", email, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ error: "invalid_credentials" }, 401);

    const user = await options.users.findByEmail(email);
    const verified = await options.credentials.verify({ email, password, user });
    if (!user || !verified || (options.emailVerification && !options.emailVerification.isVerified(user))) {
      return response({ error: "invalid_credentials" }, 401);
    }

    return createSessionForUser(user);
  }

  async function logout(request: Request): Promise<Response> {
    const token = readSessionToken(request.headers.get("cookie"), cookieName);
    if (token) await options.sessions.deleteByTokenHash(await hashSessionToken(token));
    return new Response(null, {
      status: 204,
      headers: { "Cache-Control": "no-store", "Set-Cookie": clearedSessionCookie(cookieName) },
    });
  }

  async function cleanupExpired(): Promise<void> {
    const stores = new Set<ExpiredRecordStore>([options.sessions]);
    if (options.emailVerification) stores.add(options.emailVerification.tokens);
    if (options.passwordReset) stores.add(options.passwordReset.tokens);
    const nowMs = Date.now();
    try {
      await Promise.all([...stores].map((store) => store.deleteExpired({ nowMs, limit: 500 })));
    } catch (error) {
      await report("cleanupExpired", error);
      throw error;
    }
  }

  async function handle(request: Request): Promise<Response> {
    if (!hostIsAllowed(request)) return response({ error: "invalid_host" }, 403);
    const { pathname } = new URL(request.url);
    if (!pathname.startsWith(`${basePath}/`)) return response({ error: "not_found" }, 404);

    const route = pathname.slice(basePath.length);
    const method = request.method.toUpperCase();
    if (route === "/session" && method === "GET") {
      if (!originIsAllowed(request) && request.headers.has("origin")) return response({ error: "invalid_origin" }, 403);
      try {
        const user = await getSession(request);
        return user ? response({ user }, 200) : response({ error: "unauthenticated" }, 401);
      } catch (error) {
        return errorResponse(error);
      }
    }

    if (route === "/sessions" || /^\/sessions\/[^/]+$/.test(route)) {
      if ((route === "/sessions" && !["GET", "DELETE"].includes(method)) ||
        (route !== "/sessions" && method !== "DELETE")) {
        return response({ error: "method_not_allowed" }, 405, { Allow: route === "/sessions" ? "GET, DELETE" : "DELETE" });
      }
      if ((method !== "GET" || request.headers.has("origin")) && !originIsAllowed(request)) {
        return response({ error: "invalid_origin" }, 403);
      }

      let user: AuthenticatedUser | null;
      try {
        user = await getSession(request);
      } catch (error) {
        return errorResponse(error);
      }
      if (!user) return response({ error: "unauthenticated" }, 401);

      try {
        if (route === "/sessions" && method === "GET") {
          const sessions = (await options.sessions.listByUserId(user.id)).filter((session) => session.expiresAtMs > Date.now());
          return response({ sessions: sessions.map(({ id, createdAtMs, expiresAtMs }) => ({ id, createdAtMs, expiresAtMs })) }, 200);
        }
        if (route === "/sessions") {
          await options.sessions.deleteByUserId(user.id);
          return new Response(null, {
            status: 204,
            headers: { "Set-Cookie": clearedSessionCookie(cookieName) },
          });
        }
        await options.sessions.deleteByIdForUser(route.slice("/sessions/".length), user.id);
        return new Response(null, { status: 204 });
      } catch (error) {
        if (!(error instanceof RequestError)) await report(`sessions.${method.toLowerCase()}`, error);
        return errorResponse(error);
      }
    }

    const emailVerificationRoute = route === "/email-verification/request" || route === "/email-verification/confirm";
    const passwordResetRoute = route === "/password-reset/request" || route === "/password-reset/confirm";
    const enabled = ["/register", "/login", "/logout"].includes(route) ||
      (emailVerificationRoute && !!options.emailVerification) ||
      (passwordResetRoute && !!options.passwordReset);
    if (!enabled) return response({ error: "not_found" }, 404);
    if (method !== "POST") return response({ error: "method_not_allowed" }, 405, { Allow: "POST" });
    if (!originIsAllowed(request)) return response({ error: "invalid_origin" }, 403);
    try {
      if (route === "/register") return await register(request);
      if (route === "/login") return await login(request);
      if (route === "/logout") return await logout(request);
      if (route === "/email-verification/request") return await requestEmailVerification(request);
      if (route === "/email-verification/confirm") return await confirmEmailVerification(request);
      if (route === "/password-reset/request") return await requestPasswordReset(request);
      return await confirmPasswordReset(request);
    } catch (error) {
      if (!(error instanceof RequestError)) await report(route.slice(1), error);
      return errorResponse(error);
    }
  }

  return { handle, cleanupExpired, getSession, createSessionResponse };
}
