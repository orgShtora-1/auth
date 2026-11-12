import { clearedSessionCookie, readSessionToken, sessionCookie } from "./cookies.js";
import { createSessionToken, hashSessionToken } from "./crypto.js";
import { objectFields, parseActionTokenRequest, parseEmailRequest, parseLoginCredentials, parseOtpCode, parsePasswordReset, parseRegistrationCredentials, parseTotpVerifyRequest, readJson, RequestError } from "./request.js";
import { createOtpauthUri, createRecoveryCodes, createTotpSecret, normalizeRecoveryCode, verifyTotp } from "./totp.js";
import type {
  AccessPolicy,
  AuthActionTokenPurpose,
  AuthActionTokenStore,
  AuthApi,
  AuthIdentifier,
  TotpRecord,
  AuthenticatedSession,
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
const defaultChallengeTtlSeconds = 300;
const defaultMagicLinkTtlSeconds = 900;
const defaultTotpDigits = 6;
const defaultTotpPeriodSeconds = 30;
const defaultTotpSkew = 1;
const defaultRecoveryCodeCount = 10;

const defaultPasswordPolicy = { minLength: 15, maxLength: 4096 };
const hardMaxPasswordLength = 4096;
export function createAuth<User extends AuthUser>(options: AuthOptions<User>): AuthApi {
  const basePath = options.basePath ?? defaultBasePath;
  const cookieName = options.cookieName ?? defaultCookieName;
  const sessionTtlSeconds = options.sessionTtlSeconds ?? defaultSessionTtl;
  const maxRequestBytes = options.maxRequestBytes ?? defaultMaxRequestBytes;
  const requireOrigin = options.requireOrigin ?? true;
  const registrationMode = options.identity?.registration ?? "email";
  const loginMode = options.identity?.login ?? "email";
  const passwordPolicy = { ...defaultPasswordPolicy, ...options.passwordPolicy };
  if (!["email", "username", "both", "either"].includes(registrationMode) ||
      !["email", "username", "either"].includes(loginMode)) {
    throw new TypeError("identity modes are invalid");
  }
  if ((registrationMode === "email" && loginMode !== "email") ||
      (registrationMode === "username" && loginMode !== "username") ||
      (registrationMode === "either" && loginMode !== "either")) {
    throw new TypeError("identity login mode is incompatible with registration mode");
  }
  if (!Number.isInteger(passwordPolicy.minLength) || passwordPolicy.minLength < 1 ||
      !Number.isInteger(passwordPolicy.maxLength) || passwordPolicy.maxLength > hardMaxPasswordLength ||
      passwordPolicy.maxLength < passwordPolicy.minLength) {
    throw new RangeError("passwordPolicy lengths must be integers between 1 and 4096 with minLength <= maxLength");
  }
  for (const flag of [
    options.passwordPolicy?.requireUppercase,
    options.passwordPolicy?.requireLowercase,
    options.passwordPolicy?.requireSpecial,
  ]) {
    if (flag !== undefined && typeof flag !== "boolean") throw new TypeError("passwordPolicy requirements must be booleans");
  }
  if (options.emailVerification && registrationMode !== "email" && registrationMode !== "both") {
    throw new TypeError("emailVerification requires registration mode 'email' or 'both'");
  }

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
  for (const ttl of [options.emailVerification?.tokenTtlSeconds, options.passwordReset?.tokenTtlSeconds,
    options.magicLink?.delivery.tokenTtlSeconds]) {
    if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 1 || ttl > maxActionTokenTtl)) {
      throw new RangeError("tokenTtlSeconds must be between 1 and 86400");
    }
  }
  if (options.sessionIdleSeconds !== undefined &&
      (!Number.isInteger(options.sessionIdleSeconds) || options.sessionIdleSeconds < 1)) {
    throw new RangeError("sessionIdleSeconds must be a positive integer");
  }
  if (options.sessionIdleSeconds !== undefined && !options.sessions.refreshExpiry) {
    throw new TypeError("sessions.refreshExpiry is required when sessionIdleSeconds is configured");
  }
  if (options.sessionRotationSeconds !== undefined &&
      (!Number.isInteger(options.sessionRotationSeconds) || options.sessionRotationSeconds < 1)) {
    throw new RangeError("sessionRotationSeconds must be a positive integer");
  }
  const totpOptions = options.totp && {
    ...options.totp,
    digits: options.totp.digits ?? defaultTotpDigits,
    periodSeconds: options.totp.periodSeconds ?? defaultTotpPeriodSeconds,
    skew: options.totp.skew ?? defaultTotpSkew,
    recoveryCodeCount: options.totp.recoveryCodeCount ?? defaultRecoveryCodeCount,
  };
  if (totpOptions) {
    if (typeof totpOptions.issuer !== "string" || totpOptions.issuer.length === 0) {
      throw new TypeError("totp.issuer must be a non-empty string");
    }
    if (totpOptions.digits !== 6 && totpOptions.digits !== 8) throw new TypeError("totp.digits must be 6 or 8");
    if (!Number.isInteger(totpOptions.periodSeconds) || totpOptions.periodSeconds < 1) {
      throw new RangeError("totp.periodSeconds must be a positive integer");
    }
    if (!Number.isInteger(totpOptions.skew) || totpOptions.skew < 0 || totpOptions.skew > 10) {
      throw new RangeError("totp.skew must be an integer between 0 and 10");
    }
    if (!Number.isInteger(totpOptions.recoveryCodeCount) || totpOptions.recoveryCodeCount < 1 ||
        totpOptions.recoveryCodeCount > 100) {
      throw new RangeError("totp.recoveryCodeCount must be an integer between 1 and 100");
    }
  }
  const sessionIdleMs = options.sessionIdleSeconds !== undefined ? options.sessionIdleSeconds * 1000 : undefined;
  const sessionRotationMs = options.sessionRotationSeconds !== undefined ? options.sessionRotationSeconds * 1000 : undefined;
  async function requireUnblockedPassword(password: string, request: Request): Promise<void> {
    if (options.passwordBlocklist && await options.passwordBlocklist({ password, request })) {
      throw new RequestError(400, "invalid_request");
    }
  }

  function passwordAllowed(password: string): boolean {
    let length = 0;
    for (const _character of password) length += 1;
    return length >= passwordPolicy.minLength &&
      length <= passwordPolicy.maxLength &&
      (!options.passwordPolicy?.requireUppercase || /\p{Lu}/u.test(password)) &&
      (!options.passwordPolicy?.requireLowercase || /\p{Ll}/u.test(password)) &&
      (!options.passwordPolicy?.requireSpecial || /[^\p{L}\p{N}\p{White_Space}]/u.test(password));
  }

  function requirePasswordPolicy(password: string): void {
    if (!passwordAllowed(password)) throw new RequestError(400, "invalid_request");
  }

  function requireEmail(user: User): string {
    if (typeof user.email !== "string" || user.email.length === 0) {
      throw new TypeError("UserStore returned a user without an email");
    }
    return user.email;
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

  function assertUserIdentity(user: User): void {
    const validEmail = user.email === undefined ||
      (typeof user.email === "string" && user.email.length <= 254 && user.email.includes("@") &&
        !/\s/.test(user.email) && user.email === user.email.toLowerCase());
    const validUsername = user.username === undefined ||
      (typeof user.username === "string" && /^[a-z0-9._-]{3,32}$/.test(user.username));
    const hasEmail = user.email !== undefined;
    const hasUsername = user.username !== undefined;
    const modeSatisfied =
      (registrationMode === "email" && hasEmail && !hasUsername) ||
      (registrationMode === "username" && hasUsername && !hasEmail) ||
      (registrationMode === "both" && hasEmail && hasUsername) ||
      (registrationMode === "either" && hasEmail !== hasUsername);
    if (typeof user.id !== "string" || user.id.length === 0 || !validEmail || !validUsername || !modeSatisfied) {
      throw new TypeError("UserStore returned an invalid user identity");
    }
  }

  function publicUser(user: User): AuthenticatedUser {
    return {
      id: user.id,
      ...(["email", "both"].includes(registrationMode) && user.email !== undefined ? { email: user.email } : {}),
      ...(["username", "both"].includes(registrationMode) && user.username !== undefined ? { username: user.username } : {}),
      ...(registrationMode === "either" && user.email !== undefined ? { email: user.email } : {}),
      ...(registrationMode === "either" && user.username !== undefined ? { username: user.username } : {}),
    };
  }

  async function getSessionDetails(request: Request): Promise<AuthenticatedSession | null> {
    try {
      const token = readSessionToken(request.headers.get("cookie"), cookieName);
      if (!token) return null;
      const tokenHash = await hashSessionToken(token);
      let stored = await options.sessions.findByTokenHash(tokenHash);
      const now = Date.now();
      if (!stored || stored.tokenHash !== tokenHash ||
          !Number.isFinite(stored.createdAtMs) || stored.createdAtMs > now ||
          !Number.isFinite(stored.expiresAtMs) || stored.expiresAtMs <= now) {
        if (stored?.tokenHash === tokenHash) await options.sessions.deleteByTokenHash(tokenHash);
        return null;
      }
      if (sessionIdleMs !== undefined) {
        const target = Math.min(now + sessionIdleMs, stored.createdAtMs + sessionTtlSeconds * 1000);
        if (target > stored.expiresAtMs && options.sessions.refreshExpiry) {
          await options.sessions.refreshExpiry({ tokenHash, expiresAtMs: target });
          stored = { ...stored, expiresAtMs: target };
        }
      }

      const user = await options.users.findById(stored.userId);
      if (!user) {
        await options.sessions.deleteByTokenHash(tokenHash);
        return null;
      }
      assertUserIdentity(user);
      if (options.emailVerification && !options.emailVerification.isVerified(user)) return null;
      if (options.emailPolicy && (!user.email || !(await isAllowed(options.emailPolicy, user.email, request)))) return null;
      if (options.ipPolicy) {
        const ip = await clientIp(request);
        if (!ip || !(await isAllowed(options.ipPolicy, ip, request))) return null;
      }
      return {
        user: publicUser(user),
        createdAtMs: stored.createdAtMs,
        expiresAtMs: stored.expiresAtMs,
      };
    } catch (error) {
      if (!(error instanceof RequestError)) await report("getSession", error);
      throw error;
    }
  }

  async function getSession(request: Request): Promise<AuthenticatedUser | null> {
    return (await getSessionDetails(request))?.user ?? null;
  }

  async function resolveRotatedSession(request: Request): Promise<{ user: AuthenticatedUser; setCookie?: string } | null> {
    const details = await getSessionDetails(request);
    if (!details) return null;
    if (sessionRotationMs === undefined) return { user: details.user };
    const token = readSessionToken(request.headers.get("cookie"), cookieName);
    if (!token) return { user: details.user };
    const tokenHash = await hashSessionToken(token);
    const current = await options.sessions.findByTokenHash(tokenHash);
    if (!current) return { user: details.user };
    const now = Date.now();
    if (now - current.createdAtMs < sessionRotationMs) return { user: details.user };
    const replacementToken = createSessionToken();
    const replacement: StoredSession = {
      id: createSessionToken(),
      tokenHash: await hashSessionToken(replacementToken),
      userId: current.userId,
      createdAtMs: now,
      expiresAtMs: Math.min(current.createdAtMs + sessionTtlSeconds * 1000,
        now + (options.sessionIdleSeconds ?? sessionTtlSeconds) * 1000),
    };
    await options.sessions.create(replacement);
    await options.sessions.deleteByTokenHash(tokenHash);
    return {
      user: details.user,
      setCookie: sessionCookie(replacementToken, cookieName,
        Math.max(1, Math.round((replacement.expiresAtMs - now) / 1000)), now),
    };
  }

  async function rateLimit(
    action: "register" | "login" | "email-verification" | "password-reset" | "magic-link" | "totp",
    identifier: AuthIdentifier,
    request: Request,
  ): Promise<Response | null> {
    if (!options.rateLimiter) return null;
    const ip = await clientIp(request);
    if (!ip) {
      if (action === "login") return response({ error: "invalid_credentials" }, 401);
      return response({ status: "accepted" }, 202);
    }
    const result = await options.rateLimiter.check({ action, identifier, ip });
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

  async function passPolicies(email: string | undefined, request: Request): Promise<boolean> {
    if (options.emailPolicy && (!email || !(await isAllowed(options.emailPolicy, email, request)))) return false;
    if (!options.ipPolicy) return true;
    const ip = await clientIp(request);
    return ip !== null && isAllowed(options.ipPolicy, ip, request);
  }

  async function register(request: Request): Promise<Response> {
    const credentials = parseRegistrationCredentials(await readJson(request, maxRequestBytes), registrationMode);
    requirePasswordPolicy(credentials.password);
    await requireUnblockedPassword(credentials.password, request);
    const identifier: AuthIdentifier = credentials.email !== undefined
      ? { type: "email", value: credentials.email }
      : { type: "username", value: credentials.username! };
    const limited = await rateLimit("register", identifier, request);
    if (limited) return limited;
    if (!(await passPolicies(credentials.email, request))) return response({ status: "accepted" }, 202);
    const created = await options.users.create(credentials);
    if (created.created) {
      if (!created.user) throw new TypeError("UserStore must return the created user");
      assertUserIdentity(created.user);
      if (options.emailVerification) {
        await issueActionToken(
          "email-verification",
          created.user.id,
          requireEmail(created.user),
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
    const limited = await rateLimit("email-verification", { type: "email", value: email }, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ status: "accepted" }, 202);

    const user = await options.users.findByEmail(email);
    if (user && !flow.isVerified(user)) {
      await issueActionToken(
        "email-verification",
        user.id,
        requireEmail(user),
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
    const limited = await rateLimit("password-reset", { type: "email", value: email }, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ status: "accepted" }, 202);

    const user = await options.users.findByEmail(email);
    if (user) {
      await issueActionToken(
        "password-reset",
        user.id,
        requireEmail(user),
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
    requirePasswordPolicy(password);
    await requireUnblockedPassword(password, request);
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
    assertUserIdentity(user);
    const token = createSessionToken();
    const tokenHash = await hashSessionToken(token);
    const now = Date.now();
    const session: StoredSession = {
      id: createSessionToken(),
      tokenHash,
      userId: user.id,
      createdAtMs: now,
      expiresAtMs: now + Math.min(sessionTtlSeconds, options.sessionIdleSeconds ?? sessionTtlSeconds) * 1000,
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
      if (!user) return response({ error: "unauthenticated" }, 401);
      assertUserIdentity(user);
      if ((options.emailVerification && !options.emailVerification.isVerified(user)) ||
          !(await passPolicies(user.email, request))) {
        return response({ error: "unauthenticated" }, 401);
      }
      return await createSessionForUser(user);
    } catch (error) {
      if (!(error instanceof RequestError)) await report("createSessionResponse", error);
      throw error;
    }
  }

  async function login(request: Request): Promise<Response> {
    const { identifier, password } = parseLoginCredentials(await readJson(request, maxRequestBytes), loginMode);
    const limited = await rateLimit("login", identifier, request);
    if (limited) return limited;

    const user = await options.users.findByIdentifier(identifier);
    const verified = await options.credentials.verify({ identifier, password, user });
    if (user) assertUserIdentity(user);
    const policyAllowed = await passPolicies(identifier.type === "email" ? identifier.value : user?.email, request);
    if (!user || !verified || !policyAllowed ||
        (options.emailVerification && !options.emailVerification.isVerified(user))) {
      return response({ error: "invalid_credentials" }, 401);
    }
    if (totpOptions) {
      const record = await totpOptions.store.get(user.id);
      if (record?.confirmed) {
        const challengeToken = createSessionToken();
        await totpOptions.challengeTokens.create({
          purpose: "totp-challenge",
          userId: user.id,
          tokenHash: await hashSessionToken(challengeToken),
          expiresAtMs: Date.now() + defaultChallengeTtlSeconds * 1000,
        });
        return response({ totpRequired: true, challengeToken }, 200);
      }
    }
    return createSessionForUser(user);
  }

  async function userIdentifier(user: User): Promise<AuthIdentifier> {
    return user.email !== undefined ? { type: "email", value: user.email } : { type: "username", value: user.username! };
  }

  async function totpEnroll(request: Request): Promise<Response> {
    if (!totpOptions) return response({ error: "not_found" }, 404);
    const user = await getSession(request);
    if (!user) return response({ error: "unauthenticated" }, 401);
    const existing = await totpOptions.store.get(user.id);
    if (existing?.confirmed) return response({ error: "invalid_request" }, 400);
    const secret = createTotpSecret();
    const recoveryCodes = createRecoveryCodes(totpOptions.recoveryCodeCount);
    const record: TotpRecord = {
      secret,
      confirmed: false,
      recoveryCodeHashes: await Promise.all(recoveryCodes.map((code) => hashSessionToken(normalizeRecoveryCode(code)))),
    };
    await totpOptions.store.set(user.id, record);
    const appUser = await options.users.findById(user.id);
    if (!appUser) return response({ error: "unauthenticated" }, 401);
    const accountLabel = appUser.email ?? appUser.username ?? appUser.id;
    return response({
      otpauthUri: createOtpauthUri({
        issuer: totpOptions.issuer,
        accountLabel,
        secret,
        digits: totpOptions.digits,
        periodSeconds: totpOptions.periodSeconds,
      }),
      secret,
      recoveryCodes,
    }, 200);
  }

  async function totpConfirm(request: Request): Promise<Response> {
    if (!totpOptions) return response({ error: "not_found" }, 404);
    const user = await getSession(request);
    if (!user) return response({ error: "unauthenticated" }, 401);
    const code = parseOtpCode(objectFields(await readJson(request, maxRequestBytes)).code);
    const record = await totpOptions.store.get(user.id);
    if (!record || record.confirmed) return response({ error: "invalid_request" }, 400);
    const valid = await verifyTotp({
      secret: record.secret,
      token: code,
      digits: totpOptions.digits,
      periodSeconds: totpOptions.periodSeconds,
      skew: totpOptions.skew,
      nowMs: Date.now(),
    });
    if (!valid) return response({ error: "invalid_request" }, 400);
    await totpOptions.store.set(user.id, { ...record, confirmed: true });
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  async function totpDisable(request: Request): Promise<Response> {
    if (!totpOptions) return response({ error: "not_found" }, 404);
    const user = await getSession(request);
    if (!user) return response({ error: "unauthenticated" }, 401);
    const fields = objectFields(await readJson(request, maxRequestBytes));
    const code = typeof fields.code === "string" ? fields.code : "";
    const record = await totpOptions.store.get(user.id);
    if (!record) return response({ error: "invalid_request" }, 400);
    const appUser = await options.users.findById(user.id);
    if (!appUser) return response({ error: "invalid_request" }, 400);
    let verified = await verifyTotp({
      secret: record.secret,
      token: code,
      digits: totpOptions.digits,
      periodSeconds: totpOptions.periodSeconds,
      skew: totpOptions.skew,
      nowMs: Date.now(),
    });
    if (!verified && /^[A-Z2-7]{10}$/.test(code.toUpperCase().replace(/[ -]/g, ""))) {
      verified = await totpOptions.store.consumeRecoveryCode(
        user.id,
        await hashSessionToken(normalizeRecoveryCode(code)),
      );
    }
    if (!verified) return response({ error: "invalid_request" }, 400);
    await totpOptions.store.delete(user.id);
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  async function totpVerify(request: Request): Promise<Response> {
    if (!totpOptions) return response({ error: "not_found" }, 404);
    const { challengeToken, code } = parseTotpVerifyRequest(await readJson(request, maxRequestBytes));
    const consumed = await totpOptions.challengeTokens.consume({
      purpose: "totp-challenge",
      tokenHash: await hashSessionToken(challengeToken),
      nowMs: Date.now(),
    });
    if (!consumed) return response({ error: "invalid_token" }, 400);
    const user = await options.users.findById(consumed.userId);
    if (!user) return response({ error: "invalid_token" }, 400);
    const limited = await rateLimit("totp", await userIdentifier(user), request);
    if (limited) return limited;
    const record = await totpOptions.store.get(user.id);
    if (!record?.confirmed) return response({ error: "invalid_credentials" }, 401);
    let verified = await verifyTotp({
      secret: record.secret,
      token: code,
      digits: totpOptions.digits,
      periodSeconds: totpOptions.periodSeconds,
      skew: totpOptions.skew,
      nowMs: Date.now(),
    });
    if (!verified && /^[A-Z2-7]{10}$/.test(code.toUpperCase().replace(/[ -]/g, ""))) {
      verified = await totpOptions.store.consumeRecoveryCode(
        user.id,
        await hashSessionToken(normalizeRecoveryCode(code)),
      );
    }
    if (!verified) return response({ error: "invalid_credentials" }, 401);
    if (options.emailVerification && !options.emailVerification.isVerified(user)) {
      return response({ error: "invalid_credentials" }, 401);
    }
    return createSessionForUser(user);
  }

  async function magicLinkRequest(request: Request): Promise<Response> {
    const flow = options.magicLink;
    if (!flow) return response({ error: "not_found" }, 404);
    const email = parseEmailRequest(await readJson(request, maxRequestBytes));
    const limited = await rateLimit("magic-link", { type: "email", value: email }, request);
    if (limited) return limited;
    if (!(await passPolicies(email, request))) return response({ status: "accepted" }, 202);
    const user = await options.users.findByEmail(email);
    if (user) {
      await issueActionToken(
        "magic-link",
        user.id,
        requireEmail(user),
        flow.tokens,
        flow.delivery,
        defaultMagicLinkTtlSeconds,
        "magic-link.send",
      );
    }
    return response({ status: "accepted" }, 202);
  }

  async function magicLinkConfirm(request: Request): Promise<Response> {
    const flow = options.magicLink;
    if (!flow) return response({ error: "not_found" }, 404);
    const token = parseActionTokenRequest(await readJson(request, maxRequestBytes));
    const consumed = await flow.tokens.consume({
      purpose: "magic-link",
      tokenHash: await hashSessionToken(token),
      nowMs: Date.now(),
    });
    if (!consumed) return response({ error: "invalid_token" }, 400);
    const user = await options.users.findById(consumed.userId);
    if (!user) return response({ error: "invalid_token" }, 400);
    const limited = await rateLimit("magic-link", await userIdentifier(user), request);
    if (limited) return limited;
    if ((options.emailVerification && !options.emailVerification.isVerified(user)) ||
        !(await passPolicies(user.email, request))) {
      return response({ error: "invalid_token" }, 400);
    }
    if (options.emailVerification) await options.emailVerification.markVerified(user.id);
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
    if (options.totp) stores.add(options.totp.challengeTokens);
    if (options.magicLink) stores.add(options.magicLink.tokens);
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
        const resolved = await resolveRotatedSession(request);
        if (!resolved) return response({ error: "unauthenticated" }, 401);
        return resolved.setCookie
          ? response({ user: resolved.user }, 200, { "Set-Cookie": resolved.setCookie })
          : response({ user: resolved.user }, 200);
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
    const magicLinkRoute = route === "/magic-link/request" || route === "/magic-link/confirm";
    const totpRoute = ["/totp/enroll", "/totp/confirm", "/totp/disable", "/totp/verify"].includes(route);
    const enabled = ["/register", "/login", "/logout"].includes(route) ||
      (emailVerificationRoute && !!options.emailVerification) ||
      (passwordResetRoute && !!options.passwordReset) ||
      (magicLinkRoute && !!options.magicLink) ||
      (totpRoute && !!options.totp);
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
      if (route === "/password-reset/confirm") return await confirmPasswordReset(request);
      if (route === "/magic-link/request") return await magicLinkRequest(request);
      if (route === "/magic-link/confirm") return await magicLinkConfirm(request);
      if (route === "/totp/enroll") return await totpEnroll(request);
      if (route === "/totp/confirm") return await totpConfirm(request);
      if (route === "/totp/disable") return await totpDisable(request);
      return await totpVerify(request);
    } catch (error) {
      if (!(error instanceof RequestError)) await report(route.slice(1), error);
      return errorResponse(error);
    }
  }

  return { handle, cleanupExpired, getSession, getSessionDetails, createSessionResponse };
}
