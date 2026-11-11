export interface AuthUser {
  readonly id: string;
  readonly email?: string;
  readonly username?: string;
}

export type AuthIdentifier =
  | { readonly type: "email"; readonly value: string }
  | { readonly type: "username"; readonly value: string };

export type RegistrationIdentityMode = "email" | "username" | "both" | "either";
export type LoginIdentityMode = "email" | "username" | "either";

export interface PasswordPolicy {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireSpecial?: boolean;
}

export interface UserStore<User extends AuthUser = AuthUser> {
  findByIdentifier(identifier: AuthIdentifier): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  /** Enforce canonical email/username uniqueness atomically; hash the password before persistence. */
  create(input: {
    email?: string;
    username?: string;
    password: string;
  }): Promise<{ created: true; user: User } | { created: false }>;
}

export interface CredentialVerifier<User extends AuthUser = AuthUser> {
  verify(input: {
    identifier: AuthIdentifier;
    password: string;
    user: User | null;
  }): Promise<boolean>;
}

export type AuthActionTokenPurpose = "email-verification" | "password-reset";

export interface AuthActionTokenStore extends ExpiredRecordStore {
  /** Atomically replace any existing token for this user and purpose. */
  create(input: { purpose: AuthActionTokenPurpose; userId: string; tokenHash: string; expiresAtMs: number }): Promise<void>;
  /** Consume only an unexpired matching token, atomically; never return its stored hash. */
  consume(input: { purpose: AuthActionTokenPurpose; tokenHash: string; nowMs: number }): Promise<{ userId: string } | null>;
}

export interface AuthActionTokenDelivery {
  /** Enqueue delivery promptly; callers must not log the bearer token. */
  send(input: { email: string; token: string; expiresAtMs: number }): Promise<void>;
  tokenTtlSeconds?: number;
}

export interface EmailVerificationOptions<User extends AuthUser = AuthUser> extends AuthActionTokenDelivery {
  tokens: AuthActionTokenStore;
  isVerified(user: User): boolean;
  markVerified(userId: string): Promise<void>;
}

export interface PasswordResetOptions extends AuthActionTokenDelivery {
  tokens: AuthActionTokenStore;
  /** Update the application's password hash; this package never hashes or stores passwords. */
  setPassword(input: { userId: string; password: string }): Promise<void>;
}

/** id is random and non-secret; tokenHash is the cookie token digest. Timestamps are Unix epoch milliseconds. */
export interface StoredSession {
  readonly id: string;
  readonly tokenHash: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

export interface AuthOptions<User extends AuthUser = AuthUser> {
  users: UserStore<User>;
  credentials: CredentialVerifier<User>;
  sessions: SessionStore;
  identity?: {
    registration?: RegistrationIdentityMode;
    login?: LoginIdentityMode;
  };
  passwordPolicy?: PasswordPolicy;
  emailPolicy?: AccessPolicy;
  resolveClientIp?: (request: Request) => string | null | Promise<string | null>;
  ipPolicy?: AccessPolicy;
  rateLimiter?: AuthRateLimiter;
  emailVerification?: EmailVerificationOptions<User>;
  passwordReset?: PasswordResetOptions;
  allowedHosts?: readonly string[];
  onError?: (event: { operation: string; error: unknown }) => void | Promise<void>;
  requireOrigin?: boolean;
  basePath?: string;
  cookieName?: string;
  sessionTtlSeconds?: number;
  maxRequestBytes?: number;
}

export interface ExpiredRecordStore {
  /** Delete at most `limit` expired records; call periodically from a scheduled task. */
  deleteExpired(input: { nowMs: number; limit: number }): Promise<void>;
}

export interface SessionStore extends ExpiredRecordStore {
  create(session: StoredSession): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<StoredSession | null>;
  deleteByTokenHash(tokenHash: string): Promise<void>;
  listByUserId(userId: string): Promise<readonly StoredSession[]>;
  deleteByIdForUser(id: string, userId: string): Promise<void>;
  deleteByUserId(userId: string): Promise<void>;
}

export interface AuthRateLimiter {
  check(input: {
    action: "register" | "login" | "email-verification" | "password-reset";
    identifier: AuthIdentifier;
    ip: string;
  }): Promise<{
    allowed: boolean;
    retryAfterSeconds?: number;
  }>;
}


export type AuthRequestRateLimitAction =
  | "oidc-start"
  | "oidc-callback"
  | "webauthn-registration-options"
  | "webauthn-registration-verify"
  | "webauthn-authentication-options"
  | "webauthn-authentication-verify";

export interface AuthRequestRateLimiter {
  check(input: {
    action: AuthRequestRateLimitAction;
    ip: string;
  }): Promise<{
    allowed: boolean;
    retryAfterSeconds?: number;
  }>;
}

export interface AccessPolicy {
  allow(input: { value: string; request: Request }): Promise<boolean>;
}


export interface AuthenticatedUser {
  readonly id: string;
  readonly email?: string;
  readonly username?: string;
}

export interface AuthApi {
  handle(request: Request): Promise<Response>;
  /** Delete a bounded batch of expired sessions and action tokens from each configured store. */
  cleanupExpired(): Promise<void>;
  /** Rejects if a backing adapter fails; unexpected errors are observed before being rethrown. */
  getSession(request: Request): Promise<AuthenticatedUser | null>;
  /** Use only after an external identity protocol has been verified; creates a server-side session. */
  createSessionResponse(request: Request, userId: string): Promise<Response>;
}
