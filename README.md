# @shtora/auth

[Repository](https://github.com/orgShtora-1/auth) · [Issues](https://github.com/orgShtora-1/auth/issues)

Framework-neutral authentication handlers and session management for Next.js and Cloudflare Workers. The core uses standard `Request`/`Response` APIs and Web Crypto; optional entry points add Cloudflare D1, OIDC, and WebAuthn support.

Your application owns its user records, credential verification, password hashing, email delivery, and persistent stores. The package does not hash, encrypt, or persist passwords and includes no ORM.

## Install

Install the published package from npm:

```sh
bun add @shtora/auth@latest
```

To install a beta release:

```sh
bun add @shtora/auth@beta
```

The `beta` tag must point to a published beta version. It is not currently available.

Install optional protocol dependencies only when you use those entry points:

```sh
bun add openid-client              # @shtora/auth/oidc
bun add @simplewebauthn/server     # @shtora/auth/webauthn
```

## Next.js App Router

Create the handler with application-owned adapters. `users`, `credentials`, `sessions`, `rateLimiter`, and `resolveClientIp` below are implementations in your application, not exports from this package.

```ts
// src/server/auth.ts
import { createAuth } from "@shtora/auth";
import {
  blockedEmails,
  blockedIps,
  credentials,
  rateLimiter,
  resolveClientIp,
  sessions,
  users,
} from "./auth-adapters";

export const auth = createAuth({
  users,
  credentials,
  sessions,
  rateLimiter,
  resolveClientIp,
  allowedHosts: ["app.example.com"],
  emailPolicy: {
    async allow({ value }) {
      return !blockedEmails.has(value);
    },
  },
  ipPolicy: {
    async allow({ value }) {
      return !blockedIps.has(value);
    },
  },
});
```

Forward the supported methods from a Route Handler:

```ts
// app/api/auth/[...auth]/route.ts
import { auth } from "@/server/auth";

export const GET = (request: Request) => auth.handle(request);
export const POST = (request: Request) => auth.handle(request);
export const DELETE = (request: Request) => auth.handle(request);
```

Use the real hostname in `allowedHosts`. Resolve client IPs only from a trusted hosting-platform or proxy value; do not parse arbitrary `X-Forwarded-For` input. Configure a shared, persistent rate limiter for public authentication endpoints.

## Cloudflare Workers and D1

Import D1 adapters from the dedicated entry point. The application still supplies its own user and credential adapters; D1 stores sessions and rate-limit counters in this example.

```ts
import { createAuth } from "@shtora/auth";
import {
  cleanupD1AuthState,
  createD1RateLimiter,
  createD1SessionStore,
  type D1Database,
} from "@shtora/auth/cloudflare";
import { credentials, users } from "./auth-adapters";

interface Env {
  DB: D1Database;
}

let auth: ReturnType<typeof createAuth> | undefined;

function getAuth(env: Env) {
  return auth ??= createAuth({
    users,
    credentials,
    sessions: createD1SessionStore(env.DB),
    rateLimiter: createD1RateLimiter(env.DB, {
      identifier: { limit: 5, windowSeconds: 60 },
      ip: { limit: 100, windowSeconds: 60 },
    }),
    resolveClientIp: (request) => request.headers.get("cf-connecting-ip"),
    allowedHosts: ["auth.example.com"],
  });
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return getAuth(env).handle(request);
  },

  async scheduled(_controller: unknown, env: Env): Promise<void> {
    await cleanupD1AuthState(env.DB, { rateLimitMaxWindowSeconds: 60 });
  },
};
```

The npm package omits SQL files; see the [Cloudflare D1 adapter](#cloudflare-d1-adapter) section for the pinned migration source and application instructions. D1 cleanup is bounded; schedule it often enough for your session and rate-limit volume. Workers Free and Paid use the same package code, subject to each plan's D1, storage, and CPU quotas.

## Routes

The default base path is `/api/auth`; set `basePath` to change it.

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Creates an account. Duplicate and policy-blocked registrations share the same `202` response. |
| `POST` | `/api/auth/login` | Verifies credentials and sets a session cookie. |
| `POST` | `/api/auth/logout` | Revokes the current session and clears the cookie after successful revocation. |
| `GET` | `/api/auth/session` | Returns the authenticated user or `401`. |
| `GET` | `/api/auth/sessions` | Lists the user's active sessions without token hashes. |
| `DELETE` | `/api/auth/sessions/:id` | Revokes a session owned by the current user. |
| `DELETE` | `/api/auth/sessions` | Revokes all sessions for the current user. |
| `POST` | `/api/auth/email-verification/request` | Optional; sends a verification message with an enumeration-resistant response. |
| `POST` | `/api/auth/email-verification/confirm` | Optional; consumes a one-time token and marks the account verified. |
| `POST` | `/api/auth/password-reset/request` | Optional; sends a reset message with an enumeration-resistant response. |
| `POST` | `/api/auth/password-reset/confirm` | Optional; revokes sessions, then delegates the password update to the application. |

State-changing POST and DELETE requests require a same-origin `Origin` header by default. Read-only session GET requests allow a missing `Origin`. Keep this check enabled for browser cookie authentication unless equivalent CSRF protection is in place.
## Registration and login identifiers

Email-only behavior is the default. `identity.registration` accepts `"email"`, `"username"`, `"both"`, or `"either"`; `"either"` requires exactly one identifier. `identity.login` accepts `"email"`, `"username"`, or `"either"`, also requiring exactly one login identifier. Compatible pairs are email/email, username/username, either/either, and both with any login mode; other pairs fail during `createAuth`.

```ts
createAuth({
  users,
  credentials,
  sessions,
  identity: { registration: "either", login: "either" },
  passwordPolicy: {
    minLength: 12,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireSpecial: true,
  },
});
```

Registration accepts `{ email, password }`, `{ username, password }`, both identifiers with `registration: "both"`, or exactly one identifier with `"either"`. Login accepts the configured identifier field and a password; `"either"` rejects requests containing both. Unknown JSON keys are ignored, but supplying a disabled email/username field is invalid. Password is always required.

Usernames are 3–32 ASCII letters, digits, `.`, `_`, or `-`; they are canonicalized to lowercase without trimming. The application’s `UserStore.findByIdentifier` must use the same canonical form, and `create` must enforce email/username uniqueness atomically with database constraints. Email input is lowercased; whitespace is rejected. Username syntax excludes `@`, so valid email and username values cannot collide across namespaces. Lookup and rate limiting carry an explicit `"email"`/`"username"` discriminator.

`AuthUser` contains an opaque `id` and optional `email`/`username`. The package returns only `id` and present email/username fields; it never spreads adapter fields into a public response. OIDC and WebAuthn continue to map identities through the application’s opaque user ID.

`UserStore` results must contain exactly the configured identity shape before a session is created: email mode requires only email, username mode only username, both requires both, and either requires exactly one. Missing or invalid canonical identifiers fail closed and are reported through `onError`; no partial identity response is issued.

The default password policy is min 1 and max 4096 Unicode code points, with uppercase/lowercase/special requirements disabled. Policy checks run during registration and password-reset confirmation, not login. Passwords are neither trimmed nor normalized. “Special” means a Unicode code point that is not a letter, number, or whitespace. The 4096-code-point hard cap is independent of the request-body byte limit. Invalid shape or policy returns the generic `400 { "error": "invalid_request" }`.

Email verification requires registration mode `"email"` or `"both"` and rejects incompatible configurations at `createAuth`. Password-reset request remains email-address-only; username-only accounts and `"either"` accounts created without an email cannot request an email reset. `emailPolicy` denies email-less users, including session creation through OIDC. No additional migration is needed for this identity-mode change: D1 rate-limit table keys store only digests, with identifier kind included in the hashed key.


## Email verification and password reset

These flows are opt-in. Configure the matching options with an `AuthActionTokenStore` and a delivery callback. The store persists only a SHA-256 token hash, atomically replaces an earlier token for the same user and purpose, consumes the current unexpired token once, and implements bounded expiration cleanup. The callback receives the raw bearer token: enqueue it promptly and never log it. Submit tokens to the POST confirmation routes rather than consuming them in GET requests, which link scanners may follow.

Email verification also requires `isVerified` and `markVerified`. When enabled, unverified users cannot log in or use existing sessions. The configured package `passwordPolicy` applies to registration and password-reset confirmation. Reset sessions are revoked before `setPassword` delegates hashing and persistence to the application; if persistence fails, the user remains signed out but the old password may still work. The application owns hashing, persistence, and any policy checks for password flows outside these package handlers.

Known and unknown addresses receive the same request response, though delivery timing can differ. Use asynchronous delivery and configure rate limiting for public auth endpoints.

## External identity handlers

`auth.createSessionResponse(request, userId)` creates a package session after an external identity handler has verified its protocol response. It reloads the application user and applies configured host, email, IP, and verification policies. The caller remains responsible for protocol state, CSRF protection, and rate limiting.

## Security and storage contracts

- The default `__Host-shtora.session` cookie is `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and has no `Domain`. Cookie names must use the `__Host-` prefix.
- Session cookies contain a random 256-bit token. `SessionStore` persists only its SHA-256 hash. Use storage with reliable revocation consistency; `deleteByIdForUser` must match both session and user IDs.
- The default session lifetime is seven days (maximum one year). Request bodies are limited to 8 KiB by default; oversized cookie headers are treated as unauthenticated.
- The application must hash passwords before storing them. `CredentialVerifier.verify` should do equivalent work for missing users to reduce account-enumeration timing differences. Never return password material through `AuthUser`.
- Rate limiting is optional for core routes and should be configured for public deployments. OIDC and WebAuthn require a trusted client-IP resolver and request rate limiter; they fail closed when the IP is unavailable.
- `resolveClientIp` must use a trusted proxy or platform header. Never trust arbitrary forwarded headers.
- `allowedHosts` is an optional exact-authority allowlist. If omitted, reject unexpected hosts at the platform or proxy.
- `onError({ operation, error })` observes unexpected adapter, policy, and delivery errors. HTTP responses remain generic. Avoid logging unreviewed adapter errors; they may contain sensitive values. Direct `getSession()` and `createSessionResponse()` calls reject adapter errors after notifying the observer.

The application also owns persistent storage for action tokens, OIDC transactions, WebAuthn challenges, and credentials. Their `consume` operations must be atomic and one-use; WebAuthn credential IDs must be unique and counter updates conditional on the stored counter. Expired-record cleanup methods must honor their supplied limit. See the exported TypeScript interfaces for the complete contracts.

## Optional protocols

### OIDC

Import `createOidc` and its types from `@shtora/auth/oidc`. Required options are `issuer` (HTTPS issuer URL), `clientId`, an absolute HTTPS `callbackUrl` registered with the provider, a fixed same-origin `successPath`, a persistent `transactions` store, `resolveUser`, `auth`, a trusted `resolveClientIp`, and a `rateLimiter`. `auth` is the `createAuth` result; `resolveUser` maps the verified `{ issuer, subject }` to an application user or `null`.

The returned handler accepts GET `/start` and GET `/callback` paths. Mount it at the callback URL's origin and route both paths to it; register the exact callback URL with the identity provider. It uses state, nonce, PKCE, and one-use transaction consumption. Schedule its `cleanupExpired()` method.

### WebAuthn and passkeys

Import `createWebAuthn` and its types from `@shtora/auth/webauthn`. Required options are the exact `expectedOrigin` (HTTPS, or localhost HTTP for development), matching `rpID`, `rpName`, persistent one-use `challenges` and `credentials` stores, `resolveRegistrationUser`, `auth`, a trusted `resolveClientIp`, and a `rateLimiter`. `auth` is the `createAuth` result. Registration requires an authenticated application user with a stable, non-PII ID of at most 64 UTF-8 bytes.

Forward POST `/webauthn/registration/options`, `/webauthn/registration/verify`, `/webauthn/authentication/options`, and `/webauthn/authentication/verify` to the returned handler. It verifies the configured origin and RP ID, requires user verification, and uses one-use challenges. Credential IDs must be unique and counter updates atomic compare-and-set operations. Schedule the returned `cleanupExpired()` method.

## Public entry points

- `@shtora/auth`: `createAuth` and the core types for users, credentials, sessions, rate limiting, policies, and optional email verification/password reset.
- `@shtora/auth/cloudflare`: `D1Database`, D1 session/action-token stores, core and request rate limiters, and D1 auth-state cleanup.
- `@shtora/auth/oidc`: `createOidc` and OIDC configuration, transaction-store, and handler types.
- `@shtora/auth/webauthn`: `createWebAuthn` and WebAuthn challenge-store, credential-store, options, and user types.

Install `openid-client` for `@shtora/auth/oidc` and `@simplewebauthn/server` for `@shtora/auth/webauthn`; these optional peer dependencies are not needed by the core entry point.

## Cloudflare D1 adapter

`@shtora/auth/cloudflare` exports `createD1SessionStore`, `createD1ActionTokenStore`, `createD1RateLimiter`, `createD1RequestRateLimiter`, and `cleanupD1AuthState`. `createD1RateLimiter` implements the core auth limiter for registration, login, email verification, and password reset; `createD1RequestRateLimiter` implements the separate request limiter required by OIDC and WebAuthn using `{ limit, windowSeconds }`. Both use hashed keys in the same `shtora_rate_limits` table.

The npm package omits SQL files; apply migrations in filename order from the [pinned repository source](https://github.com/orgShtora-1/auth/tree/694089c260cdcc229b78b20a6b3a90f92eb38fd6/migrations), using `wrangler d1 execute <database-name> --remote --file <migration.sql>`. If schemas diverge in a later release, use the repository commit matching your installed package version. `cleanupD1AuthState` deletes bounded batches of expired sessions, action tokens, and rate-limit records; set `rateLimitMaxWindowSeconds` to at least the longest configured rate-limit window. D1 counters share one database and consume D1 write capacity. Cloudflare's Workers Rate Limit binding is location-local and approximate, not a globally strict limiter. See the [D1 Worker API](https://developers.cloudflare.com/d1/worker-api/d1-database/) and [Workers Rate Limit binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/).


