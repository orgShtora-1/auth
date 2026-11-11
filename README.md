# @shtora/auth

Framework-neutral authentication handlers and session management for Next.js and Cloudflare Workers. The core uses standard `Request`/`Response` APIs and Web Crypto; optional entry points add Cloudflare D1, OIDC, and WebAuthn support.

Your application owns its user records, credential verification, password hashing, email delivery, and persistent stores. The package does not hash, encrypt, or persist passwords and includes no ORM.

## Install

```sh
bun add @shtora/auth
```

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
      email: { limit: 5, windowSeconds: 60 },
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

Apply the SQL files in `migrations/` to the D1 database before handling requests. D1 cleanup is bounded; schedule it often enough for your session and rate-limit volume. Workers Free and Paid use the same package code, subject to each plan's D1, storage, and CPU quotas. Local Worker tests do not measure production quotas.

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

## Email verification and password reset

These flows are opt-in. Configure the matching options with an `AuthActionTokenStore` and a delivery callback. The store persists only a SHA-256 token hash, atomically replaces an earlier token for the same user and purpose, consumes the current unexpired token once, and implements bounded expiration cleanup. The callback receives the raw bearer token: enqueue it promptly and never log it. Submit tokens to the POST confirmation routes rather than consuming them in GET requests, which link scanners may follow.

Email verification also requires `isVerified` and `markVerified`. When enabled, unverified users cannot log in or use existing sessions. Password reset delegates password hashing and persistence to `setPassword`; sessions are revoked before that callback runs. If password persistence fails, the user remains signed out but the old password may still work. The application remains responsible for password policy and hash configuration.

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

Import `createOidc` from `@shtora/auth/oidc`. It uses state, nonce, and PKCE, checks the fixed callback URL, and consumes a matching unexpired transaction once. The application owns `OidcTransactionStore`, issuer/client configuration, identity-to-user mapping, and session creation. Use an HTTPS issuer and pre-registered callback URL; schedule the returned `cleanupExpired()` method.

### WebAuthn and passkeys

Import `createWebAuthn` from `@shtora/auth/webauthn`. Registration requires an authenticated user flow and a stable, non-PII application user ID of at most 64 UTF-8 bytes. Configure the exact expected origin and RP ID, persistent one-use challenge storage, unique credential IDs, compare-and-set counter updates, trusted client-IP resolution, and a request rate limiter. Schedule the returned `cleanupExpired()` method.

## Cloudflare D1 adapter

`@shtora/auth/cloudflare` exports D1 session, action-token, and fixed-window rate-limit adapters. The core entry point does not import Cloudflare code. Rate-limit keys are hashed before storage; the counters remain scoped to one D1 database and consume D1 write capacity. Cloudflare's Workers Rate Limit binding is location-local and approximate, not a globally strict limiter.

Run all SQL migrations in order. `cleanupD1AuthState` removes bounded batches of expired sessions, action tokens, and rate-limit records; set `rateLimitMaxWindowSeconds` to at least the longest configured rate-limit window. See the [D1 Worker API](https://developers.cloudflare.com/d1/worker-api/d1-database/) and [Workers Rate Limit binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/).

## Development

```sh
bun install
bun run typecheck
bun test
bun run build
```

Changes to auth behavior should include tests for the affected boundary or state transition. Keep package documentation in English, update this README when public contracts change, and avoid adding generated output to commits. See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow.
