# @shtora/auth

[Repository](https://github.com/orgShtora-1/auth) · [Issues](https://github.com/orgShtora-1/auth/issues)

Framework-neutral authentication handlers and session management for Next.js. The core uses standard `Request`/`Response` APIs and Web Crypto; optional entry points add OIDC and WebAuthn support.

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
| `POST` | `/api/auth/totp/enroll` | Optional; authenticated. Creates an unconfirmed enrollment and returns the otpauth URI, Base32 secret, and recovery codes. |
| `POST` | `/api/auth/totp/confirm` | Optional; authenticated. Activates the enrollment with a valid current code. |
| `POST` | `/api/auth/totp/verify` | Optional. Consumes a one-time login challenge and a valid code or recovery code, then sets a session. |
| `POST` | `/api/auth/totp/disable` | Optional; authenticated. Removes the enrollment with a valid current code or recovery code. |
| `POST` | `/api/auth/magic-link/request` | Optional; sends a magic link with an enumeration-resistant response. |
| `POST` | `/api/auth/magic-link/confirm` | Optional; consumes a one-time magic link token and sets a session. |

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
    minLength: 15,
    maxLength: 4096,
  },
});
```

Registration accepts `{ email, password }`, `{ username, password }`, both identifiers with `registration: "both"`, or exactly one identifier with `"either"`. Login accepts the configured identifier field and a password; `"either"` rejects requests containing both. Unknown JSON keys are ignored, but supplying a disabled email/username field is invalid. Password is always required.

Usernames are 3–32 ASCII letters, digits, `.`, `_`, or `-`; they are canonicalized to lowercase without trimming. The application’s `UserStore.findByIdentifier` must use the same canonical form, and `create` must enforce email/username uniqueness atomically with database constraints. Email input is lowercased; whitespace is rejected. Username syntax excludes `@`, so valid email and username values cannot collide across namespaces. Lookup and rate limiting carry an explicit `"email"`/`"username"` discriminator.

`AuthUser` contains an opaque `id` and optional `email`/`username`. The package returns only `id` and present email/username fields; it never spreads adapter fields into a public response. OIDC and WebAuthn continue to map identities through the application’s opaque user ID.

`UserStore` results must contain exactly the configured identity shape before a session is created: email mode requires only email, username mode only username, both requires both, and either requires exactly one. Missing or invalid canonical identifiers fail closed and are reported through `onError`; no partial identity response is issued.

The default password policy requires 15–4096 Unicode code points and applies no character-composition rules. Policy checks run during registration and password-reset confirmation, not login. Passwords are neither trimmed nor normalized. The 4096-code-point hard cap is independent of the request-body byte limit. Invalid shape or policy returns the generic `400 { "error": "invalid_request" }`. Applications that require passwords only as one factor of MFA may configure a lower minimum.

Email verification requires registration mode `"email"` or `"both"` and rejects incompatible configurations at `createAuth`. Password-reset request remains email-address-only; username-only accounts and `"either"` accounts created without an email cannot request an email reset. `emailPolicy` denies email-less users, including session creation through OIDC.

## Two-factor authentication (TOTP)

TOTP is opt-in. Configure the `totp` option with a `TotpStore`, the action-token store to reuse as `challengeTokens`, and an `issuer` label for authenticator apps. Defaults are six digits, a 30-second period, a skew of 1, and 10 recovery codes; `digits` accepts 6 or 8, `periodSeconds` is a positive integer, `skew` is 0–10, and `recoveryCodeCount` is 1–100.

Enrollment is session-scoped: `POST /api/auth/totp/enroll` returns `200` with `otpauthUri`, the Base32 `secret`, and single-use `recoveryCodes`, and stores an unconfirmed `TotpRecord` keyed by user ID. `POST /api/auth/totp/confirm` activates the record with a valid current code (`204`). Once confirmed, `POST /api/auth/login` with valid credentials returns `200 { totpRequired: true, challengeToken }` instead of a session cookie; the challenge is one-use and expires after five minutes. `POST /api/auth/totp/verify` accepts `{ challengeToken, code }`, where `code` is the current code or an unused recovery code, and then sets a session. `POST /api/auth/totp/disable` removes the record with a valid current code or recovery code. Recovery codes are returned once, in plaintext, at enrollment; the store persists only SHA-256 hashes, and `consumeRecoveryCode` must be atomic so each code works once.

The core entry point exports the TOTP primitives - `verifyTotp`, `createTotpSecret`, `createRecoveryCodes`, `createOtpauthUri`, `base32Encode`, `base32Decode`, and `normalizeRecoveryCode` - for building authenticator integrations.

## Magic link login

Magic link login is opt-in. Configure the `magicLink` option with an `AuthActionTokenStore` and a delivery callback of the same shape as email verification; the token TTL is 900 seconds unless `tokenTtlSeconds` is set on the delivery.

`POST /api/auth/magic-link/request` returns `202 { status: "accepted" }` for known and unknown addresses; for an existing address that passes the configured policies it delivers a raw token. `POST /api/auth/magic-link/confirm` consumes the token once, applies the same host, email, IP, and verification checks as login, and sets a session; an unknown, expired, or already-used token returns `400 { "error": "invalid_token" }`. With email verification enabled, unverified accounts are rejected at confirm, so verification must complete first.


## Email verification and password reset

These flows are opt-in. Configure the matching options with an `AuthActionTokenStore` and a delivery callback. The store persists only a SHA-256 token hash, atomically replaces an earlier token for the same user and purpose, consumes the current unexpired token once, and implements bounded expiration cleanup. The callback receives the raw bearer token: enqueue it promptly and never log it. Submit tokens to the POST confirmation routes rather than consuming them in GET requests, which link scanners may follow.

Email verification also requires `isVerified` and `markVerified`. When enabled, unverified users cannot log in or use existing sessions. The configured package `passwordPolicy` applies to registration and password-reset confirmation. Reset sessions are revoked before `setPassword` delegates hashing and persistence to the application; if persistence fails, the user remains signed out but the old password may still work. The application owns hashing, persistence, and any policy checks for password flows outside these package handlers.

Known and unknown addresses receive the same request response, though delivery timing can differ. Use asynchronous delivery and configure rate limiting for public auth endpoints.

## External identity handlers

`auth.createSessionResponse(request, userId)` creates a package session after an external identity handler has verified its protocol response. It reloads the application user and applies configured host, email, IP, and verification policies. The caller remains responsible for protocol state, CSRF protection, and rate limiting.

## Security and storage contracts

`auth.getSessionDetails(request)` returns the authenticated user with `createdAtMs` and `expiresAtMs` after the same session and policy checks as `getSession()`. Compare `createdAtMs` with an application-defined freshness window before sensitive actions. The package does not enforce step-up authentication on application routes.

- The default `__Host-shtora.session` cookie is `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and has no `Domain`. Cookie names must use the `__Host-` prefix.
- Session cookies contain a random 256-bit token. `SessionStore` persists only its SHA-256 hash. Use storage with reliable revocation consistency; `deleteByIdForUser` must match both session and user IDs.
- The default session lifetime is seven days (maximum one year). Request bodies are limited to 8 KiB by default; oversized cookie headers are treated as unauthenticated.
- The application must hash passwords before storing them. `CredentialVerifier.verify` should do equivalent work for missing users to reduce account-enumeration timing differences. Never return password material through `AuthUser`.
- Core rate limiting is optional in the API but required for public deployments. Configure a shared, persistent limiter for registration, login, verification, and reset routes. OIDC and WebAuthn require a trusted client-IP resolver and request rate limiter; they fail closed when the IP is unavailable.
- `resolveClientIp` must use a trusted proxy or platform header. Never trust arbitrary forwarded headers.
- `allowedHosts` is an optional exact-authority allowlist. If omitted, reject unexpected hosts at the platform or proxy.
- `onError({ operation, error })` observes unexpected adapter, policy, and delivery errors. HTTP responses remain generic. Avoid logging unreviewed adapter errors; they may contain sensitive values. Direct `getSession()` and `createSessionResponse()` calls reject adapter errors after notifying the observer.
- `sessionIdleSeconds` extends the session expiry while the user is active, capped at the absolute `sessionTtlSeconds` lifetime; it requires `sessions.refreshExpiry`, which the package calls only with a later expiry.
- `sessionRotationSeconds` issues a fresh session token once a session is older than that many seconds; the rotated token arrives in the `Set-Cookie` of the next `/session` response and the previous token is revoked.
- `passwordBlocklist({ password, request })` runs during registration and password-reset confirmation; returning `true` rejects the password with the generic `400 { "error": "invalid_request" }`.


## Optional protocols

### OIDC

Import `createOidc` and its types from `@shtora/auth/oidc`. Required options are `issuer` (HTTPS issuer URL), `clientId`, an absolute HTTPS `callbackUrl` registered with the provider, a fixed same-origin `successPath`, a persistent `transactions` store, `resolveUser`, `auth`, a trusted `resolveClientIp`, and a `rateLimiter`. `auth` is the `createAuth` result; `resolveUser` maps the verified `{ issuer, subject }` to an application user or `null`.

The returned handler accepts GET `/start` and GET `/callback` paths. Mount it at the callback URL's origin and route both paths to it; register the exact callback URL with the identity provider. It uses state, nonce, PKCE, and one-use transaction consumption. Schedule its `cleanupExpired()` method.

### WebAuthn and passkeys

Import `createWebAuthn` and its types from `@shtora/auth/webauthn`. Required options are the exact `expectedOrigin` (HTTPS, or localhost HTTP for development), matching `rpID`, `rpName`, persistent one-use `challenges` and `credentials` stores, `resolveRegistrationUser`, `auth`, a trusted `resolveClientIp`, and a `rateLimiter`. `auth` is the `createAuth` result. Registration requires an authenticated application user with a stable, non-PII ID of at most 64 UTF-8 bytes. An optional `resolvePendingRegistrationUser` resolver supports passkey-first signup for users without an existing session; it must resolve the pending user from server-side state, never raw client input.

Forward POST `/webauthn/registration/options`, `/webauthn/registration/verify`, `/webauthn/authentication/options`, and `/webauthn/authentication/verify` to the returned handler. It verifies the configured origin and RP ID, requires user verification, and uses one-use challenges. Credential IDs must be unique and counter updates atomic compare-and-set operations. Schedule the returned `cleanupExpired()` method.

## Public entry points

- `@shtora/auth`: `createAuth`, the core types for users, credentials, sessions, rate limiting, policies, email verification, password reset, TOTP, and magic link login, and the TOTP primitives `verifyTotp`, `createTotpSecret`, `createRecoveryCodes`, `createOtpauthUri`, `base32Encode`, `base32Decode`, and `normalizeRecoveryCode`.
- `@shtora/auth/oidc`: `createOidc` and OIDC configuration, transaction-store, and handler types.
- `@shtora/auth/webauthn`: `createWebAuthn` and WebAuthn challenge-store, credential-store, options, and user types.

Install `openid-client` for `@shtora/auth/oidc` and `@simplewebauthn/server` for `@shtora/auth/webauthn`; these optional peer dependencies are not needed by the core entry point.



