# Contributing

## Scope

Keep the core runtime-neutral and focused on auth handlers and sessions. Database schemas, password hashing, credential verification, and user records belong to the consuming application. Put runtime-specific adapters behind their existing package entry points.

## Local checks

Use Bun and run from the repository root:

```sh
bun install
bun run typecheck
bun test
bun run build
```

The test suite must not depend on external services or production credentials. If a change needs an integration environment, document the exact setup and keep its test data isolated.

## Changes

- Add tests for externally observable behavior, security boundaries, and state transitions.
- Update the README when changing a public API, contract, or supported integration.
- Keep documentation in English and use concrete, tested examples.
- Avoid generated boilerplate, unused abstractions, and new dependencies without a clear need.
- Do not commit build output, credentials, real user data, or environment files.
- For authentication changes, describe the threat or invariant the change addresses and any consumer migration required.

## Pull requests

Explain the user-visible change, its security implications, and the checks you ran. Complete the checklist in the pull request template; mark a check not applicable only with a short reason.

For a suspected vulnerability, do not publish exploit details, tokens, or personal data in a public issue. Use the repository's private vulnerability-reporting channel when available, or contact a maintainer privately.
