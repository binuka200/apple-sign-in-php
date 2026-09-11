# Changelog

## Unreleased

- Raised test coverage of `src` from 77% to over 99%, adding regression tests for
  forged and malformed token signatures, unmatched authorized parties, missing
  subjects, malformed callback and notification payloads, client-secret key
  handling, JWKS refresh-lock contention, and OAuth network and revocation failures.

## 0.1.2 - 2026-09-11

- Added a release workflow that publishes a checksummed source archive with a
  Sigstore build-provenance attestation for every `v*` tag.

## 0.1.1 - 2026-09-02

- Rate-limited unsuccessful forced JWKS refreshes, including stale-only fallback paths.
- Marked browser-posted callback profile data as untrusted and added
  `AppleUserProfile::verifiedEmail()` matching against a verified identity token.
- Replaced assumed Apple notification redelivery with durable-inbox and local-retry guidance.
- Added regression coverage for failed refresh cooldowns and tampered callback email values.

## 0.1.0 - 2026-08-20

- Complete Sign in with Apple authorization, token, refresh, and revocation flow.
- Hardened identity-token verification with issuer, complete audience, `azp`,
  nonce, hybrid-flow `c_hash`, time, subject, algorithm, and token-size checks.
- Side-effect-free server-notification verification so applications can commit
  event idempotency and account changes in one durable transaction.
- Bounded and cached JWKS retrieval with stale fallback, refresh cooldown, and lock support.
- First-login profile parsing, telemetry hooks, and framework examples.
- Expo and React Native integration guide with native iOS and browser-based Android flows.
- Reproducible lint, static-analysis, test, advisory, and lowest-dependency CI checks.
- PHP 8.1-compatible immutable value objects using readonly properties.
