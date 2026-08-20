# Changelog

## Unreleased

## 0.1.0 - 2026-08-20

- Complete Sign in with Apple authorization, token, refresh, and revocation flow.
- Hardened identity-token verification with issuer, complete audience, `azp`,
  nonce, hybrid-flow `c_hash`, time, subject, algorithm, and token-size checks.
- Side-effect-free server-notification verification so applications can commit
  event idempotency and account changes in one durable transaction.
- Bounded and cached JWKS retrieval with stale fallback, refresh cooldown, and lock support.
- First-login profile parsing, telemetry hooks, and framework examples.
- Expo and React Native integration guide with native iOS and browser-based Android flows.
