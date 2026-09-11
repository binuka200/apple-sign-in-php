# Safe Apple Sign In for PHP

[![CI](https://github.com/binuka200/apple-sign-in-php/actions/workflows/ci.yml/badge.svg)](https://github.com/binuka200/apple-sign-in-php/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/binuka200/apple-sign-in)](https://packagist.org/packages/binuka200/apple-sign-in)
[![PHP Version](https://img.shields.io/packagist/dependency-v/binuka200/apple-sign-in/php)](https://packagist.org/packages/binuka200/apple-sign-in)
[![License](https://img.shields.io/packagist/l/binuka200/apple-sign-in)](LICENSE)

A framework-neutral, defensive implementation of the complete Sign in with
Apple server lifecycle for PHP 8.1+.

It replaces abandoned packages that vendor old JWT code or fetch Apple's keys
on every login request. It does not create application sessions, users, routes,
or database records; those decisions remain in your application.

This is an independent community project and is not affiliated with or endorsed
by Apple Inc.

## Included

- State- and nonce-protected authorization URLs and callback parsing.
- ES256 client-secret generation from Apple's `.p8` key.
- Authorization-code exchange, refresh-token validation, and token revocation.
- RS256 identity-token verification with issuer, audience, time, subject, and
  optional nonce validation.
- First-authorization name and email parsing, explicitly treated as
  browser-posted profile data rather than identity proof.
- Side-effect-free typed server notification verification for account deletion,
  revoked consent, and private-email forwarding changes.
- PSR-16 JWKS caching, strict network bounds, one JWKS retry, stale-key fallback,
  forced-refresh rate limiting, and an optional cross-worker refresh lock.
- Observer hooks for metrics and structured logging without exposing secrets.

## Install

```bash
composer require binuka200/apple-sign-in
```

## Configuration

You need the following values from Apple Developer:

- Team ID
- App ID or Services ID, used as the client ID and token audience
- Sign in with Apple key ID
- Downloaded `.p8` private-key file
- Registered HTTPS callback URI

Use a shared PSR-16 cache such as Redis in production. `ArrayCache` is only for
tests and one-process examples.

```php
use SafeApple\SignIn\AppleIdentityTokenVerifier;
use SafeApple\SignIn\AppleJwksProvider;
use SafeApple\SignIn\AppleOAuthClient;
use SafeApple\SignIn\ClientSecretGenerator;
use SafeApple\SignIn\Support\FlockRefreshLock;

$jwks = new AppleJwksProvider(
    cache: $sharedPsr16Cache,
    refreshLock: new FlockRefreshLock('/run/lock/my-app-apple-jwks.lock'),
);

$verifier = new AppleIdentityTokenVerifier(
    $jwks,
    ['com.example.app', 'com.example.web'],
    leeway: 30,
);

$clientSecret = ClientSecretGenerator::fromKeyFile(
    teamId: $_ENV['APPLE_TEAM_ID'],
    clientId: $_ENV['APPLE_CLIENT_ID'],
    keyId: $_ENV['APPLE_KEY_ID'],
    privateKeyPath: $_ENV['APPLE_PRIVATE_KEY_PATH'],
);

$oauth = new AppleOAuthClient($_ENV['APPLE_CLIENT_ID'], $clientSecret);
```

The default client secret lasts five minutes and is generated for each API
operation. Apple permits a maximum lifetime of 15,777,000 seconds.

## Start authorization

Generate a challenge, store both values in the user's server-side session, then
redirect to Apple:

```php
use SafeApple\SignIn\AuthorizationUrlBuilder;
use SafeApple\SignIn\LoginChallenge;

$challenge = LoginChallenge::generate();
$_SESSION['apple_challenge'] = [
    'state' => $challenge->state,
    'nonce' => $challenge->nonce,
];

$authorization = new AuthorizationUrlBuilder(
    $_ENV['APPLE_CLIENT_ID'],
    'https://example.com/auth/apple/callback',
);

header('Location: '.$authorization->build($challenge));
```

## Handle the callback

Consume the stored challenge once. Parsing the callback first validates `state`.
Then verify that the callback ID token is bound to the single-use code, exchange
the code, and verify the resulting identity token with the original nonce.

```php
use SafeApple\SignIn\AppleAuthorizationResponse;
use SafeApple\SignIn\LoginChallenge;

$stored = $_SESSION['apple_challenge'] ?? null;
unset($_SESSION['apple_challenge']);

if (!is_array($stored)) {
    throw new RuntimeException('Apple login session expired.');
}

$challenge = new LoginChallenge($stored['state'], $stored['nonce']);
$callback = AppleAuthorizationResponse::fromPost($_POST, $challenge);
$callbackIdentity = $verifier->verifyAuthorizationResponse(
    $callback->identityToken,
    $callback->code,
    $challenge->nonce,
);

$tokens = $oauth->exchangeAuthorizationCode(
    $callback->code,
    'https://example.com/auth/apple/callback',
);

$identity = $verifier->verify($tokens->identityToken, $challenge->nonce);
if (!hash_equals($callbackIdentity->subject, $identity->subject)) {
    throw new RuntimeException('Apple identities do not match.');
}

// Use this as the stable provider identity. Never use email as the key.
$appleSubject = $identity->subject;

// The callback `user` object is browser-posted and is not signed. This helper
// returns its email only when it matches the verified identity-token email.
$verifiedProfileEmail = $callback->user?->verifiedEmail($identity);

// Apple only supplies the name on the first authorization. Persist it now.
// It is user-controlled text: escape it for the eventual output context.
$firstName = $callback->user?->firstName;
$lastName = $callback->user?->lastName;

// Store refresh tokens encrypted at rest.
$refreshToken = $tokens->refreshToken;
```

For native applications that send a SHA-256 nonce to Apple, verify against
`$challenge->hashedNonce()` instead of the raw nonce.

## Refresh and revoke

```php
$tokens = $oauth->refresh($encryptedRefreshTokenAfterDecryption);

// When the local account is deleted or disconnected:
$oauth->revoke($refreshToken, 'refresh_token');
```

Authorization-code requests are not automatically retried because the code is
single-use. A successful Apple response lost in transit cannot safely be replayed.

## Server-to-server notifications

Configure the endpoint in Apple Developer. Verification deliberately has no
side effects:

```php
use SafeApple\SignIn\AppleAccountEvent;
use SafeApple\SignIn\AppleNotificationVerifier;

$notifications = new AppleNotificationVerifier(
    $jwks,
    ['com.example.app', 'com.example.web'],
);

$event = $notifications->verify($_POST['payload']);

// Before returning success, insert the verified event into a durable inbox or
// queue under a UNIQUE constraint on jwtId. A worker can then retry processing
// locally and idempotently until the account change succeeds.
enqueueAppleEventOnce($event);

http_response_code(204);
```

Apple describes each event as expected to be delivered once. Duplicate events
may occur, but they are not a redelivery guarantee. Commit durable intake before
returning a success status, retry account mutations from your own queue, and use
monitoring plus reconciliation where possible. If verification or durable intake
fails, return a non-success status and alert; do not rely on Apple to send the
event again. See [Apple's DTS guidance on notification delivery](https://developer.apple.com/forums/thread/809509).

PSR-16 cannot express an atomic insert-if-absent operation. Use a database or
durable queue with a unique key on `jwtId` for inbox idempotency.

## Resilience and telemetry

JWKS responses are fresh for one hour and retained as a stale fallback for 24
hours. Successful and failed refresh attempts enter the forced-refresh cooldown,
so repeated unknown key IDs cannot cause sequential network requests every time.
Configure `FlockRefreshLock` to make this protection atomic between PHP-FPM
workers on the same filesystem. Distributed deployments can implement
`RefreshLock` using their existing Redis or database lock.

Implement `Observer` to forward safe events such as `jwks.cache_hit`,
`jwks.stale_fallback`, `oauth.token_succeeded`, and `oauth.token_rejected` to
your logger or metrics system. Context never includes codes, tokens, client
secrets, or private keys.

## Framework examples

- [Expo and React Native mobile apps](docs/mobile-apps.md)
- [Plain PHP](examples/plain-php.md)
- [Laravel](examples/laravel.md)
- [Symfony](examples/symfony.md)

## Failure behavior

Failures while communicating with Apple or verifying Apple data extend
`AppleSignInException`. Important subclasses are:

- `InvalidIdentityToken`, `UnknownKeyId`
- `StateMismatch`, `InvalidAuthorizationResponse`
- `AppleApiException`, `AppleApiUnavailable`
- `InvalidNotification`
- `JwksUnavailable`, `InvalidConfiguration`

Invalid credential and endpoint configuration uses `InvalidConfiguration`.
Other invalid method or constructor arguments use PHP's
`InvalidArgumentException`. Infrastructure failures from an injected cache or
refresh-lock implementation may retain the exception type supplied by that
implementation.

Map detailed failures to a generic login error at the public boundary. Never
return raw Apple errors, tokens, codes, or claims to an unauthenticated client.

## Development

```bash
composer install
composer check
composer audit --locked
```

CI covers PHP 8.1 through 8.5, including the lowest supported dependency set.
The codebase is checked at PHPStan level 8 and dependencies are audited for
published security advisories. Use a PHP branch that still receives upstream
security fixes in production.

A separate job measures line coverage of `src` and fails when it drops below
the committed floor:

```bash
composer coverage
```

## Versioning and support

Releases follow [Semantic Versioning](https://semver.org/). Before 1.0, minor
releases may include documented breaking changes; patch releases are intended
to remain backward compatible. Only the latest release receives security fixes.

Each GitHub release ships a source archive with a SHA-256 checksum and a
Sigstore build-provenance attestation produced by the release workflow. To
confirm an archive was built from this repository:

```bash
gh attestation verify apple-sign-in-php-<version>.tar.gz --repo binuka200/apple-sign-in-php
sha256sum -c apple-sign-in-php-<version>.tar.gz.sha256
```

Release tags are protected against deletion and rewriting, so a published
version always points at the same commit.

## License

MIT
