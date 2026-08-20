# Expo and React Native integration

This package runs in your PHP API. It is not installed in the mobile app.
Expo or React Native obtains an Apple credential from the operating system and
sends the credential to PHP. PHP verifies Apple's signature, nonce, audience,
issuer, and times before creating your application's own session.

```text
Mobile app              Apple                 PHP API
    |                      |                      |
    |-- request challenge ---------------------->|
    |<-- state, nonce, challenge ID -------------|
    |-- native Apple sign-in -->|                 |
    |<-- identity token + code -|                 |
    |-- token, code, challenge ID, state -------->|
    |                      |<-- exchange code ----|
    |<-- application session --------------------|
```

## Platform support

| Platform | Recommended flow | Apple client ID |
|---|---|---|
| Expo iOS/tvOS | `expo-apple-authentication` | Native bundle/App ID |
| Bare React Native iOS | Native Authentication Services wrapper | Native bundle/App ID |
| Android | Browser authorization through the PHP backend | Services ID |
| Web | Browser authorization through the PHP backend | Services ID |

Expo's Apple Authentication module is native to iOS and tvOS. Do not attempt to
use it as the Android or web implementation.

## 1. Configure Apple and PHP

For native iOS, use the application's bundle identifier as the client ID:

```php
use SafeApple\SignIn\AppleIdentityTokenVerifier;
use SafeApple\SignIn\AppleJwksProvider;
use SafeApple\SignIn\AppleOAuthClient;
use SafeApple\SignIn\ClientSecretGenerator;

$nativeClientId = 'com.example.mobile';
$webClientId = 'com.example.web';

$jwks = new AppleJwksProvider($sharedPsr16Cache);
$verifier = new AppleIdentityTokenVerifier(
    $jwks,
    [$nativeClientId, $webClientId],
    leeway: 30,
);

$nativeSecret = ClientSecretGenerator::fromKeyFile(
    teamId: $_ENV['APPLE_TEAM_ID'],
    clientId: $nativeClientId,
    keyId: $_ENV['APPLE_KEY_ID'],
    privateKeyPath: $_ENV['APPLE_PRIVATE_KEY_PATH'],
);

$nativeOAuth = new AppleOAuthClient($nativeClientId, $nativeSecret);
```

Create separate `ClientSecretGenerator` and `AppleOAuthClient` objects for a
Services ID. Never accept a client ID from the mobile request and use it to
select credentials. Select the configured client on a route controlled by your
server, such as `/auth/apple/native` or `/auth/apple/browser`.

## 2. Add Apple Authentication to Expo

Install the package with Expo's version-aware installer:

```bash
npx expo install expo-apple-authentication expo-secure-store
```

Enable the native entitlement and config plugin:

```json
{
  "expo": {
    "ios": {
      "bundleIdentifier": "com.example.mobile",
      "usesAppleSignIn": true
    },
    "plugins": [
      "expo-apple-authentication",
      "expo-secure-store"
    ]
  }
}
```

The bundle identifier must match the native client ID configured in PHP and in
Apple Developer. Build a new native binary after changing capabilities.

## 3. Create a one-time challenge endpoint

Generate state and nonce on the server. Store them under an opaque challenge ID
for approximately five minutes. The client receives the values Apple needs, but
the server retains the authoritative copy.

```php
use SafeApple\SignIn\LoginChallenge;

$challenge = LoginChallenge::generate();
$challengeId = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

$sharedPsr16Cache->set(
    'apple.mobile.challenge.'.hash('sha256', $challengeId),
    [
        'state' => $challenge->state,
        'nonce' => $challenge->nonce,
    ],
    300,
);

header('Content-Type: application/json');
echo json_encode([
    'challengeId' => $challengeId,
    'state' => $challenge->state,
    'nonce' => $challenge->nonce,
], JSON_THROW_ON_ERROR);
```

In a real application, also bind the cache entry to the device installation or
pre-login session. Rate-limit both mobile authentication endpoints.

## 4. Request the Apple credential in Expo

The following implementation performs two network requests: one to obtain the
challenge and one to submit Apple's result. It deliberately does not retry the
second request because the authorization code is single-use.

```tsx
import * as AppleAuthentication from "expo-apple-authentication";
import * as SecureStore from "expo-secure-store";
import { fetch } from "expo/fetch";

const API_URL = process.env.EXPO_PUBLIC_API_URL;
const SESSION_KEY = "application_session";

type Challenge = {
  challengeId: string;
  state: string;
  nonce: string;
};

type SessionResponse = {
  accessToken: string;
  user: {
    id: string;
    displayName: string | null;
  };
};

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });

    const data = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(
        data?.message ?? `Authentication request failed (${response.status})`,
      );
    }
    return data as T;
  } finally {
    clearTimeout(timeout);
  }
}

export async function signInWithApple(): Promise<SessionResponse> {
  const available = await AppleAuthentication.isAvailableAsync();
  if (!available) {
    throw new Error("Sign in with Apple is unavailable on this device");
  }

  const challenge = await postJson<Challenge>("/auth/apple/mobile/challenge");

  const credential = await AppleAuthentication.signInAsync({
    requestedScopes: [
      AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
      AppleAuthentication.AppleAuthenticationScope.EMAIL,
    ],
    state: challenge.state,
    nonce: challenge.nonce,
  });

  if (!credential.identityToken || !credential.authorizationCode) {
    throw new Error("Apple did not return the required credentials");
  }

  const session = await postJson<SessionResponse>("/auth/apple/mobile", {
    challengeId: challenge.challengeId,
    state: credential.state,
    identityToken: credential.identityToken,
    authorizationCode: credential.authorizationCode,
    email: credential.email,
    fullName: credential.fullName,
  });

  await SecureStore.setItemAsync(SESSION_KEY, session.accessToken);
  return session;
}
```

Render Apple's native button rather than a generic pressable:

```tsx
import * as AppleAuthentication from "expo-apple-authentication";

export function AppleSignInButton() {
  return (
    <AppleAuthentication.AppleAuthenticationButton
      buttonType={AppleAuthentication.AppleAuthenticationButtonType.SIGN_IN}
      buttonStyle={AppleAuthentication.AppleAuthenticationButtonStyle.BLACK}
      cornerRadius={8}
      style={{ width: 240, height: 48 }}
      onPress={() => {
        signInWithApple().catch((error) => {
          if (error?.code !== "ERR_REQUEST_CANCELED") {
            // Present a generic, retryable login error to the user.
          }
        });
      }}
    />
  );
}
```

Do not log `identityToken`, `authorizationCode`, nonce, or the resulting
application session token.

## 5. Verify the mobile credential in PHP

Retrieve and delete the challenge before processing the credential. This makes
the server-side challenge single-use even when an attacker replays the request.

```php
use SafeApple\SignIn\Exception\InvalidIdentityToken;
use SafeApple\SignIn\LoginChallenge;

$payload = json_decode(
    file_get_contents('php://input'),
    true,
    16,
    JSON_THROW_ON_ERROR,
);

if (!is_array($payload) || !is_string($payload['challengeId'] ?? null)) {
    throw new RuntimeException('Invalid request.');
}

$challengeKey = 'apple.mobile.challenge.'.hash('sha256', $payload['challengeId']);
$stored = $sharedPsr16Cache->get($challengeKey);
$sharedPsr16Cache->delete($challengeKey);

if (!is_array($stored)
    || !is_string($stored['state'] ?? null)
    || !is_string($stored['nonce'] ?? null)
) {
    throw new RuntimeException('Apple challenge expired.');
}

$challenge = new LoginChallenge($stored['state'], $stored['nonce']);
$challenge->assertState(is_string($payload['state'] ?? null) ? $payload['state'] : '');

$identityToken = is_string($payload['identityToken'] ?? null)
    ? $payload['identityToken']
    : '';
$authorizationCode = is_string($payload['authorizationCode'] ?? null)
    ? $payload['authorizationCode']
    : '';

// Local verification happens before making an outbound Apple request. This also
// proves that the callback ID token and authorization code belong together.
$mobileIdentity = $verifier->verifyAuthorizationResponse(
    $identityToken,
    $authorizationCode,
    $challenge->nonce,
);

$tokens = $nativeOAuth->exchangeAuthorizationCode($authorizationCode);
$exchangedIdentity = $verifier->verify($tokens->identityToken, $challenge->nonce);
if (!hash_equals($mobileIdentity->subject, $exchangedIdentity->subject)) {
    throw new InvalidIdentityToken('Apple identities do not match.');
}

// Find or create the local user using only the verified Apple subject.
$user = findOrCreateUserByAppleSubject($exchangedIdentity->subject);
$applicationToken = issueApplicationSession($user);

header('Content-Type: application/json');
echo json_encode([
    'accessToken' => $applicationToken,
    'user' => [
        'id' => $user->id,
        'displayName' => $user->displayName,
    ],
], JSON_THROW_ON_ERROR);
```

The mobile-supplied `email`, `fullName`, and `credential.user` are not identity
proof. Use the verified JWT `sub` as the provider key. If the client sends an
email, compare it with the verified token email before storing it. Treat the
name only as first-login profile data and sanitize it for display.

Store Apple's refresh token encrypted on the server if you need session checks
or later revocation. Never return the Apple refresh token or client secret to
the mobile application.

## Bare React Native

For a bare iOS project, use a maintained native wrapper around Apple's
Authentication Services framework and enable the Sign in with Apple capability
in Xcode. The returned values must be mapped to the same PHP request:

```ts
{
  challengeId,
  state,
  identityToken,
  authorizationCode,
  email,
  fullName,
}
```

The PHP verification and token-exchange code is identical. Check the wrapper's
nonce contract carefully: pass the exact expected nonce claim to
`AppleIdentityTokenVerifier::verifyAuthorizationResponse()`. If the wrapper
hashes a raw nonce before sending it to Apple, PHP must verify the hash rather
than the raw value.

## Android and browser-based mobile login

Apple's native Expo module does not implement Android. Use the web authorization
flow with a Services ID:

1. The app opens a PHP `/auth/apple/browser/start` endpoint in the system browser.
2. PHP creates and stores a `LoginChallenge`, then redirects to the URL produced
   by `AuthorizationUrlBuilder`.
3. Apple form-posts to the registered HTTPS PHP callback.
4. PHP parses `AppleAuthorizationResponse`, verifies the callback token's nonce
   and `c_hash`, exchanges the code, and verifies the token-endpoint identity.
5. PHP creates a short-lived, one-time handoff code and redirects to an allowlisted
   universal link or application link.
6. The app exchanges that handoff code for its application session.

Never place Apple tokens, authorization codes, or your application bearer token
in a deep-link URL. Only include an opaque, single-use handoff code. Do not accept
an arbitrary return URL from the app; use an allowlist configured on the server.

## Sign-out and account deletion

Normal app sign-out removes the application session from Secure Store and
invalidates it on your API. It does not need to invoke Apple's sign-out UI.

When a user disconnects Apple or deletes their account, revoke the stored Apple
refresh token on the server:

```php
$nativeOAuth->revoke($decryptedRefreshToken, 'refresh_token');
```

Also configure `AppleNotificationVerifier` so consent revocation and Apple
account deletion invalidate local sessions even when the action begins outside
your application.

## Production checklist

- Use HTTPS for every API request.
- Generate state and nonce on PHP and consume the challenge once.
- Rate-limit challenge and credential endpoints.
- Do not automatically retry the credential-submission request.
- Verify signature, issuer, complete audience set, `azp`, nonce, `c_hash`,
  expiry, and subject on PHP.
- Exchange the authorization code on PHP, never in the mobile app.
- Use JWT `sub`, not email or the client-provided user value, as the account key.
- Persist first-login name data immediately; it is usually not returned again.
- Encrypt Apple refresh tokens at rest and never send them to the app.
- Store only your own application session in Secure Store.
- Configure revocation and account-deletion notifications.
- Test cancellation, offline requests, expired challenges, replay attempts, and
  reinstall/sign-in-again behavior on a physical device.

## Troubleshooting

### `invalid_client`

Confirm that the native bundle ID, PHP client ID, client-secret `sub`, Apple App
ID, Team ID, key ID, and `.p8` key all belong to the same Apple configuration.

### `invalid_grant`

The code may be expired, already consumed, issued for another client ID, or
submitted with a mismatched redirect URI. Start a fresh Apple authorization;
do not retry the same code automatically.

### Audience validation fails

Inspect the token only in a secure development environment and ensure its `aud`
is included in the server's configured audience list. Never weaken or skip the
audience check.

### Nonce validation fails

Verify whether the mobile wrapper sends the raw nonce or a SHA-256 digest to
Apple. PHP must compare against the exact value stored in the identity token's
`nonce` claim.

### Name or email is `null`

Apple commonly returns profile fields only on the first authorization, and the
user may decline a scope. Persist available first-login data immediately and
design the account UI to tolerate missing fields.

## References

- [Expo Apple Authentication](https://docs.expo.dev/versions/latest/sdk/apple-authentication/)
- [Expo Secure Store](https://docs.expo.dev/versions/latest/sdk/securestore/)
- [Apple Authentication Services](https://developer.apple.com/documentation/authenticationservices/)
- [Apple authorization code](https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidcredential/authorizationcode)
- [Apple Sign in REST API](https://developer.apple.com/documentation/signinwithapplerestapi)
