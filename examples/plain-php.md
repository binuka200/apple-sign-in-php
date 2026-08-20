# Plain PHP integration

Bootstrap the shared objects once in your dependency container:

```php
$keys = new SafeApple\SignIn\AppleJwksProvider($sharedPsr16Cache);
$verify = new SafeApple\SignIn\AppleIdentityTokenVerifier($keys, $_ENV['APPLE_CLIENT_ID']);
$secret = SafeApple\SignIn\ClientSecretGenerator::fromKeyFile(
    $_ENV['APPLE_TEAM_ID'],
    $_ENV['APPLE_CLIENT_ID'],
    $_ENV['APPLE_KEY_ID'],
    $_ENV['APPLE_PRIVATE_KEY_PATH'],
);
$oauth = new SafeApple\SignIn\AppleOAuthClient($_ENV['APPLE_CLIENT_ID'], $secret);
```

Store a generated `LoginChallenge` in `$_SESSION` before redirecting. On the
callback, remove it from the session, parse `$_POST` with
`AppleAuthorizationResponse::fromPost()`, verify the callback ID token with
`verifyAuthorizationResponse()` to bind it to the code, exchange the code, and
verify the returned identity token. Require both verified tokens to have the
same subject. Regenerate the PHP session ID after successful login.

Treat first-login name fields as user-controlled text and escape them for the
HTML, JSON, or other output context where they are displayed.

Do not use `ArrayCache` under PHP-FPM: it does not persist between requests.
