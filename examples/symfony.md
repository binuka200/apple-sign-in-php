# Symfony integration

Use Symfony Cache's PSR-16 adapter and inject the existing HTTP client:

```yaml
# config/services.yaml
services:
  SafeApple\SignIn\AppleJwksProvider:
    arguments:
      $cache: '@cache.app.simple'
      $httpClient: '@http_client'

  SafeApple\SignIn\AppleIdentityTokenVerifier:
    arguments:
      $audiences: ['%env(APPLE_CLIENT_ID)%']
      $leeway: 30
```

Store the challenge in Symfony's session, remove it when processing the
callback, verify the callback ID token with `verifyAuthorizationResponse()`,
and rotate the session ID after successful authentication. Configure the HTTP
client globally with TLS verification enabled; this package still adds strict
per-request timeout and maximum-duration options.

For telemetry, implement `Observer` with a small adapter that forwards event
names and safe context to a PSR-3 logger and your metrics client.
