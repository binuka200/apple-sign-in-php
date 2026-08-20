# Laravel integration

Bind a PSR-16 cache adapter, then register the Apple services as container
singletons in a service provider:

```php
$this->app->singleton(AppleJwksProvider::class, fn ($app) =>
    new AppleJwksProvider($app->make(Psr\SimpleCache\CacheInterface::class))
);

$this->app->singleton(AppleIdentityTokenVerifier::class, fn ($app) =>
    new AppleIdentityTokenVerifier(
        $app->make(AppleJwksProvider::class),
        [config('services.apple.client_id')],
        30,
    )
);
```

Store `state` and `nonce` with Laravel's session service and remove them with
`pull()` in the callback. Verify the callback token with
`verifyAuthorizationResponse()` before exchanging its code.

Use queued jobs for account-deletion notifications, but verify the signed
payload synchronously before dispatching the job. Enforce idempotency with a
database UNIQUE constraint on `jwtId`; record it in the same transaction as the
account mutation so failed work remains retryable.

Keep the `.p8` contents in a secret manager or mounted secret file, not in the
repository or `config/services.php`.
