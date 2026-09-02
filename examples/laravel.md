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

For account-deletion notifications, verify the signed payload synchronously and
commit it to a durable inbox before returning success. Enforce inbox idempotency
with a database UNIQUE constraint on `jwtId`, then let a queued worker retry the
account mutation locally. Apple redelivery is not guaranteed.

Keep the `.p8` contents in a secret manager or mounted secret file, not in the
repository or `config/services.php`.
