<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use Psr\SimpleCache\CacheInterface;
use SafeApple\SignIn\Contract\JwksProvider;
use SafeApple\SignIn\Contract\Observer;
use SafeApple\SignIn\Contract\RefreshLock;
use SafeApple\SignIn\Exception\JwksUnavailable;
use SafeApple\SignIn\Support\NullObserver;
use SafeApple\SignIn\Support\SafeObserver;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\RetryableHttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class AppleJwksProvider implements JwksProvider
{
    public const ENDPOINT = 'https://appleid.apple.com/auth/keys';

    private readonly Observer $observer;

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly ?HttpClientInterface $httpClient = null,
        private readonly int $ttl = 3600,
        private readonly string $cacheKey = 'safe_apple.sign_in.jwks',
        private readonly int $refreshCooldown = 60,
        private readonly int $staleTtl = 86400,
        ?Observer $observer = null,
        private readonly ?RefreshLock $refreshLock = null,
    ) {
        if ($ttl < 1) {
            throw new \InvalidArgumentException('JWKS cache TTL must be positive.');
        }
        if ($refreshCooldown < 0) {
            throw new \InvalidArgumentException('JWKS refresh cooldown cannot be negative.');
        }
        if ($staleTtl < $ttl) {
            throw new \InvalidArgumentException('JWKS stale TTL must be at least as long as its fresh TTL.');
        }
        $this->observer = new SafeObserver($observer ?? new NullObserver());
    }

    public function get(bool $forceRefresh = false): array
    {
        $cached = $this->cache->get($this->cacheKey);
        if ($this->isValidKeySet($cached)) {
            if (!$forceRefresh || $this->refreshIsCoolingDown()) {
                $this->observer->record('jwks.cache_hit', ['forced' => $forceRefresh]);
                return $cached;
            }
        }

        if ($this->refreshLock !== null) {
            if (!$this->refreshLock->acquire()) {
                $fallback = $this->fallback($cached);
                if ($fallback !== null) {
                    $this->observer->record('jwks.lock_fallback', ['forced' => $forceRefresh]);
                    return $fallback;
                }
                throw new JwksUnavailable('Apple signing keys are being refreshed by another worker.');
            }

            try {
                $latest = $this->cache->get($this->cacheKey);
                if ($this->isValidKeySet($latest)
                    && (!$forceRefresh || $this->refreshIsCoolingDown())
                ) {
                    $this->observer->record('jwks.cache_hit_after_lock', ['forced' => $forceRefresh]);
                    return $latest;
                }
                return $this->fetch($forceRefresh, $this->isValidKeySet($latest) ? $latest : $cached);
            } finally {
                $this->refreshLock->release();
            }
        }

        return $this->fetch($forceRefresh, $cached);
    }

    /** @param mixed $cached
     *  @return array{keys: list<array<string, mixed>>}
     */
    private function fetch(bool $forceRefresh, mixed $cached): array
    {

        try {
            $client = $this->httpClient ?? new RetryableHttpClient(
                HttpClient::create(['timeout' => 2.0, 'max_duration' => 4.0]),
                null,
                1,
            );
            $response = $client->request('GET', self::ENDPOINT, [
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 2.0,
                'max_duration' => 4.0,
            ]);
            $data = $response->toArray();
        } catch (HttpException | \JsonException $exception) {
            $fallback = $this->fallback($cached);
            if ($fallback !== null) {
                $this->observer->record('jwks.stale_fallback', ['forced' => $forceRefresh]);
                return $fallback;
            }
            $this->observer->record('jwks.fetch_failed', ['forced' => $forceRefresh]);
            throw new JwksUnavailable('Could not retrieve Apple signing keys.', 0, $exception);
        }

        if (!$this->isValidKeySet($data)) {
            throw new JwksUnavailable('Apple returned an invalid signing-key document.');
        }

        $this->cache->set($this->cacheKey, $data, $this->ttl);
        $this->cache->set($this->cacheKey.'.stale', $data, $this->staleTtl);
        $this->cache->set($this->cacheKey.'.refreshed_at', time(), $this->ttl);
        $this->observer->record('jwks.refreshed', ['forced' => $forceRefresh]);
        return $data;
    }

    /** @return array{keys: list<array<string, mixed>>}|null */
    private function fallback(mixed $cached): ?array
    {
        $fallback = $this->isValidKeySet($cached)
            ? $cached
            : $this->cache->get($this->cacheKey.'.stale');
        return $this->isValidKeySet($fallback) ? $fallback : null;
    }

    private function refreshIsCoolingDown(): bool
    {
        if ($this->refreshCooldown === 0) {
            return false;
        }

        $refreshedAt = $this->cache->get($this->cacheKey.'.refreshed_at');
        return is_int($refreshedAt) && $refreshedAt > time() - $this->refreshCooldown;
    }

    /** @phpstan-assert-if-true array{keys: list<array<string, mixed>>} $value */
    private function isValidKeySet(mixed $value): bool
    {
        if (!is_array($value) || !isset($value['keys']) || !is_array($value['keys'])
            || !array_is_list($value['keys']) || $value['keys'] === []
        ) {
            return false;
        }

        foreach ($value['keys'] as $key) {
            if (!is_array($key) || !isset($key['kid'], $key['kty'], $key['n'], $key['e'])) {
                return false;
            }
        }

        return true;
    }
}
