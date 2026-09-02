<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleJwksProvider;
use SafeApple\SignIn\Cache\ArrayCache;
use SafeApple\SignIn\Exception\JwksUnavailable;
use SafeApple\SignIn\Tests\Support\RecordingObserver;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class AppleJwksProviderTest extends TestCase
{
    /** @var array{keys: list<array<string, string>>} */
    private array $keySet = [
        'keys' => [[
            'kid' => 'key-1',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'n' => 'modulus',
            'e' => 'AQAB',
        ]],
    ];

    public function testItCachesTheJwks(): void
    {
        $responses = 0;
        $client = new MockHttpClient(function (string $method, string $url, array $options) use (&$responses): MockResponse {
            $responses++;
            self::assertSame('GET', $method);
            self::assertSame(AppleJwksProvider::ENDPOINT, $url);
            self::assertSame(2.0, $options['timeout']);
            self::assertSame(4.0, $options['max_duration']);
            return new MockResponse(json_encode($this->keySet, JSON_THROW_ON_ERROR));
        });
        $provider = new AppleJwksProvider(new ArrayCache(), $client);

        self::assertSame($this->keySet, $provider->get());
        self::assertSame($this->keySet, $provider->get());
        self::assertSame(1, $responses);
    }

    public function testAForcedRefreshBypassesTheCache(): void
    {
        $client = new MockHttpClient([
            new MockResponse(json_encode($this->keySet, JSON_THROW_ON_ERROR)),
            new MockResponse(json_encode($this->keySet, JSON_THROW_ON_ERROR)),
        ]);
        $provider = new AppleJwksProvider(new ArrayCache(), $client, refreshCooldown: 0);

        $provider->get();
        $provider->get(true);

        self::assertSame(2, $client->getRequestsCount());
    }

    public function testItRateLimitsForcedRefreshesForAttackerControlledKeyIds(): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode($this->keySet, JSON_THROW_ON_ERROR)));
        $provider = new AppleJwksProvider(new ArrayCache(), $client);

        $provider->get();
        $provider->get(true);
        $provider->get(true);

        self::assertSame(1, $client->getRequestsCount());
    }

    public function testItRateLimitsRepeatedFailedForcedRefreshes(): void
    {
        $cache = new ArrayCache();
        $cache->set('safe_apple.sign_in.jwks', $this->keySet, 3600);
        $client = new MockHttpClient(
            static fn (): MockResponse => new MockResponse('', ['error' => 'network unavailable']),
        );
        $provider = new AppleJwksProvider($cache, $client);

        self::assertSame($this->keySet, $provider->get(true));
        self::assertSame($this->keySet, $provider->get(true));

        self::assertSame(1, $client->getRequestsCount());
        self::assertIsInt($cache->get('safe_apple.sign_in.jwks.last_attempt_at'));
    }

    public function testItAppliesFailedRefreshCooldownToStaleOnlyFallbacks(): void
    {
        $cache = new ArrayCache();
        $cache->set('safe_apple.sign_in.jwks.stale', $this->keySet, 3600);
        $client = new MockHttpClient(
            static fn (): MockResponse => new MockResponse('', ['error' => 'network unavailable']),
        );
        $provider = new AppleJwksProvider($cache, $client);

        self::assertSame($this->keySet, $provider->get(true));
        self::assertSame($this->keySet, $provider->get(true));

        self::assertSame(1, $client->getRequestsCount());
    }

    public function testItRejectsAnInvalidJwksDocument(): void
    {
        $client = new MockHttpClient(new MockResponse('{"keys":[]}'));
        $provider = new AppleJwksProvider(new ArrayCache(), $client);

        $this->expectException(JwksUnavailable::class);
        $this->expectExceptionMessage('invalid signing-key document');
        $provider->get();
    }

    public function testItWrapsNetworkFailures(): void
    {
        $client = new MockHttpClient(new MockResponse('', ['error' => 'network unavailable']));
        $provider = new AppleJwksProvider(new ArrayCache(), $client);

        $this->expectException(JwksUnavailable::class);
        $provider->get();
    }

    public function testItUsesStaleKeysDuringAShortAppleOutage(): void
    {
        $cache = new ArrayCache();
        $cache->set('safe_apple.sign_in.jwks.stale', $this->keySet, 3600);
        $observer = new RecordingObserver();
        $client = new MockHttpClient(new MockResponse('', ['error' => 'network unavailable']));
        $provider = new AppleJwksProvider($cache, $client, observer: $observer);

        self::assertSame($this->keySet, $provider->get());
        self::assertSame('jwks.stale_fallback', $observer->records[0]['event']);
    }
}
