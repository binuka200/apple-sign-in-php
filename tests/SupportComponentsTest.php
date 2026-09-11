<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use DateInterval;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SafeApple\SignIn\Cache\ArrayCache;
use SafeApple\SignIn\Contract\Observer;
use SafeApple\SignIn\Support\FlockRefreshLock;
use SafeApple\SignIn\Support\SafeObserver;
use SafeApple\SignIn\Support\SystemClock;

final class SupportComponentsTest extends TestCase
{
    public function testAFailingObserverNeverBreaksAuthentication(): void
    {
        $observer = new SafeObserver(new class implements Observer {
            public function record(string $event, array $context = []): void
            {
                throw new RuntimeException('Metrics backend is down.');
            }
        });

        $observer->record('jwks.cache_hit', ['forced' => false]);

        $this->expectNotToPerformAssertions();
    }

    public function testTheSystemClockReportsTheCurrentTime(): void
    {
        $before = time();

        $now = (new SystemClock())->now()->getTimestamp();

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual(time(), $now);
    }

    public function testTheCacheExpiresValuesAndReportsPresence(): void
    {
        $cache = new ArrayCache();

        $cache->set('fresh', 'value', 3600);
        $cache->set('stale', 'value', 0);

        self::assertSame('value', $cache->get('fresh'));
        self::assertTrue($cache->has('fresh'));
        self::assertNull($cache->get('stale'));
        self::assertFalse($cache->has('stale'));
        self::assertSame('fallback', $cache->get('missing', 'fallback'));
    }

    public function testTheCacheAcceptsAnIntervalTtlAndBulkOperations(): void
    {
        $cache = new ArrayCache();

        $cache->set('interval', 'value', new DateInterval('PT1H'));
        $cache->setMultiple(['a' => 1, 'b' => 2]);

        self::assertSame('value', $cache->get('interval'));
        self::assertSame(['a' => 1, 'b' => 2], iterator_to_array((function () use ($cache): \Generator {
            yield from $cache->getMultiple(['a', 'b']);
        })()));

        $cache->deleteMultiple(['a']);
        self::assertFalse($cache->has('a'));
        self::assertTrue($cache->has('b'));

        $cache->delete('b');
        $cache->set('kept', 'value');
        $cache->clear();
        self::assertFalse($cache->has('kept'));
    }

    public function testTheLockRejectsUnusableConfiguration(): void
    {
        foreach ([['', 250], ['/tmp/apple.lock', -1], ['/tmp/apple.lock', 2001]] as [$path, $wait]) {
            try {
                new FlockRefreshLock($path, $wait);
                self::fail('Expected the invalid lock configuration to be rejected.');
            } catch (InvalidArgumentException $exception) {
                self::assertStringContainsString('Lock path is required', $exception->getMessage());
            }
        }
    }

    public function testTheLockReportsAnUnusableLockFile(): void
    {
        $lock = new FlockRefreshLock(sys_get_temp_dir().'/missing-directory/apple.lock');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('lock file could not be opened');
        $lock->acquire();
    }

    public function testTheLockIsReentrantForTheSameWorker(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'apple-lock');
        self::assertIsString($path);
        $lock = new FlockRefreshLock($path);

        try {
            self::assertTrue($lock->acquire());
            self::assertTrue($lock->acquire());
        } finally {
            $lock->release();
            unlink($path);
        }
    }
}
