<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\Support\FlockRefreshLock;

final class FlockRefreshLockTest extends TestCase
{
    public function testItSerializesRefreshesWithABoundedWait(): void
    {
        $path = sys_get_temp_dir().'/safe-apple-test-'.bin2hex(random_bytes(8)).'.lock';
        $first = new FlockRefreshLock($path, 0);
        $second = new FlockRefreshLock($path, 20);

        try {
            self::assertTrue($first->acquire());
            self::assertFalse($second->acquire());
            $first->release();
            self::assertTrue($second->acquire());
        } finally {
            $first->release();
            $second->release();
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}
