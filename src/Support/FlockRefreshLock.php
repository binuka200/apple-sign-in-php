<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Support;

use SafeApple\SignIn\Contract\RefreshLock;

final class FlockRefreshLock implements RefreshLock
{
    /** @var resource|null */
    private mixed $handle = null;

    public function __construct(
        private readonly string $path,
        private readonly int $waitMilliseconds = 250,
    ) {
        if ($path === '' || $waitMilliseconds < 0 || $waitMilliseconds > 2000) {
            throw new \InvalidArgumentException('Lock path is required and wait must be between 0 and 2000 milliseconds.');
        }
    }

    public function acquire(): bool
    {
        if (is_resource($this->handle)) {
            return true;
        }
        $handle = @fopen($this->path, 'c');
        if ($handle === false) {
            throw new \RuntimeException('JWKS lock file could not be opened.');
        }
        $deadline = microtime(true) + ($this->waitMilliseconds / 1000);
        do {
            if (flock($handle, LOCK_EX | LOCK_NB)) {
                $this->handle = $handle;
                return true;
            }
            if ($this->waitMilliseconds > 0) {
                usleep(10_000);
            }
        } while (microtime(true) < $deadline);

        fclose($handle);
        return false;
    }

    public function release(): void
    {
        if (!is_resource($this->handle)) {
            return;
        }
        flock($this->handle, LOCK_UN);
        fclose($this->handle);
        $this->handle = null;
    }

    public function __destruct()
    {
        $this->release();
    }
}
