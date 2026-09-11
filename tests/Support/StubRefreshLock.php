<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests\Support;

use SafeApple\SignIn\Contract\RefreshLock;

final class StubRefreshLock implements RefreshLock
{
    public int $acquired = 0;

    public int $released = 0;

    /** @param \Closure(): void|null $whileHeld */
    public function __construct(
        private readonly bool $grant = true,
        private readonly ?\Closure $whileHeld = null,
    ) {
    }

    public function acquire(): bool
    {
        $this->acquired++;
        if ($this->grant && $this->whileHeld !== null) {
            ($this->whileHeld)();
        }

        return $this->grant;
    }

    public function release(): void
    {
        $this->released++;
    }
}
