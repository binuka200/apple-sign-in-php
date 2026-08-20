<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Contract;

interface RefreshLock
{
    /** Waits only for the implementation's configured bounded duration. */
    public function acquire(): bool;

    public function release(): void;
}
