<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Support;

use DateTimeImmutable;
use SafeApple\SignIn\Contract\Clock;

final class SystemClock implements Clock
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now');
    }
}
