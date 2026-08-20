<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests\Support;

use DateTimeImmutable;
use SafeApple\SignIn\Contract\Clock;

final readonly class FixedClock implements Clock
{
    public function __construct(private DateTimeImmutable $time)
    {
    }

    public function now(): DateTimeImmutable
    {
        return $this->time;
    }
}
