<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Contract;

use DateTimeImmutable;

interface Clock
{
    public function now(): DateTimeImmutable;
}
