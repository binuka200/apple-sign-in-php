<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Contract;

interface Observer
{
    /** @param array<string, bool|int|float|string|null> $context */
    public function record(string $event, array $context = []): void;
}
