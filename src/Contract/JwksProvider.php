<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Contract;

interface JwksProvider
{
    /** @return array{keys: list<array<string, mixed>>} */
    public function get(bool $forceRefresh = false): array;
}
