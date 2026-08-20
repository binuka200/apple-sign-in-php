<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests\Support;

use SafeApple\SignIn\Contract\JwksProvider;

final class SequenceJwksProvider implements JwksProvider
{
    /** @var list<bool> */
    public array $calls = [];

    /** @param array{keys: list<array<string, mixed>>} $initial
     *  @param array{keys: list<array<string, mixed>>}|null $refreshed
     */
    public function __construct(
        private readonly array $initial,
        private readonly ?array $refreshed = null,
    ) {
    }

    public function get(bool $forceRefresh = false): array
    {
        $this->calls[] = $forceRefresh;
        return $forceRefresh && $this->refreshed !== null ? $this->refreshed : $this->initial;
    }
}
