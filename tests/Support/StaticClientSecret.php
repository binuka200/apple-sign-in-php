<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests\Support;

use SafeApple\SignIn\Contract\ClientSecretProvider;

final class StaticClientSecret implements ClientSecretProvider
{
    public function __construct(private readonly string $value = 'client-secret')
    {
    }

    public function generate(): string
    {
        return $this->value;
    }
}
