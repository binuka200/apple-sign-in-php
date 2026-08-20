<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Contract;

interface ClientSecretProvider
{
    public function generate(): string;
}
