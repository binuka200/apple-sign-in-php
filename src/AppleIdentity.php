<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final class AppleIdentity
{
    /** @param array<string, mixed> $claims */
    public function __construct(
        public readonly string $subject,
        public readonly string $audience,
        public readonly ?string $email,
        public readonly ?bool $emailVerified,
        public readonly ?bool $isPrivateEmail,
        public readonly array $claims,
    ) {
    }
}
