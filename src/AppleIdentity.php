<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final readonly class AppleIdentity
{
    /** @param array<string, mixed> $claims */
    public function __construct(
        public string $subject,
        public string $audience,
        public ?string $email,
        public ?bool $emailVerified,
        public ?bool $isPrivateEmail,
        public array $claims,
    ) {
    }
}
