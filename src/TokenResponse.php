<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final readonly class TokenResponse
{
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public int $expiresIn,
        public string $identityToken,
        public ?string $refreshToken,
    ) {
    }
}
