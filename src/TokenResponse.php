<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final class TokenResponse
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly string $identityToken,
        public readonly ?string $refreshToken,
    ) {
    }
}
