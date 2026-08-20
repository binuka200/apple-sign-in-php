<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Exception\StateMismatch;

final class LoginChallenge
{
    public function __construct(
        public readonly string $state,
        public readonly string $nonce,
    ) {
        if (strlen($state) < 32 || strlen($nonce) < 32) {
            throw new \InvalidArgumentException('State and nonce must each contain at least 32 characters.');
        }
    }

    public static function generate(): self
    {
        return new self(self::randomValue(), self::randomValue());
    }

    public function hashedNonce(): string
    {
        return hash('sha256', $this->nonce);
    }

    public function assertState(string $receivedState): void
    {
        if ($receivedState === '' || !hash_equals($this->state, $receivedState)) {
            throw new StateMismatch('Apple authorization state does not match.');
        }
    }

    private static function randomValue(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
