<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use Firebase\JWT\JWT;
use SafeApple\SignIn\Contract\ClientSecretProvider;
use SafeApple\SignIn\Contract\Clock;
use SafeApple\SignIn\Exception\InvalidConfiguration;
use SafeApple\SignIn\Support\SystemClock;
use Throwable;

final class ClientSecretGenerator implements ClientSecretProvider
{
    public const MAX_LIFETIME = 15_777_000;
    public const AUDIENCE = 'https://appleid.apple.com';

    private readonly Clock $clock;

    public function __construct(
        private readonly string $teamId,
        private readonly string $clientId,
        private readonly string $keyId,
        private readonly string $privateKey,
        private readonly int $lifetime = 300,
        ?Clock $clock = null,
    ) {
        foreach (['team ID' => $teamId, 'client ID' => $clientId, 'key ID' => $keyId, 'private key' => $privateKey] as $name => $value) {
            if (trim($value) === '') {
                throw new InvalidConfiguration(sprintf('Apple %s cannot be empty.', $name));
            }
        }
        if ($lifetime < 1 || $lifetime > self::MAX_LIFETIME) {
            throw new InvalidConfiguration(sprintf('Client-secret lifetime must be between 1 and %d seconds.', self::MAX_LIFETIME));
        }
        $this->clock = $clock ?? new SystemClock();
    }

    public static function fromKeyFile(
        string $teamId,
        string $clientId,
        string $keyId,
        string $privateKeyPath,
        int $lifetime = 300,
        ?Clock $clock = null,
    ): self {
        $privateKey = @file_get_contents($privateKeyPath);
        if ($privateKey === false) {
            throw new InvalidConfiguration('Apple private-key file could not be read.');
        }

        return new self($teamId, $clientId, $keyId, $privateKey, $lifetime, $clock);
    }

    public function generate(): string
    {
        $issuedAt = $this->clock->now()->getTimestamp();
        try {
            return JWT::encode([
                'iss' => $this->teamId,
                'iat' => $issuedAt,
                'exp' => $issuedAt + $this->lifetime,
                'aud' => self::AUDIENCE,
                'sub' => $this->clientId,
            ], $this->privateKey, 'ES256', $this->keyId);
        } catch (Throwable $exception) {
            throw new InvalidConfiguration('Apple private key is not a valid P-256 signing key.', 0, $exception);
        }
    }
}
