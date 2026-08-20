<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SafeApple\SignIn\Contract\JwksProvider;
use SafeApple\SignIn\Exception\InvalidIdentityToken;
use SafeApple\SignIn\Exception\UnknownKeyId;
use Throwable;

/** Verifies Apple's signature and registered time claims without applying token-type claims. */
final class AppleSignedTokenDecoder
{
    public const MAX_TOKEN_BYTES = 65_536;

    public function __construct(
        private readonly JwksProvider $jwks,
        private readonly int $leeway = 0,
    ) {
        if ($leeway < 0 || $leeway > 300) {
            throw new \InvalidArgumentException('Leeway must be between 0 and 300 seconds.');
        }
    }

    /** @return array<string, mixed> */
    public function decode(string $token): array
    {
        if ($token === '' || strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new InvalidIdentityToken('Apple signed token is empty or too large.');
        }

        [$kid, $algorithm] = $this->readHeader($token);
        if ($algorithm !== 'RS256') {
            throw new InvalidIdentityToken('Apple signed token must use RS256.');
        }

        $key = $this->findKey($kid, false) ?? $this->findKey($kid, true);
        if ($key === null) {
            throw new UnknownKeyId(sprintf('Apple signing key %s was not found.', $kid));
        }

        try {
            $previousLeeway = JWT::$leeway;
            JWT::$leeway = $this->leeway;
            try {
                $parsedKey = JWK::parseKey($key, 'RS256');
                if (!$parsedKey instanceof Key) {
                    throw new \UnexpectedValueException('Apple JWK could not be parsed.');
                }
                $claimsObject = JWT::decode($token, $parsedKey);
            } finally {
                JWT::$leeway = $previousLeeway;
            }

            /** @var array<string, mixed> $claims */
            $claims = json_decode(
                json_encode($claimsObject, JSON_THROW_ON_ERROR),
                true,
                512,
                JSON_THROW_ON_ERROR,
            );
            return $claims;
        } catch (Throwable $exception) {
            throw new InvalidIdentityToken('Apple token signature or registered time claims are invalid.', 0, $exception);
        }
    }

    /** @return array{string, string} */
    private function readHeader(string $jwt): array
    {
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            throw new InvalidIdentityToken('Apple signed token is malformed.');
        }

        $encoded = strtr($segments[0], '-_', '+/');
        $padding = strlen($encoded) % 4;
        if ($padding === 1) {
            throw new InvalidIdentityToken('Apple signed token header is malformed.');
        }
        if ($padding > 1) {
            $encoded .= str_repeat('=', 4 - $padding);
        }
        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            throw new InvalidIdentityToken('Apple signed token header is malformed.');
        }

        try {
            $header = json_decode($decoded, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidIdentityToken('Apple signed token header is malformed.', 0, $exception);
        }

        if (!is_array($header) || !is_string($header['kid'] ?? null) || $header['kid'] === '' || !is_string($header['alg'] ?? null)) {
            throw new InvalidIdentityToken('Apple signed token header has no valid kid or alg.');
        }

        return [$header['kid'], $header['alg']];
    }

    /** @return array<string, mixed>|null */
    private function findKey(string $kid, bool $forceRefresh): ?array
    {
        foreach ($this->jwks->get($forceRefresh)['keys'] as $key) {
            if (($key['kid'] ?? null) === $kid && ($key['kty'] ?? null) === 'RSA' && (($key['alg'] ?? 'RS256') === 'RS256')) {
                return $key;
            }
        }
        return null;
    }
}
