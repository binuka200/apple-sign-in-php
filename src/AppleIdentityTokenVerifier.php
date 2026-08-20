<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Contract\JwksProvider;
use SafeApple\SignIn\Exception\InvalidIdentityToken;

final class AppleIdentityTokenVerifier
{
    public const ISSUER = 'https://appleid.apple.com';

    /** @var non-empty-list<string> */
    private array $audiences;

    private readonly AppleSignedTokenDecoder $decoder;

    /** @param string|list<mixed> $audiences */
    public function __construct(
        private readonly JwksProvider $jwks,
        string|array $audiences,
        private readonly int $leeway = 0,
    ) {
        $audiences = is_string($audiences) ? [$audiences] : $audiences;
        $audiences = array_values(array_filter($audiences, static fn (mixed $value): bool => is_string($value) && $value !== ''));
        if ($audiences === []) {
            throw new \InvalidArgumentException('At least one non-empty Apple audience is required.');
        }
        if ($leeway < 0 || $leeway > 300) {
            throw new \InvalidArgumentException('Leeway must be between 0 and 300 seconds.');
        }
        $this->audiences = $audiences;
        $this->decoder = new AppleSignedTokenDecoder($jwks, $leeway);
    }

    public function verify(string $identityToken, ?string $expectedNonce = null): AppleIdentity
    {
        $claims = $this->decoder->decode($identityToken);
        return $this->verifyClaims($claims, $expectedNonce);
    }

    /** Verify an ID token returned with an authorization code by Apple's authorization endpoint. */
    public function verifyAuthorizationResponse(
        string $identityToken,
        string $authorizationCode,
        ?string $expectedNonce = null,
    ): AppleIdentity {
        if ($authorizationCode === '') {
            throw new \InvalidArgumentException('Authorization code cannot be empty.');
        }

        $claims = $this->decoder->decode($identityToken);
        $codeHash = $claims['c_hash'] ?? null;
        $expectedCodeHash = rtrim(strtr(base64_encode(substr(hash('sha256', $authorizationCode, true), 0, 16)), '+/', '-_'), '=');
        if (!is_string($codeHash) || !hash_equals($expectedCodeHash, $codeHash)) {
            throw new InvalidIdentityToken('Apple identity token is not bound to the authorization code.');
        }

        return $this->verifyClaims($claims, $expectedNonce);
    }

    /** @param array<string, mixed> $claims */
    private function verifyClaims(array $claims, ?string $expectedNonce): AppleIdentity
    {
        $issuer = $claims['iss'] ?? null;
        $subject = $claims['sub'] ?? null;
        $audience = $this->matchingAudience($claims['aud'] ?? null, $claims['azp'] ?? null);

        if (!is_string($issuer) || !hash_equals(self::ISSUER, $issuer)) {
            throw new InvalidIdentityToken('Apple identity token has an invalid issuer.');
        }
        if (!is_string($subject) || $subject === '') {
            throw new InvalidIdentityToken('Apple identity token has no subject.');
        }
        if (!is_int($claims['iat'] ?? null) || !is_int($claims['exp'] ?? null)) {
            throw new InvalidIdentityToken('Apple identity token has invalid time claims.');
        }
        if ($audience === null) {
            throw new InvalidIdentityToken('Apple identity token is not intended for this application.');
        }
        if ($expectedNonce !== null) {
            $nonce = $claims['nonce'] ?? null;
            if (!is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
                throw new InvalidIdentityToken('Apple identity token nonce does not match.');
            }
        }

        return new AppleIdentity(
            subject: $subject,
            audience: $audience,
            email: is_string($claims['email'] ?? null) ? $claims['email'] : null,
            emailVerified: $this->optionalBoolean($claims['email_verified'] ?? null),
            isPrivateEmail: $this->optionalBoolean($claims['is_private_email'] ?? null),
            claims: $claims,
        );
    }

    private function matchingAudience(mixed $claim, mixed $authorizedParty): ?string
    {
        $values = is_string($claim) ? [$claim] : $claim;
        if (!is_array($values) || $values === [] || !array_is_list($values)) {
            return null;
        }

        foreach ($values as $value) {
            if (!is_string($value) || $value === '' || !in_array($value, $this->audiences, true)) {
                return null;
            }
        }

        if (count($values) > 1 && !is_string($authorizedParty)) {
            return null;
        }
        if ($authorizedParty !== null
            && (!is_string($authorizedParty) || $authorizedParty === ''
                || !in_array($authorizedParty, $values, true)
                || !in_array($authorizedParty, $this->audiences, true))
        ) {
            return null;
        }

        return is_string($authorizedParty) ? $authorizedParty : $values[0];
    }

    private function optionalBoolean(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 'true' || $value === '1') {
            return true;
        }
        if ($value === 'false' || $value === '0') {
            return false;
        }
        return null;
    }
}
