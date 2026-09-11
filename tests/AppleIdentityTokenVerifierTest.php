<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleIdentityTokenVerifier;
use SafeApple\SignIn\AppleSignedTokenDecoder;
use SafeApple\SignIn\Exception\InvalidIdentityToken;
use SafeApple\SignIn\Exception\UnknownKeyId;
use SafeApple\SignIn\Tests\Support\SequenceJwksProvider;

final class AppleIdentityTokenVerifierTest extends TestCase
{
    private string $privateKey;

    /** @var array<string, mixed> */
    private array $jwk;

    protected function setUp(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($resource, $privateKey));
        $this->privateKey = $privateKey;
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $this->jwk = [
            'kty' => 'RSA',
            'kid' => 'current-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ];
    }

    public function testItVerifiesAValidIdentityToken(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, ['com.example.app', 'com.example.web']);

        $identity = $verifier->verify($this->token(), 'expected-nonce');

        self::assertSame('apple-user-123', $identity->subject);
        self::assertSame('com.example.app', $identity->audience);
        self::assertSame('user@example.com', $identity->email);
        self::assertTrue($identity->emailVerified);
        self::assertFalse($identity->isPrivateEmail);
        self::assertSame([false], $provider->calls);
    }

    public function testItRejectsAnInvalidAudience(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.another.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not intended for this application');
        $verifier->verify($this->token());
    }

    public function testItRejectsAnAudienceArrayContainingAnUntrustedAudience(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, ['com.example.app', 'com.example.web']);

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not intended for this application');
        $verifier->verify($this->token([
            'aud' => ['com.example.app', 'com.attacker.app'],
            'azp' => 'com.example.app',
        ]));
    }

    public function testMultipleTrustedAudiencesRequireAValidAuthorizedParty(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, ['com.example.app', 'com.example.web']);

        $identity = $verifier->verify($this->token([
            'aud' => ['com.example.app', 'com.example.web'],
            'azp' => 'com.example.web',
        ]));

        self::assertSame('com.example.web', $identity->audience);
    }

    public function testItRejectsMultipleAudiencesWithoutAnAuthorizedParty(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, ['com.example.app', 'com.example.web']);

        $this->expectException(InvalidIdentityToken::class);
        $verifier->verify($this->token(['aud' => ['com.example.app', 'com.example.web']]));
    }

    public function testItRejectsAnInvalidIssuer(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('invalid issuer');
        $verifier->verify($this->token(['iss' => 'https://attacker.example']));
    }

    public function testItRejectsANonceMismatch(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('nonce does not match');
        $verifier->verify($this->token(), 'wrong-nonce');
    }

    public function testItRequiresIssuedAtAndExpiryClaims(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('invalid time claims');
        $verifier->verify($this->token(['exp' => null]));
    }

    public function testItRefreshesOnceForAKeyRotation(): void
    {
        $provider = new SequenceJwksProvider(['keys' => []], ['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $identity = $verifier->verify($this->token());

        self::assertSame('apple-user-123', $identity->subject);
        self::assertSame([false, true], $provider->calls);
    }

    public function testAnUnknownKidNeverFallsBackToTheFirstKey(): void
    {
        $otherKey = $this->jwk;
        $otherKey['kid'] = 'some-other-key';
        $provider = new SequenceJwksProvider(['keys' => [$otherKey]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        try {
            $verifier->verify($this->token());
            self::fail('Expected an unknown-key failure.');
        } catch (UnknownKeyId $exception) {
            self::assertStringContainsString('current-key', $exception->getMessage());
            self::assertSame([false, true], $provider->calls);
        }
    }

    public function testItRejectsAnAlgorithmOtherThanRs256BeforeFetchingKeys(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');
        $token = $this->encodedHeader(['alg' => 'none', 'kid' => 'current-key']).'.'.self::base64Url('{}').'.';

        try {
            $verifier->verify($token);
            self::fail('Expected an invalid-token failure.');
        } catch (InvalidIdentityToken $exception) {
            self::assertStringContainsString('RS256', $exception->getMessage());
            self::assertSame([], $provider->calls);
        }
    }

    public function testItVerifiesTheAuthorizationCodeHash(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');
        $code = 'single-use-authorization-code';

        $identity = $verifier->verifyAuthorizationResponse(
            $this->token(['c_hash' => self::codeHash($code)]),
            $code,
            'expected-nonce',
        );

        self::assertSame('apple-user-123', $identity->subject);
    }

    public function testItRejectsAnAuthorizationCodeHashMismatch(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not bound to the authorization code');
        $verifier->verifyAuthorizationResponse(
            $this->token(['c_hash' => self::codeHash('different-code')]),
            'actual-code',
        );
    }

    public function testItRequiresAnAuthorizationCodeHashForTheHybridFlow(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not bound to the authorization code');
        $verifier->verifyAuthorizationResponse($this->token(), 'actual-code');
    }

    public function testItRejectsAnOversizedTokenBeforeFetchingKeys(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        try {
            $verifier->verify(str_repeat('a', 65_537));
            self::fail('Expected an oversized-token failure.');
        } catch (InvalidIdentityToken $exception) {
            self::assertStringContainsString('too large', $exception->getMessage());
            self::assertSame([], $provider->calls);
        }
    }

    public function testItRejectsATokenSignedByAKeyApplePublishesNoKeyFor(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $foreignKey = '';
        self::assertTrue(openssl_pkey_export($resource, $foreignKey));
        $forged = JWT::encode([
            'iss' => AppleIdentityTokenVerifier::ISSUER,
            'aud' => 'com.example.app',
            'sub' => 'apple-user-123',
            'iat' => time(),
            'exp' => time() + 300,
        ], $foreignKey, 'RS256', 'current-key');
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('signature or registered time claims are invalid');
        $verifier->verify($forged);
    }

    public function testItRejectsAnExpiredToken(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('signature or registered time claims are invalid');
        $verifier->verify($this->token(['iat' => time() - 600, 'exp' => time() - 300]));
    }

    public function testItRejectsAMalformedTokenBeforeFetchingKeys(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        try {
            $verifier->verify('header.payload');
            self::fail('Expected a malformed-token failure.');
        } catch (InvalidIdentityToken $exception) {
            self::assertStringContainsString('malformed', $exception->getMessage());
            self::assertSame([], $provider->calls);
        }
    }

    public function testItRejectsAHeaderWithoutAKeyId(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');
        $token = $this->encodedHeader(['alg' => 'RS256']).'.'.self::base64Url('{}').'.';

        try {
            $verifier->verify($token);
            self::fail('Expected a missing-kid failure.');
        } catch (InvalidIdentityToken $exception) {
            self::assertStringContainsString('kid or alg', $exception->getMessage());
            self::assertSame([], $provider->calls);
        }
    }

    public function testItRejectsATokenWithoutASubject(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('no subject');
        $verifier->verify($this->token(['sub' => '']));
    }

    public function testItRejectsAnAudienceClaimThatIsNotAStringOrList(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not intended for this application');
        $verifier->verify($this->token(['aud' => ['primary' => 'com.example.app']]));
    }

    public function testItRejectsAnAuthorizedPartyOutsideTheAudienceClaim(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, ['com.example.app', 'com.example.web']);

        $this->expectException(InvalidIdentityToken::class);
        $this->expectExceptionMessage('not intended for this application');
        $verifier->verify($this->token(['aud' => ['com.example.app'], 'azp' => 'com.example.web']));
    }

    public function testItRejectsAnEmptyAuthorizationCode(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $this->expectException(\InvalidArgumentException::class);
        $verifier->verifyAuthorizationResponse($this->token(), '');
    }

    public function testItRequiresAtLeastOneNonEmptyAudience(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty Apple audience');
        new AppleIdentityTokenVerifier(new SequenceJwksProvider(['keys' => [$this->jwk]]), ['', 42]);
    }

    public function testItRejectsLeewayApplesClockSkewNeverNeeds(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('between 0 and 300 seconds');
        new AppleIdentityTokenVerifier(new SequenceJwksProvider(['keys' => [$this->jwk]]), 'com.example.app', 301);
    }

    public function testTheDecoderRejectsLeewayOutsideTheAllowedRangeOnItsOwn(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new AppleSignedTokenDecoder(new SequenceJwksProvider(['keys' => [$this->jwk]]), -1);
    }

    public function testItReadsBooleanAndUnrecognizedEmailClaims(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');

        $identity = $verifier->verify(
            $this->token(['email_verified' => true, 'is_private_email' => 'maybe']),
            'expected-nonce',
        );

        self::assertTrue($identity->emailVerified);
        self::assertNull($identity->isPrivateEmail);
    }

    public function testItRejectsHeadersThatCannotBeDecoded(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleIdentityTokenVerifier($provider, 'com.example.app');
        $payload = self::base64Url('{}');

        foreach (['aaaaa', '!!!!', self::base64Url('{not json')] as $header) {
            try {
                $verifier->verify($header.'.'.$payload.'.');
                self::fail('Expected a malformed-header failure.');
            } catch (InvalidIdentityToken $exception) {
                self::assertStringContainsString('malformed', $exception->getMessage());
            }
        }

        self::assertSame([], $provider->calls);
    }

    /** @param array<string, mixed> $overrides */
    private function token(array $overrides = []): string
    {
        $claims = array_replace([
            'iss' => AppleIdentityTokenVerifier::ISSUER,
            'aud' => 'com.example.app',
            'sub' => 'apple-user-123',
            'iat' => time(),
            'exp' => time() + 300,
            'nonce' => 'expected-nonce',
            'email' => 'user@example.com',
            'email_verified' => 'true',
            'is_private_email' => 'false',
        ], $overrides);

        return JWT::encode($claims, $this->privateKey, 'RS256', 'current-key');
    }

    /** @param array<string, mixed> $header */
    private function encodedHeader(array $header): string
    {
        return self::base64Url(json_encode($header, JSON_THROW_ON_ERROR));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function codeHash(string $code): string
    {
        return self::base64Url(substr(hash('sha256', $code, true), 0, 16));
    }
}
