<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleAccountEvent;
use SafeApple\SignIn\AppleIdentityTokenVerifier;
use SafeApple\SignIn\AppleNotificationVerifier;
use SafeApple\SignIn\Exception\InvalidNotification;
use SafeApple\SignIn\Tests\Support\SequenceJwksProvider;

final class AppleNotificationVerifierTest extends TestCase
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
            'kid' => 'notification-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ];
    }

    public function testItVerifiesAndParsesAServerNotification(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $event = $verifier->verify($this->notification());

        self::assertSame(AppleAccountEvent::EMAIL_DISABLED, $event->type);
        self::assertSame('apple-user-123', $event->subject);
        self::assertSame('com.example.web', $event->audience);
        self::assertSame('relay@privaterelay.appleid.com', $event->email);
        self::assertTrue($event->isPrivateEmail);
    }

    public function testVerificationIsSideEffectFreeSoApplicationsCanRetryFailedHandling(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');
        $payload = $this->notification();

        $first = $verifier->verify($payload);
        $retry = $verifier->verify($payload);

        self::assertSame($first->jwtId, $retry->jwtId);
    }

    public function testItRejectsAnAudienceArrayContainingAnUntrustedAudience(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, ['com.example.app', 'com.example.web']);

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('audience is invalid');
        $verifier->verify($this->notification([], [
            'aud' => ['com.example.web', 'com.attacker.app'],
            'azp' => 'com.example.web',
        ]));
    }

    public function testItRejectsAnUnexpectedEventType(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('event is malformed');
        $verifier->verify($this->notification(['type' => 'surprise-event']));
    }

    public function testItRejectsAnOldNotification(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web', maxAge: 3600);

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('freshness');
        $verifier->verify($this->notification([], ['iat' => time() - 7200]));
    }

    public function testItRejectsAnOversizedNotificationBeforeFetchingKeys(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        try {
            $verifier->verify(str_repeat('a', 65_537));
            self::fail('Expected an oversized-notification failure.');
        } catch (InvalidNotification $exception) {
            self::assertStringContainsString('signature is invalid', $exception->getMessage());
            self::assertSame([], $provider->calls);
        }
    }

    public function testItRejectsANotificationWithoutAnEventPayload(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('no event payload');
        $verifier->verify($this->notification([], ['events' => null]));
    }

    public function testItRejectsMalformedEventJson(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('event JSON is malformed');
        $verifier->verify($this->notification([], ['events' => '{"type":']));
    }

    public function testItRejectsAnEventPayloadThatIsNotAnObject(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('event must be an object');
        $verifier->verify($this->notification([], ['events' => '"email-disabled"']));
    }

    public function testItAcceptsAnEventDeliveredAsAnObjectRatherThanAString(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $event = $verifier->verify($this->notification([], ['events' => [
            'type' => AppleAccountEvent::ACCOUNT_DELETED,
            'sub' => 'apple-user-123',
            'event_time' => time(),
            'is_private_email' => true,
        ]]));

        self::assertSame(AppleAccountEvent::ACCOUNT_DELETED, $event->type);
        self::assertTrue($event->isPrivateEmail);
        self::assertNull($event->email);
    }

    public function testItRejectsAnAuthorizedPartyOutsideTheAudienceClaim(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, ['com.example.web', 'com.example.app']);

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('audience is invalid');
        $verifier->verify($this->notification([], [
            'aud' => ['com.example.web'],
            'azp' => 'com.example.app',
        ]));
    }

    public function testItRejectsANotificationWithoutAJwtId(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('freshness claims');
        $verifier->verify($this->notification([], ['jti' => '']));
    }

    public function testItRequiresAtLeastOneNotificationAudience(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('notification audience');
        new AppleNotificationVerifier(new SequenceJwksProvider(['keys' => [$this->jwk]]), []);
    }

    public function testItRejectsAMaximumAgeShorterThanAppleRetries(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 60 seconds');
        new AppleNotificationVerifier(new SequenceJwksProvider(['keys' => [$this->jwk]]), 'com.example.web', 30, 59);
    }

    public function testItRejectsANotificationFromAnotherIssuer(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('issuer is invalid');
        $verifier->verify($this->notification([], ['iss' => 'https://accounts.google.com']));
    }

    public function testItRejectsAnAudienceClaimThatIsNotAStringOrList(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('audience is invalid');
        $verifier->verify($this->notification([], ['aud' => ['primary' => 'com.example.web']]));
    }

    public function testItRejectsMultipleAudiencesWithoutAnAuthorizedParty(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, ['com.example.web', 'com.example.app']);

        $this->expectException(InvalidNotification::class);
        $this->expectExceptionMessage('audience is invalid');
        $verifier->verify($this->notification([], ['aud' => ['com.example.web', 'com.example.app']]));
    }

    public function testItReadsAStringPrivateEmailFlag(): void
    {
        $provider = new SequenceJwksProvider(['keys' => [$this->jwk]]);
        $verifier = new AppleNotificationVerifier($provider, 'com.example.web');

        $event = $verifier->verify($this->notification(['is_private_email' => 'false']));

        self::assertFalse($event->isPrivateEmail);
    }

    /** @param array<string, mixed> $eventOverrides
     *  @param array<string, mixed> $claimOverrides
     */
    private function notification(array $eventOverrides = [], array $claimOverrides = []): string
    {
        $event = array_replace([
            'type' => 'email-disabled',
            'sub' => 'apple-user-123',
            'event_time' => time(),
            'email' => 'relay@privaterelay.appleid.com',
            'is_private_email' => 'true',
        ], $eventOverrides);
        $claims = array_replace([
            'iss' => AppleIdentityTokenVerifier::ISSUER,
            'aud' => 'com.example.web',
            'iat' => time(),
            'jti' => 'notification-123',
            'events' => json_encode($event, JSON_THROW_ON_ERROR),
        ], $claimOverrides);

        return JWT::encode($claims, $this->privateKey, 'RS256', 'notification-key');
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
