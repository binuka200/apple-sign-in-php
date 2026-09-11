<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleIdentity;
use SafeApple\SignIn\AppleUserProfile;
use SafeApple\SignIn\Exception\InvalidAuthorizationResponse;

final class AppleUserProfileTest extends TestCase
{
    public function testItRejectsAnEmptyOrOversizedProfileDocument(): void
    {
        foreach (['', str_repeat('a', 16_385)] as $json) {
            try {
                AppleUserProfile::fromJson($json);
                self::fail('Expected an empty or oversized profile to be rejected.');
            } catch (InvalidAuthorizationResponse $exception) {
                self::assertStringContainsString('empty or too large', $exception->getMessage());
            }
        }
    }

    public function testItRejectsMalformedProfileJson(): void
    {
        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('malformed');
        AppleUserProfile::fromJson('{"name":');
    }

    public function testItRejectsAProfileThatIsNotAnObject(): void
    {
        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('must be an object');
        AppleUserProfile::fromJson('"just-a-string"');
    }

    public function testItRejectsProfileValuesThatAreNotShortStrings(): void
    {
        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('invalid value');
        AppleUserProfile::fromJson(json_encode([
            'name' => ['firstName' => str_repeat('a', 1025)],
        ], JSON_THROW_ON_ERROR));
    }

    public function testItIgnoresANameThatIsNotAnObject(): void
    {
        $profile = AppleUserProfile::fromJson('{"name":"Ada Lovelace","email":"ada@example.com"}');

        self::assertNull($profile->firstName);
        self::assertNull($profile->lastName);
        self::assertSame('ada@example.com', $profile->email);
    }

    public function testAProfileWithoutAnEmailHasNoVerifiedEmail(): void
    {
        $profile = AppleUserProfile::fromJson('{"name":{"firstName":"Ada"}}');

        self::assertNull($profile->verifiedEmail($this->identity('ada@example.com')));
    }

    public function testItRejectsAProfileEmailWhenTheIdentityCarriesNone(): void
    {
        $profile = AppleUserProfile::fromJson('{"email":"attacker@example.com"}');

        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('does not match the verified identity token');
        $profile->verifiedEmail($this->identity(null));
    }

    public function testItReturnsTheEmailOnlyWhenItMatchesTheVerifiedIdentity(): void
    {
        $profile = AppleUserProfile::fromJson('{"email":"ada@example.com"}');

        self::assertSame('ada@example.com', $profile->verifiedEmail($this->identity('ada@example.com')));
    }

    private function identity(?string $email): AppleIdentity
    {
        return new AppleIdentity(
            subject: 'apple-user-123',
            audience: 'com.example.web',
            email: $email,
            emailVerified: true,
            isPrivateEmail: false,
            claims: [],
        );
    }
}
