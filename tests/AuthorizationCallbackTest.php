<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleAuthorizationResponse;
use SafeApple\SignIn\AuthorizationUrlBuilder;
use SafeApple\SignIn\Exception\InvalidAuthorizationResponse;
use SafeApple\SignIn\Exception\InvalidConfiguration;
use SafeApple\SignIn\LoginChallenge;

final class AuthorizationCallbackTest extends TestCase
{
    public function testItSurfacesAnErrorReturnedByApple(): void
    {
        $challenge = LoginChallenge::generate();

        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('user_cancelled_authorize');
        AppleAuthorizationResponse::fromPost([
            'state' => $challenge->state,
            'error' => 'user_cancelled_authorize',
        ], $challenge);
    }

    public function testItRejectsACallbackWithoutACodeOrIdentityToken(): void
    {
        $challenge = LoginChallenge::generate();

        foreach ([
            ['state' => $challenge->state],
            ['state' => $challenge->state, 'code' => 'code'],
            ['state' => $challenge->state, 'code' => '', 'id_token' => 'token'],
            ['state' => $challenge->state, 'code' => 'code', 'id_token' => 123],
        ] as $post) {
            try {
                AppleAuthorizationResponse::fromPost($post, $challenge);
                self::fail('Expected an incomplete callback to be rejected.');
            } catch (InvalidAuthorizationResponse $exception) {
                self::assertStringContainsString('no code or identity token', $exception->getMessage());
            }
        }
    }

    public function testItRejectsAUserProfileThatIsNotJsonText(): void
    {
        $challenge = LoginChallenge::generate();

        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('must be JSON text');
        AppleAuthorizationResponse::fromPost([
            'state' => $challenge->state,
            'code' => 'code',
            'id_token' => 'token',
            'user' => ['name' => ['firstName' => 'Ada']],
        ], $challenge);
    }

    public function testItRequiresAClientId(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage('client ID cannot be empty');
        new AuthorizationUrlBuilder('', 'https://example.com/callback');
    }

    public function testItRejectsARedirectUriAppleWouldNotAccept(): void
    {
        foreach ([
            'http://example.com/callback',
            'https://localhost/callback',
            'https://127.0.0.1/callback',
            'https://example.com/callback#fragment',
            'not-a-url',
        ] as $redirectUri) {
            try {
                new AuthorizationUrlBuilder('com.example.web', $redirectUri);
                self::fail(sprintf('Expected %s to be rejected.', $redirectUri));
            } catch (InvalidConfiguration $exception) {
                self::assertStringContainsString('redirect URI', $exception->getMessage());
            }
        }
    }

    public function testItRejectsScopesApplePublishesNoSupportFor(): void
    {
        $builder = new AuthorizationUrlBuilder('com.example.web', 'https://example.com/callback');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('name and email');
        $builder->build(LoginChallenge::generate(), ['name', 'openid']);
    }
}
