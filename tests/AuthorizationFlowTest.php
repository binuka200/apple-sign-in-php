<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleAuthorizationResponse;
use SafeApple\SignIn\AppleIdentity;
use SafeApple\SignIn\AuthorizationUrlBuilder;
use SafeApple\SignIn\Exception\InvalidAuthorizationResponse;
use SafeApple\SignIn\Exception\StateMismatch;
use SafeApple\SignIn\LoginChallenge;

final class AuthorizationFlowTest extends TestCase
{
    public function testItBuildsAStateAndNonceProtectedAuthorizationUrl(): void
    {
        $challenge = new LoginChallenge(str_repeat('s', 32), str_repeat('n', 32));
        $builder = new AuthorizationUrlBuilder('com.example.web', 'https://example.com/auth/apple/callback');

        $url = $builder->build($challenge);

        self::assertStringStartsWith(AuthorizationUrlBuilder::ENDPOINT.'?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame('com.example.web', $query['client_id']);
        self::assertSame('code id_token', $query['response_type']);
        self::assertSame('form_post', $query['response_mode']);
        self::assertSame($challenge->state, $query['state']);
        self::assertSame($challenge->nonce, $query['nonce']);
        self::assertSame(hash('sha256', str_repeat('n', 32)), $challenge->hashedNonce());
    }

    public function testItParsesAndPreservesTheFirstLoginProfile(): void
    {
        $challenge = new LoginChallenge(str_repeat('s', 32), str_repeat('n', 32));
        $response = AppleAuthorizationResponse::fromPost([
            'state' => $challenge->state,
            'code' => 'code',
            'id_token' => 'jwt',
            'user' => '{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}',
        ], $challenge);

        self::assertSame('code', $response->code);
        self::assertNotNull($response->user);
        self::assertSame('Ada', $response->user->firstName);
        self::assertSame('Lovelace', $response->user->lastName);
        self::assertSame('ada@example.com', $response->user->email);
        self::assertSame('ada@example.com', $response->user->verifiedEmail(new AppleIdentity(
            subject: 'apple-subject',
            audience: 'com.example.web',
            email: 'ada@example.com',
            emailVerified: true,
            isPrivateEmail: false,
            claims: [],
        )));
    }

    public function testItRejectsAProfileEmailThatDoesNotMatchTheVerifiedIdentity(): void
    {
        $challenge = new LoginChallenge(str_repeat('s', 32), str_repeat('n', 32));
        $response = AppleAuthorizationResponse::fromPost([
            'state' => $challenge->state,
            'code' => 'code',
            'id_token' => 'jwt',
            'user' => '{"email":"tampered@example.com"}',
        ], $challenge);
        self::assertNotNull($response->user);

        $this->expectException(InvalidAuthorizationResponse::class);
        $this->expectExceptionMessage('does not match the verified identity token');
        $response->user->verifiedEmail(new AppleIdentity(
            subject: 'apple-subject',
            audience: 'com.example.web',
            email: 'signed@example.com',
            emailVerified: true,
            isPrivateEmail: false,
            claims: [],
        ));
    }

    public function testItRejectsCallbackStateMismatchBeforeUsingCredentials(): void
    {
        $challenge = new LoginChallenge(str_repeat('s', 32), str_repeat('n', 32));
        $this->expectException(StateMismatch::class);
        AppleAuthorizationResponse::fromPost([
            'state' => str_repeat('x', 32),
            'code' => 'code',
            'id_token' => 'jwt',
        ], $challenge);
    }
}
