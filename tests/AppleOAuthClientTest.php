<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\AppleOAuthClient;
use SafeApple\SignIn\Exception\AppleApiException;
use SafeApple\SignIn\Tests\Support\RecordingObserver;
use SafeApple\SignIn\Tests\Support\StaticClientSecret;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class AppleOAuthClientTest extends TestCase
{
    public function testItExchangesAnAuthorizationCode(): void
    {
        $observer = new RecordingObserver();
        $client = new MockHttpClient(function (string $method, string $url, array $options): MockResponse {
            self::assertSame('POST', $method);
            self::assertSame(AppleOAuthClient::TOKEN_ENDPOINT, $url);
            self::assertSame(3.0, $options['timeout']);
            self::assertSame(5.0, $options['max_duration']);
            self::assertStringContainsString('grant_type=authorization_code', $options['body']);
            self::assertStringContainsString('code=one-time-code', $options['body']);
            self::assertStringNotContainsString('code=client-secret', $options['body']);
            return new MockResponse(json_encode([
                'access_token' => 'access',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'refresh',
                'id_token' => 'identity',
            ], JSON_THROW_ON_ERROR));
        });
        $oauth = new AppleOAuthClient('com.example.web', new StaticClientSecret(), $client, $observer);

        $tokens = $oauth->exchangeAuthorizationCode('one-time-code', 'https://example.com/callback');

        self::assertSame('access', $tokens->accessToken);
        self::assertSame('refresh', $tokens->refreshToken);
        self::assertSame('identity', $tokens->identityToken);
        self::assertSame('oauth.token_succeeded', $observer->records[0]['event']);
    }

    public function testItRefreshesTokensWithoutRequiringANewRefreshTokenInTheResponse(): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode([
            'access_token' => 'new-access',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => 'new-identity',
        ], JSON_THROW_ON_ERROR)));
        $oauth = new AppleOAuthClient('com.example.web', new StaticClientSecret(), $client);

        $tokens = $oauth->refresh('stored-refresh');

        self::assertSame('new-access', $tokens->accessToken);
        self::assertNull($tokens->refreshToken);
    }

    public function testItSurfacesApplesTypedOauthError(): void
    {
        $client = new MockHttpClient(new MockResponse('{"error":"invalid_grant"}', ['http_code' => 400]));
        $oauth = new AppleOAuthClient('com.example.web', new StaticClientSecret(), $client);

        try {
            $oauth->exchangeAuthorizationCode('expired-code');
            self::fail('Expected Apple to reject the grant.');
        } catch (AppleApiException $exception) {
            self::assertSame('invalid_grant', $exception->appleError);
            self::assertSame(400, $exception->httpStatus);
        }
    }

    public function testItRevokesARefreshToken(): void
    {
        $client = new MockHttpClient(new MockResponse('', ['http_code' => 200]));
        $oauth = new AppleOAuthClient('com.example.web', new StaticClientSecret(), $client);

        $oauth->revoke('refresh-token');

        self::assertSame(1, $client->getRequestsCount());
    }
}
