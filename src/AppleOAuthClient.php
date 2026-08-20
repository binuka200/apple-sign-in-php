<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Contract\ClientSecretProvider;
use SafeApple\SignIn\Contract\Observer;
use SafeApple\SignIn\Exception\AppleApiException;
use SafeApple\SignIn\Exception\AppleApiUnavailable;
use SafeApple\SignIn\Exception\InvalidConfiguration;
use SafeApple\SignIn\Support\NullObserver;
use SafeApple\SignIn\Support\SafeObserver;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class AppleOAuthClient
{
    public const TOKEN_ENDPOINT = 'https://appleid.apple.com/auth/token';
    public const REVOCATION_ENDPOINT = 'https://appleid.apple.com/auth/revoke';

    private readonly HttpClientInterface $httpClient;
    private readonly Observer $observer;

    public function __construct(
        private readonly string $clientId,
        private readonly ClientSecretProvider $clientSecret,
        ?HttpClientInterface $httpClient = null,
        ?Observer $observer = null,
    ) {
        if ($clientId === '') {
            throw new InvalidConfiguration('Apple client ID cannot be empty.');
        }
        // Token and revoke calls are deliberately not automatically retried: an
        // authorization code is single-use and a lost successful response cannot
        // safely be replayed as though it were idempotent.
        $this->httpClient = $httpClient ?? HttpClient::create(['timeout' => 3.0, 'max_duration' => 5.0]);
        $this->observer = new SafeObserver($observer ?? new NullObserver());
    }

    public function exchangeAuthorizationCode(string $code, ?string $redirectUri = null): TokenResponse
    {
        if ($code === '') {
            throw new \InvalidArgumentException('Authorization code cannot be empty.');
        }
        $body = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret->generate(),
            'code' => $code,
            'grant_type' => 'authorization_code',
        ];
        if ($redirectUri !== null) {
            $body['redirect_uri'] = $redirectUri;
        }
        return $this->tokenRequest($body, 'authorization_code');
    }

    public function refresh(string $refreshToken): TokenResponse
    {
        if ($refreshToken === '') {
            throw new \InvalidArgumentException('Refresh token cannot be empty.');
        }
        return $this->tokenRequest([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret->generate(),
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
        ], 'refresh_token');
    }

    public function revoke(string $token, string $tokenTypeHint = 'refresh_token'): void
    {
        if ($token === '') {
            throw new \InvalidArgumentException('Token cannot be empty.');
        }
        if (!in_array($tokenTypeHint, ['refresh_token', 'access_token'], true)) {
            throw new \InvalidArgumentException('Token type hint must be refresh_token or access_token.');
        }

        try {
            $response = $this->httpClient->request('POST', self::REVOCATION_ENDPOINT, [
                'headers' => ['Accept' => 'application/json'],
                'body' => [
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret->generate(),
                    'token' => $token,
                    'token_type_hint' => $tokenTypeHint,
                ],
                'timeout' => 3.0,
                'max_duration' => 5.0,
            ]);
            $status = $response->getStatusCode();
            if ($status !== 200) {
                $this->throwApiError($response->toArray(false), $status, 'revocation_failed');
            }
            $this->observer->record('oauth.revoke_succeeded', ['token_type' => $tokenTypeHint]);
        } catch (AppleApiException $exception) {
            $this->observer->record('oauth.revoke_rejected', ['error' => $exception->appleError]);
            throw $exception;
        } catch (HttpException $exception) {
            $this->observer->record('oauth.network_failed', ['operation' => 'revoke']);
            throw new AppleApiUnavailable('Apple token revocation did not complete within the network bound.', 0, $exception);
        }
    }

    /** @param array<string, string> $body */
    private function tokenRequest(array $body, string $grantType): TokenResponse
    {
        try {
            $response = $this->httpClient->request('POST', self::TOKEN_ENDPOINT, [
                'headers' => ['Accept' => 'application/json'],
                'body' => $body,
                'timeout' => 3.0,
                'max_duration' => 5.0,
            ]);
            $status = $response->getStatusCode();
            $data = $response->toArray(false);
            if ($status !== 200) {
                $this->throwApiError($data, $status, 'token_request_failed');
            }
            $result = $this->parseTokenResponse($data, $grantType === 'authorization_code');
            $this->observer->record('oauth.token_succeeded', ['grant_type' => $grantType]);
            return $result;
        } catch (AppleApiException $exception) {
            $this->observer->record('oauth.token_rejected', ['grant_type' => $grantType, 'error' => $exception->appleError]);
            throw $exception;
        } catch (HttpException $exception) {
            $this->observer->record('oauth.network_failed', ['operation' => 'token']);
            throw new AppleApiUnavailable('Apple token request did not complete within the network bound.', 0, $exception);
        }
    }

    /** @param array<string, mixed> $data */
    private function parseTokenResponse(array $data, bool $requireRefreshToken): TokenResponse
    {
        if (!is_string($data['access_token'] ?? null) || $data['access_token'] === ''
            || !is_string($data['token_type'] ?? null) || strcasecmp($data['token_type'], 'bearer') !== 0
            || !is_int($data['expires_in'] ?? null) || $data['expires_in'] < 1
            || !is_string($data['id_token'] ?? null) || $data['id_token'] === ''
            || ($requireRefreshToken && (!is_string($data['refresh_token'] ?? null) || $data['refresh_token'] === ''))
        ) {
            throw new AppleApiUnavailable('Apple returned a malformed token response.');
        }

        return new TokenResponse(
            accessToken: $data['access_token'],
            tokenType: $data['token_type'],
            expiresIn: $data['expires_in'],
            identityToken: $data['id_token'],
            refreshToken: is_string($data['refresh_token'] ?? null) ? $data['refresh_token'] : null,
        );
    }

    /** @param array<string, mixed> $data */
    private function throwApiError(array $data, int $status, string $fallback): never
    {
        $error = is_string($data['error'] ?? null) && $data['error'] !== '' ? $data['error'] : $fallback;
        throw new AppleApiException($error, $status);
    }
}
