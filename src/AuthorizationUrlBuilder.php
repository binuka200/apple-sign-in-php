<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Exception\InvalidConfiguration;

final class AuthorizationUrlBuilder
{
    public const ENDPOINT = 'https://appleid.apple.com/auth/authorize';

    public function __construct(
        private readonly string $clientId,
        private readonly string $redirectUri,
    ) {
        if ($clientId === '') {
            throw new InvalidConfiguration('Apple client ID cannot be empty.');
        }
        $parts = parse_url($redirectUri);
        $host = is_array($parts) ? ($parts['host'] ?? null) : null;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || !is_string($host)
            || $host === '' || strcasecmp($host, 'localhost') === 0 || filter_var($host, FILTER_VALIDATE_IP)
            || isset($parts['fragment'])
        ) {
            throw new InvalidConfiguration('Apple redirect URI must be HTTPS, use a domain name, and contain no fragment.');
        }
    }

    /** @param list<string> $scopes */
    public function build(LoginChallenge $challenge, array $scopes = ['name', 'email']): string
    {
        $scopes = array_values(array_unique($scopes));
        foreach ($scopes as $scope) {
            if (!in_array($scope, ['name', 'email'], true)) {
                throw new \InvalidArgumentException('Apple scopes may only contain name and email.');
            }
        }

        $query = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code id_token',
            'response_mode' => 'form_post',
            'state' => $challenge->state,
            'nonce' => $challenge->nonce,
        ];
        if ($scopes !== []) {
            $query['scope'] = implode(' ', $scopes);
        }

        return self::ENDPOINT.'?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }
}
