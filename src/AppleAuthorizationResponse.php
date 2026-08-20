<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Exception\InvalidAuthorizationResponse;

final class AppleAuthorizationResponse
{
    public function __construct(
        public readonly string $code,
        public readonly string $identityToken,
        public readonly ?AppleUserProfile $user,
    ) {
    }

    /** @param array<string, mixed> $post */
    public static function fromPost(array $post, LoginChallenge $challenge): self
    {
        $state = is_string($post['state'] ?? null) ? $post['state'] : '';
        $challenge->assertState($state);

        if (is_string($post['error'] ?? null) && $post['error'] !== '') {
            throw new InvalidAuthorizationResponse(sprintf('Apple authorization failed with %s.', $post['error']));
        }

        $code = $post['code'] ?? null;
        $identityToken = $post['id_token'] ?? null;
        if (!is_string($code) || $code === '' || !is_string($identityToken) || $identityToken === '') {
            throw new InvalidAuthorizationResponse('Apple authorization response has no code or identity token.');
        }

        $user = null;
        if (isset($post['user'])) {
            if (!is_string($post['user'])) {
                throw new InvalidAuthorizationResponse('Apple user profile must be JSON text.');
            }
            $user = AppleUserProfile::fromJson($post['user']);
        }

        return new self($code, $identityToken, $user);
    }
}
