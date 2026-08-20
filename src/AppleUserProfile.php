<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Exception\InvalidAuthorizationResponse;

final class AppleUserProfile
{
    public function __construct(
        public readonly ?string $firstName,
        public readonly ?string $lastName,
        public readonly ?string $email,
    ) {
    }

    public static function fromJson(string $json): self
    {
        if ($json === '' || strlen($json) > 16_384) {
            throw new InvalidAuthorizationResponse('Apple user profile is empty or too large.');
        }
        try {
            $data = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidAuthorizationResponse('Apple user profile is malformed.', 0, $exception);
        }
        if (!is_array($data)) {
            throw new InvalidAuthorizationResponse('Apple user profile must be an object.');
        }
        $name = is_array($data['name'] ?? null) ? $data['name'] : [];

        return new self(
            firstName: self::optionalString($name['firstName'] ?? null),
            lastName: self::optionalString($name['lastName'] ?? null),
            email: self::optionalString($data['email'] ?? null),
        );
    }

    private static function optionalString(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value) || strlen($value) > 1024) {
            throw new InvalidAuthorizationResponse('Apple user profile contains an invalid value.');
        }
        return $value;
    }
}
