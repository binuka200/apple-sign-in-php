<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Exception;

final class AppleApiException extends AppleSignInException
{
    public function __construct(
        public readonly string $appleError,
        public readonly int $httpStatus,
    ) {
        parent::__construct(sprintf('Apple API request failed with %s.', $appleError));
    }
}
