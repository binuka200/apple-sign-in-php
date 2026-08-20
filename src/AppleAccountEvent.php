<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final class AppleAccountEvent
{
    public const EMAIL_DISABLED = 'email-disabled';
    public const EMAIL_ENABLED = 'email-enabled';
    public const CONSENT_REVOKED = 'consent-revoked';
    public const ACCOUNT_DELETED = 'account-deleted';

    /** @param array<string, mixed> $claims */
    public function __construct(
        public readonly string $type,
        public readonly string $subject,
        public readonly string $audience,
        public readonly int $eventTime,
        public readonly string $jwtId,
        public readonly ?string $email,
        public readonly ?bool $isPrivateEmail,
        public readonly array $claims,
    ) {
    }
}
