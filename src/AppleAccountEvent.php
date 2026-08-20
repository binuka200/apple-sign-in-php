<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

final readonly class AppleAccountEvent
{
    public const EMAIL_DISABLED = 'email-disabled';
    public const EMAIL_ENABLED = 'email-enabled';
    public const CONSENT_REVOKED = 'consent-revoked';
    public const ACCOUNT_DELETED = 'account-deleted';

    /** @param array<string, mixed> $claims */
    public function __construct(
        public string $type,
        public string $subject,
        public string $audience,
        public int $eventTime,
        public string $jwtId,
        public ?string $email,
        public ?bool $isPrivateEmail,
        public array $claims,
    ) {
    }
}
