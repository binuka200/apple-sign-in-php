<?php

declare(strict_types=1);

namespace SafeApple\SignIn;

use SafeApple\SignIn\Contract\JwksProvider;
use SafeApple\SignIn\Exception\InvalidNotification;

final class AppleNotificationVerifier
{
    /** @var non-empty-list<string> */
    private array $audiences;
    private readonly AppleSignedTokenDecoder $decoder;

    /** @param string|list<mixed> $audiences */
    public function __construct(
        JwksProvider $jwks,
        string|array $audiences,
        private readonly int $leeway = 30,
        private readonly int $maxAge = 86400,
    ) {
        $audiences = is_string($audiences) ? [$audiences] : $audiences;
        $audiences = array_values(array_filter($audiences, static fn (mixed $value): bool => is_string($value) && $value !== ''));
        if ($audiences === []) {
            throw new \InvalidArgumentException('At least one notification audience is required.');
        }
        if ($maxAge < 60) {
            throw new \InvalidArgumentException('Notification maximum age must be at least 60 seconds.');
        }
        $this->audiences = $audiences;
        $this->decoder = new AppleSignedTokenDecoder($jwks, $leeway);
    }

    public function verify(string $signedPayload): AppleAccountEvent
    {
        try {
            $claims = $this->decoder->decode($signedPayload);
        } catch (\Throwable $exception) {
            throw new InvalidNotification('Apple notification signature is invalid.', 0, $exception);
        }

        if (($claims['iss'] ?? null) !== AppleIdentityTokenVerifier::ISSUER) {
            throw new InvalidNotification('Apple notification issuer is invalid.');
        }
        $audience = $this->matchingAudience($claims['aud'] ?? null, $claims['azp'] ?? null);
        if ($audience === null) {
            throw new InvalidNotification('Apple notification audience is invalid.');
        }
        $issuedAt = $claims['iat'] ?? null;
        $jwtId = $claims['jti'] ?? null;
        if (!is_int($issuedAt) || $issuedAt < time() - $this->maxAge || $issuedAt > time() + $this->leeway
            || !is_string($jwtId) || $jwtId === ''
        ) {
            throw new InvalidNotification('Apple notification has invalid freshness claims.');
        }

        $event = $this->parseEvent($claims['events'] ?? null);
        $type = $event['type'] ?? null;
        $subject = $event['sub'] ?? null;
        $eventTime = $event['event_time'] ?? null;
        if (!is_string($type) || !in_array($type, [
            AppleAccountEvent::EMAIL_DISABLED,
            AppleAccountEvent::EMAIL_ENABLED,
            AppleAccountEvent::CONSENT_REVOKED,
            AppleAccountEvent::ACCOUNT_DELETED,
        ], true) || !is_string($subject) || $subject === '' || !is_int($eventTime)) {
            throw new InvalidNotification('Apple notification event is malformed.');
        }

        return new AppleAccountEvent(
            type: $type,
            subject: $subject,
            audience: $audience,
            eventTime: $eventTime,
            jwtId: $jwtId,
            email: is_string($event['email'] ?? null) ? $event['email'] : null,
            isPrivateEmail: $this->optionalBoolean($event['is_private_email'] ?? null),
            claims: $claims,
        );
    }

    /** @return array<string, mixed> */
    private function parseEvent(mixed $events): array
    {
        if (is_array($events)) {
            return $events;
        }
        if (!is_string($events) || $events === '' || strlen($events) > 16_384) {
            throw new InvalidNotification('Apple notification has no event payload.');
        }
        try {
            $decoded = json_decode($events, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidNotification('Apple notification event JSON is malformed.', 0, $exception);
        }
        if (!is_array($decoded)) {
            throw new InvalidNotification('Apple notification event must be an object.');
        }
        return $decoded;
    }

    private function matchingAudience(mixed $claim, mixed $authorizedParty): ?string
    {
        $values = is_string($claim) ? [$claim] : $claim;
        if (!is_array($values) || $values === [] || !array_is_list($values)) {
            return null;
        }

        foreach ($values as $value) {
            if (!is_string($value) || $value === '' || !in_array($value, $this->audiences, true)) {
                return null;
            }
        }

        if (count($values) > 1 && !is_string($authorizedParty)) {
            return null;
        }
        if ($authorizedParty !== null
            && (!is_string($authorizedParty) || $authorizedParty === ''
                || !in_array($authorizedParty, $values, true)
                || !in_array($authorizedParty, $this->audiences, true))
        ) {
            return null;
        }

        return is_string($authorizedParty) ? $authorizedParty : $values[0];
    }

    private function optionalBoolean(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }
        return match ($value) {
            'true', '1' => true,
            'false', '0' => false,
            default => null,
        };
    }
}
