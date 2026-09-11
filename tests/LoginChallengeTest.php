<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\Exception\StateMismatch;
use SafeApple\SignIn\LoginChallenge;

final class LoginChallengeTest extends TestCase
{
    public function testItGeneratesUnpredictableStateAndNonceValues(): void
    {
        $first = LoginChallenge::generate();
        $second = LoginChallenge::generate();

        self::assertGreaterThanOrEqual(32, strlen($first->state));
        self::assertGreaterThanOrEqual(32, strlen($first->nonce));
        self::assertNotSame($first->state, $first->nonce);
        self::assertNotSame($first->state, $second->state);
        self::assertNotSame($first->nonce, $second->nonce);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $first->state);
    }

    public function testItRejectsStateAndNonceValuesShorterThanAppleFlowSafety(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 32 characters');
        new LoginChallenge('short-state', str_repeat('n', 32));
    }

    public function testItRejectsAnEmptyCallbackState(): void
    {
        $challenge = LoginChallenge::generate();

        $this->expectException(StateMismatch::class);
        $challenge->assertState('');
    }

    public function testItHashesTheNonceForTheAuthorizationRequest(): void
    {
        $challenge = LoginChallenge::generate();

        self::assertSame(hash('sha256', $challenge->nonce), $challenge->hashedNonce());
        self::assertNotSame($challenge->nonce, $challenge->hashedNonce());
    }
}
