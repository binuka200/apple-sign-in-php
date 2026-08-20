<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SafeApple\SignIn\ClientSecretGenerator;
use SafeApple\SignIn\Exception\InvalidConfiguration;
use SafeApple\SignIn\Tests\Support\FixedClock;

final class ClientSecretGeneratorTest extends TestCase
{
    public function testItGeneratesAnAppleEs256ClientSecret(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($key);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($key, $privateKey));
        $clock = new FixedClock(new DateTimeImmutable('@1700000000'));
        $generator = new ClientSecretGenerator('TEAM123456', 'com.example.web', 'KEY1234567', $privateKey, 600, $clock);

        $segments = explode('.', $generator->generate());
        self::assertCount(3, $segments);
        $header = self::decode($segments[0]);
        $claims = self::decode($segments[1]);

        self::assertSame('ES256', $header['alg']);
        self::assertSame('KEY1234567', $header['kid']);
        self::assertSame('TEAM123456', $claims['iss']);
        self::assertSame('com.example.web', $claims['sub']);
        self::assertSame('https://appleid.apple.com', $claims['aud']);
        self::assertSame(1700000000, $claims['iat']);
        self::assertSame(1700000600, $claims['exp']);
    }

    public function testItRejectsASecretLongerThanAppleAllows(): void
    {
        $this->expectException(InvalidConfiguration::class);
        new ClientSecretGenerator('team', 'client', 'key', 'pem', ClientSecretGenerator::MAX_LIFETIME + 1);
    }

    /** @return array<string, mixed> */
    private static function decode(string $value): array
    {
        $value = strtr($value, '-_', '+/');
        $value .= str_repeat('=', (4 - strlen($value) % 4) % 4);
        $json = base64_decode($value, true);
        self::assertNotFalse($json);
        return json_decode($json, true, 16, JSON_THROW_ON_ERROR);
    }
}
