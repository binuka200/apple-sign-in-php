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

    public function testItRejectsEmptyAppleCredentials(): void
    {
        $valid = ['TEAM123456', 'com.example.web', 'KEY1234567', 'pem'];
        $names = ['team ID', 'client ID', 'key ID', 'private key'];

        foreach ($names as $index => $name) {
            $arguments = $valid;
            $arguments[$index] = '  ';

            try {
                new ClientSecretGenerator(...$arguments);
                self::fail(sprintf('Expected an empty %s to be rejected.', $name));
            } catch (InvalidConfiguration $exception) {
                self::assertStringContainsString($name, $exception->getMessage());
            }
        }
    }

    public function testItRejectsANonPositiveLifetime(): void
    {
        $this->expectException(InvalidConfiguration::class);
        new ClientSecretGenerator('TEAM123456', 'com.example.web', 'KEY1234567', 'pem', 0);
    }

    public function testItReportsAPrivateKeyThatIsNotAP256SigningKey(): void
    {
        $generator = new ClientSecretGenerator('TEAM123456', 'com.example.web', 'KEY1234567', 'not-a-pem-key');

        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage('not a valid P-256 signing key');
        $generator->generate();
    }

    public function testItLoadsThePrivateKeyFromAFile(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'apple-key');
        self::assertIsString($path);

        try {
            self::assertNotFalse(file_put_contents($path, self::privateKey()));
            $generator = ClientSecretGenerator::fromKeyFile('TEAM123456', 'com.example.web', 'KEY1234567', $path);

            self::assertCount(3, explode('.', $generator->generate()));
        } finally {
            unlink($path);
        }
    }

    public function testItReportsAnUnreadablePrivateKeyFile(): void
    {
        $this->expectException(InvalidConfiguration::class);
        $this->expectExceptionMessage('could not be read');
        ClientSecretGenerator::fromKeyFile(
            'TEAM123456',
            'com.example.web',
            'KEY1234567',
            sys_get_temp_dir().'/apple-key-that-does-not-exist.p8',
        );
    }

    private static function privateKey(): string
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($key);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($key, $privateKey));

        return $privateKey;
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
