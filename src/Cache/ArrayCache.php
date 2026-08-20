<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Cache;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/** A request-local cache intended for simple setups and tests. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{value: mixed, expires: ?int}> */
    private array $values = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (!isset($this->values[$key])) {
            return $default;
        }

        $item = $this->values[$key];
        if ($item['expires'] !== null && $item['expires'] <= time()) {
            unset($this->values[$key]);
            return $default;
        }

        return $item['value'];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $seconds = $ttl instanceof DateInterval
            ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time()
            : $ttl;
        $this->values[$key] = [
            'value' => $value,
            'expires' => $seconds === null ? null : time() + max(0, $seconds),
        ];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->values = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get((string) $key, $default);
        }
        return $values;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        $missing = new \stdClass();
        return $this->get($key, $missing) !== $missing;
    }
}
