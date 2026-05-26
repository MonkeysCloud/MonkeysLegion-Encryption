<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Testing;

use MonkeysLegion\Encryption\Contracts\EncrypterInterface;
use MonkeysLegion\Encryption\Key\Key;

/**
 * Fake encrypter for unit tests — reversible base64 round-trip.
 *
 * Records all operations for assertion helpers.
 */
final class FakeEncrypter implements EncrypterInterface
{
    private const string PREFIX = 'fake-encrypted:';

    /** @var list<array{operation: string, value: string}> */
    private array $recorded = [];

    public function __construct(
        private readonly Key $key,
    ) {}

    public function encrypt(string $value, bool $serialize = true): string
    {
        $data = $serialize ? serialize($value) : $value;
        $payload = self::PREFIX . base64_encode($data);

        $this->recorded[] = ['operation' => 'encrypt', 'value' => $value];

        return $payload;
    }

    public function decrypt(string $payload, bool $unserialize = true): string
    {
        $encoded = str_replace(self::PREFIX, '', $payload);
        $data = base64_decode($encoded, true);

        if ($data === false) {
            $data = '';
        }

        $this->recorded[] = ['operation' => 'decrypt', 'value' => $payload];

        if ($unserialize) {
            $result = @unserialize($data);

            return is_string($result) ? $result : $data;
        }

        return $data;
    }

    public function encryptString(string $value): string
    {
        return $this->encrypt($value, false);
    }

    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    public function getKey(): Key
    {
        return $this->key;
    }

    // ── Assertions ─────────────────────────────────────────────

    /**
     * Get all recorded operations.
     *
     * @return list<array{operation: string, value: string}>
     */
    public function recorded(): array
    {
        return $this->recorded;
    }

    /**
     * Get count of encrypt operations.
     */
    public function encryptCount(): int
    {
        return count(array_filter(
            $this->recorded,
            fn(array $r): bool => $r['operation'] === 'encrypt',
        ));
    }

    /**
     * Get count of decrypt operations.
     */
    public function decryptCount(): int
    {
        return count(array_filter(
            $this->recorded,
            fn(array $r): bool => $r['operation'] === 'decrypt',
        ));
    }

    /**
     * Assert nothing was encrypted or decrypted.
     */
    public function assertNothingEncrypted(): void
    {
        if ($this->recorded !== []) {
            throw new \RuntimeException(
                'Expected no encryption operations, but ' . count($this->recorded) . ' were recorded.',
            );
        }
    }
}
