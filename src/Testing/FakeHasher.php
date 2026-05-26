<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Testing;

use MonkeysLegion\Encryption\Contracts\HasherInterface;
use MonkeysLegion\Encryption\Hash\HashInfo;

/**
 * Fake hasher for unit tests — plaintext round-trip.
 */
final class FakeHasher implements HasherInterface
{
    private const string PREFIX = 'fakehash:';

    public function hash(string $value): string
    {
        return self::PREFIX . $value;
    }

    public function verify(string $value, string $hash): bool
    {
        return $hash === self::PREFIX . $value;
    }

    public function needsRehash(string $hash): bool
    {
        return !str_starts_with($hash, self::PREFIX);
    }

    public function info(string $hash): HashInfo
    {
        return new HashInfo(
            algorithmName: 'fake',
            options: [],
        );
    }
}
