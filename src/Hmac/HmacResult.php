<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Hmac;

use MonkeysLegion\Encryption\Enum\HmacAlgorithm;

/**
 * Result of an HMAC signing operation.
 *
 * Uses PHP 8.4 property hooks.
 */
final class HmacResult
{
    /**
     * Length of the MAC in hex characters.
     */
    public int $length {
        get => strlen($this->mac);
    }

    public function __construct(
        public readonly string $mac,
        public readonly HmacAlgorithm $algorithm,
        public readonly string $data,
    ) {}

    /**
     * Verify a MAC against this result using constant-time comparison.
     */
    public function verify(string $mac): bool
    {
        return hash_equals($this->mac, $mac);
    }

    public function __toString(): string
    {
        return $this->mac;
    }
}
