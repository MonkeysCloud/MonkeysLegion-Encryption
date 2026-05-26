<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Contracts;

use MonkeysLegion\Encryption\Hash\HashInfo;

/**
 * Contract for password hashing.
 */
interface HasherInterface
{
    /**
     * Hash the given value.
     */
    public function hash(string $value): string;

    /**
     * Verify a value against a hash.
     */
    public function verify(string $value, string $hash): bool;

    /**
     * Check if a hash needs rehashing (algorithm/options changed).
     */
    public function needsRehash(string $hash): bool;

    /**
     * Get information about a hash.
     */
    public function info(string $hash): HashInfo;
}
