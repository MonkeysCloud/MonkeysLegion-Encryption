<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Contracts;

/**
 * Contract for key derivation (HKDF).
 */
interface KeyDerivationInterface
{
    /**
     * Derive a sub-key from a master key with a context label.
     *
     * @param string $masterKey Raw master key material.
     * @param string $context   Context label for domain separation.
     * @param int    $length    Desired output length in bytes.
     *
     * @return string Derived key material.
     */
    public function derive(string $masterKey, string $context, int $length = 32): string;
}
