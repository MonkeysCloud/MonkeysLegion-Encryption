<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Contracts;

use MonkeysLegion\Encryption\Key\Key;

/**
 * Contract for symmetric encryption/decryption.
 */
interface EncrypterInterface
{
    /**
     * Encrypt the given value.
     *
     * @param string $value     Plaintext to encrypt.
     * @param bool   $serialize Whether to serialize the value before encrypting.
     *
     * @return string Encrypted payload (base64-encoded JSON envelope).
     */
    public function encrypt(string $value, bool $serialize = true): string;

    /**
     * Decrypt the given payload.
     *
     * @param string $payload     Encrypted payload.
     * @param bool   $unserialize Whether to unserialize after decrypting.
     *
     * @return string Decrypted value.
     */
    public function decrypt(string $payload, bool $unserialize = true): string;

    /**
     * Encrypt a string without serialization.
     */
    public function encryptString(string $value): string;

    /**
     * Decrypt a string without unserialization.
     */
    public function decryptString(string $payload): string;

    /**
     * Get the current encryption key.
     */
    public function getKey(): Key;
}
