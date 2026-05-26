<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Key;

use MonkeysLegion\Encryption\Enum\Cipher;

/**
 * Generate cryptographically secure encryption keys.
 */
final class KeyGenerator
{
    /**
     * Generate a new key for the given cipher.
     */
    public static function generate(Cipher $cipher = Cipher::Aes256Gcm): Key
    {
        return Key::generate($cipher);
    }

    /**
     * Generate a key and return as base64 string.
     */
    public static function generateBase64(Cipher $cipher = Cipher::Aes256Gcm): string
    {
        return Key::generate($cipher)->base64();
    }

    /**
     * Generate a key and return as hex string.
     */
    public static function generateHex(Cipher $cipher = Cipher::Aes256Gcm): string
    {
        return Key::generate($cipher)->hex();
    }

    /**
     * Generate raw random bytes of the correct length for a cipher.
     */
    public static function generateRaw(Cipher $cipher = Cipher::Aes256Gcm): string
    {
        return random_bytes(max(1, $cipher->keyLength()));
    }
}
