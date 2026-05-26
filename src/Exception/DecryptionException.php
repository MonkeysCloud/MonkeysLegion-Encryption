<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Exception;

/**
 * Thrown when decryption fails — invalid payload, MAC mismatch, or wrong key.
 */
class DecryptionException extends EncryptionException
{
    public static function invalidPayload(): self
    {
        return new self('The payload is invalid or has been tampered with.');
    }

    public static function macMismatch(): self
    {
        return new self('The MAC verification failed — payload integrity compromised.');
    }

    public static function unsupportedCipher(string $cipher): self
    {
        return new self("Unsupported cipher \"{$cipher}\" in encrypted payload.");
    }

    public static function noKeyDecrypted(): self
    {
        return new self('Unable to decrypt with any available key in the key chain.');
    }
}
