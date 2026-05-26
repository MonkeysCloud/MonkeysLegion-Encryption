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
 * Thrown on invalid key length, missing key material, or key generation failures.
 */
class KeyException extends EncryptionException
{
    public static function invalidLength(int $expected, int $actual): self
    {
        return new self("Invalid key length: expected {$expected} bytes, got {$actual} bytes.");
    }

    public static function emptyKey(): self
    {
        return new self('Encryption key must not be empty.');
    }

    public static function invalidBase64(): self
    {
        return new self('The provided key is not valid base64.');
    }

    public static function destroyed(): self
    {
        return new self('Cannot access a destroyed key — material has been wiped from memory.');
    }

    public static function generationFailed(string $reason): self
    {
        return new self("Key generation failed: {$reason}");
    }
}
