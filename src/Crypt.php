<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption;

use MonkeysLegion\Encryption\Contracts\EncrypterInterface;
use MonkeysLegion\Encryption\Key\Key;

use RuntimeException;

/**
 * Static encryption facade — convenience API for application code.
 *
 * Must be initialized once via `Crypt::setInstance()` (typically by the
 * service provider or bootstrap). Provides a clean, static API similar
 * to Laravel's `Crypt::encrypt()` / `Crypt::decrypt()`.
 *
 * @example
 *   // Bootstrap (done once by the framework)
 *   Crypt::setInstance(new Encrypter($key));
 *
 *   // Application code
 *   $encrypted = Crypt::encrypt('sensitive data');
 *   $decrypted = Crypt::decrypt($encrypted);
 *
 *   $token = Crypt::encryptString($rawToken);
 *   $raw   = Crypt::decryptString($token);
 */
final class Crypt
{
    private static ?EncrypterInterface $instance = null;

    /**
     * Prevent instantiation.
     */
    private function __construct() {}

    // ── Configuration ─────────────────────────────────────────

    /**
     * Set the global encrypter instance.
     */
    public static function setInstance(EncrypterInterface $encrypter): void
    {
        self::$instance = $encrypter;
    }

    /**
     * Get the global encrypter instance.
     */
    public static function getInstance(): EncrypterInterface
    {
        return self::$instance ?? throw new RuntimeException(
            'Crypt has not been initialized. Call Crypt::setInstance() first.',
        );
    }

    /**
     * Reset the instance (useful in tests).
     */
    public static function reset(): void
    {
        self::$instance = null;
    }

    // ── Encryption API ────────────────────────────────────────

    /**
     * Encrypt a value (with serialization).
     */
    public static function encrypt(string $value, bool $serialize = true): string
    {
        return self::getInstance()->encrypt($value, $serialize);
    }

    /**
     * Decrypt a payload (with unserialization).
     */
    public static function decrypt(string $payload, bool $unserialize = true): string
    {
        return self::getInstance()->decrypt($payload, $unserialize);
    }

    /**
     * Encrypt a string (without serialization).
     */
    public static function encryptString(string $value): string
    {
        return self::getInstance()->encryptString($value);
    }

    /**
     * Decrypt a string (without unserialization).
     */
    public static function decryptString(string $payload): string
    {
        return self::getInstance()->decryptString($payload);
    }

    /**
     * Get the current encryption key.
     */
    public static function getKey(): Key
    {
        return self::getInstance()->getKey();
    }
}
