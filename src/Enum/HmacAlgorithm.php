<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Enum;

/**
 * HMAC hash algorithms.
 */
enum HmacAlgorithm: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    /**
     * Output length in bytes.
     */
    public function outputLength(): int
    {
        return match ($this) {
            self::Sha256 => 32,
            self::Sha384 => 48,
            self::Sha512 => 64,
        };
    }

    /**
     * Human-readable label.
     */
    public function label(): string
    {
        return match ($this) {
            self::Sha256 => 'HMAC-SHA-256',
            self::Sha384 => 'HMAC-SHA-384',
            self::Sha512 => 'HMAC-SHA-512',
        };
    }
}
