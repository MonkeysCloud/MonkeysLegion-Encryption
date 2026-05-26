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
 * Password hashing algorithms.
 */
enum HashAlgorithm: string
{
    case Bcrypt  = 'bcrypt';
    case Argon2i = 'argon2i';
    case Argon2id = 'argon2id';

    /**
     * PHP password_hash() algorithm constant.
     */
    public function phpAlgo(): string
    {
        return match ($this) {
            self::Bcrypt  => PASSWORD_BCRYPT,
            self::Argon2i => PASSWORD_ARGON2I,
            self::Argon2id => PASSWORD_ARGON2ID,
        };
    }

    /**
     * Human-readable label.
     */
    public function label(): string
    {
        return match ($this) {
            self::Bcrypt  => 'Bcrypt',
            self::Argon2i => 'Argon2i',
            self::Argon2id => 'Argon2id',
        };
    }

    /**
     * Whether this is an Argon2 variant.
     */
    public function isArgon(): bool
    {
        return $this === self::Argon2i || $this === self::Argon2id;
    }
}
