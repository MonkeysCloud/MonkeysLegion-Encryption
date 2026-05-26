<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Hash;

/**
 * Information about a password hash.
 *
 * Uses PHP 8.4 property hooks.
 */
final class HashInfo
{
    /**
     * Whether this is a Bcrypt hash.
     */
    public bool $isBcrypt {
        get => $this->algorithmName === 'bcrypt';
    }

    /**
     * Whether this is an Argon2 variant.
     */
    public bool $isArgon2 {
        get => str_starts_with($this->algorithmName, 'argon2');
    }

    /**
     * Whether the hash uses a known algorithm.
     */
    public bool $isKnown {
        get => $this->algorithmName !== 'unknown';
    }

    /**
     * @param string               $algorithmName Algorithm identifier string.
     * @param array<string, mixed> $options       Algorithm-specific options.
     */
    public function __construct(
        public readonly string $algorithmName,
        public readonly array $options,
    ) {}

    /**
     * Create from a password hash string.
     */
    public static function fromHash(string $hash): self
    {
        $info = password_get_info($hash);

        return new self(
            algorithmName: $info['algoName'],
            options: $info['options'],
        );
    }
}
