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
 * Result of a key derivation operation.
 *
 * Uses PHP 8.4 property hooks.
 */
final class DerivedKey
{
    /**
     * Length of the derived key in bytes.
     */
    public int $length {
        get => strlen($this->material);
    }

    /**
     * Whether the key length matches the target cipher.
     */
    public bool $isValid {
        get => $this->length === $this->cipher->keyLength();
    }

    public function __construct(
        private readonly string $material,
        public readonly string $context,
        public readonly Cipher $cipher,
    ) {}

    /**
     * Get the raw derived key material.
     */
    public function material(): string
    {
        return $this->material;
    }

    /**
     * Convert to a Key object for use with encrypters.
     */
    public function toKey(): Key
    {
        return Key::fromRaw($this->material, $this->cipher);
    }

    /**
     * Get as base64.
     */
    public function base64(): string
    {
        return base64_encode($this->material);
    }
}
