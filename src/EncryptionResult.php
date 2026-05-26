<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption;

use MonkeysLegion\Encryption\Enum\Cipher;

/**
 * Immutable result of an encryption operation.
 *
 * Uses PHP 8.4 property hooks.
 */
final class EncryptionResult
{
    /**
     * Whether AEAD was used for this encryption.
     */
    public bool $isAead {
        get => $this->cipher->isAead();
    }

    /**
     * Whether sodium was the backend.
     */
    public bool $isSodium {
        get => $this->cipher->requiresSodium();
    }

    public function __construct(
        public readonly string $payload,
        public readonly Cipher $cipher,
    ) {}

    public function __toString(): string
    {
        return $this->payload;
    }
}
