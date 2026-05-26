<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Attribute;

use MonkeysLegion\Encryption\Enum\Cipher;

use Attribute;

/**
 * Mark an entity property for automatic encryption/decryption.
 *
 * Competitive with Laravel's `encrypted` cast — but attribute-first,
 * cipher-configurable per field, and uses PHP 8.4 property hooks for the
 * entity integration layer.
 *
 * @example
 *   #[Encrypted]
 *   public string $ssn;
 *
 *   #[Encrypted(cipher: Cipher::XChaCha20Poly1305)]
 *   public string $medicalRecord;
 *
 *   #[Encrypted(deterministic: true)]
 *   public string $email;  // Searchable encrypted field
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
final class Encrypted
{
    /**
     * @param Cipher|null $cipher        Override the default cipher for this field.
     * @param bool        $deterministic Use deterministic encryption (searchable).
     * @param string      $keyId         Named key from the key chain (future multi-key).
     */
    public function __construct(
        public readonly ?Cipher $cipher = null,
        public readonly bool $deterministic = false,
        public readonly string $keyId = 'default',
    ) {}

    /**
     * Whether this field uses deterministic (searchable) encryption.
     */
    public bool $isSearchable {
        get => $this->deterministic;
    }

    /**
     * Whether a custom cipher is specified.
     */
    public bool $hasCustomCipher {
        get => $this->cipher !== null;
    }
}
