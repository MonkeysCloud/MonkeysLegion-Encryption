<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Attribute;

use MonkeysLegion\Encryption\Enum\HashAlgorithm;

use Attribute;

/**
 * Mark an entity property for automatic password hashing.
 *
 * When the entity layer detects this attribute, the property value is
 * automatically hashed on write and the raw password is never stored.
 *
 * @example
 *   #[Hashed]
 *   public string $password;
 *
 *   #[Hashed(algorithm: HashAlgorithm::Bcrypt, options: ['rounds' => 14])]
 *   public string $password;
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
final class Hashed
{
    /**
     * @param HashAlgorithm              $algorithm Hashing algorithm (default: Argon2id).
     * @param array<string, int|string>  $options   Algorithm-specific options.
     */
    public function __construct(
        public readonly HashAlgorithm $algorithm = HashAlgorithm::Argon2id,
        public readonly array $options = [],
    ) {}

    /**
     * Whether this uses Argon2 (id or i).
     */
    public bool $isArgon {
        get => $this->algorithm->isArgon();
    }

    /**
     * Whether this uses Bcrypt.
     */
    public bool $isBcrypt {
        get => $this->algorithm === HashAlgorithm::Bcrypt;
    }
}
