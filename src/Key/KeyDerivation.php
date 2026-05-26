<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Key;

use MonkeysLegion\Encryption\Contracts\KeyDerivationInterface;
use MonkeysLegion\Encryption\Exception\KeyException;

/**
 * HKDF-based key derivation with context labels for domain separation.
 */
final class KeyDerivation implements KeyDerivationInterface
{
    /**
     * @param string $salt Optional salt for HKDF (empty string = no salt).
     */
    public function __construct(
        private readonly string $salt = '',
    ) {}

    /**
     * Derive a sub-key from a master key using HKDF-SHA256.
     */
    public function derive(string $masterKey, string $context, int $length = 32): string
    {
        if ($masterKey === '') {
            throw KeyException::emptyKey();
        }

        if ($length < 1 || $length > 255 * 32) {
            throw new KeyException("Invalid derived key length: {$length}");
        }

        $derived = hash_hkdf(
            algo: 'sha256',
            key: $masterKey,
            length: $length,
            info: $context,
            salt: $this->salt,
        );

        return $derived;
    }

    /**
     * Derive a Key object from a master key.
     */
    public function deriveKey(
        Key $masterKey,
        string $context,
        \MonkeysLegion\Encryption\Enum\Cipher $cipher = \MonkeysLegion\Encryption\Enum\Cipher::Aes256Gcm,
    ): DerivedKey {
        $material = $this->derive(
            $masterKey->material(),
            $context,
            $cipher->keyLength(),
        );

        return new DerivedKey(
            material: $material,
            context: $context,
            cipher: $cipher,
        );
    }
}
