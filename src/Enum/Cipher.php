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
 * Supported symmetric ciphers.
 */
enum Cipher: string
{
    case Aes128Cbc         = 'aes-128-cbc';
    case Aes256Cbc         = 'aes-256-cbc';
    case Aes128Gcm         = 'aes-128-gcm';
    case Aes256Gcm         = 'aes-256-gcm';
    case XChaCha20Poly1305 = 'xchacha20-poly1305';

    /**
     * Required key length in bytes.
     */
    public function keyLength(): int
    {
        return match ($this) {
            self::Aes128Cbc, self::Aes128Gcm => 16,
            self::Aes256Cbc, self::Aes256Gcm => 32,
            self::XChaCha20Poly1305         => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
        };
    }

    /**
     * IV/nonce length in bytes.
     */
    public function ivLength(): int
    {
        return match ($this) {
            self::Aes128Cbc, self::Aes256Cbc => 16,
            self::Aes128Gcm, self::Aes256Gcm => 12,
            self::XChaCha20Poly1305         => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
        };
    }

    /**
     * Whether this cipher provides authenticated encryption (AEAD).
     */
    public function isAead(): bool
    {
        return match ($this) {
            self::Aes128Cbc, self::Aes256Cbc => false,
            default                          => true,
        };
    }

    /**
     * Whether this cipher requires the sodium extension.
     */
    public function requiresSodium(): bool
    {
        return $this === self::XChaCha20Poly1305;
    }

    /**
     * Whether this cipher uses OpenSSL.
     */
    public function usesOpenSsl(): bool
    {
        return !$this->requiresSodium();
    }

    /**
     * Human-readable label.
     */
    public function label(): string
    {
        return match ($this) {
            self::Aes128Cbc         => 'AES-128-CBC',
            self::Aes256Cbc         => 'AES-256-CBC',
            self::Aes128Gcm         => 'AES-128-GCM',
            self::Aes256Gcm         => 'AES-256-GCM',
            self::XChaCha20Poly1305 => 'XChaCha20-Poly1305',
        };
    }
}
