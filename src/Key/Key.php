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
use MonkeysLegion\Encryption\Exception\KeyException;

/**
 * Immutable encryption key value object with memory-safe destroy.
 *
 * Uses PHP 8.4 property hooks for computed state.
 */
final class Key
{
    private bool $destroyed = false;

    /**
     * Key length in bytes.
     */
    public int $length {
        get => strlen($this->keyMaterial);
    }

    /**
     * Whether the key material matches the expected cipher length.
     */
    public bool $isValid {
        get => $this->length === $this->cipher->keyLength();
    }

    /**
     * @param string $keyMaterial Raw key bytes.
     * @param Cipher $cipher     The cipher this key is for.
     */
    private function __construct(
        private string $keyMaterial,
        public readonly Cipher $cipher,
    ) {}

    // ── Static Factories ───────────────────────────────────────

    /**
     * Generate a new random key for the given cipher.
     */
    public static function generate(Cipher $cipher = Cipher::Aes256Gcm): self
    {
        $material = random_bytes(max(1, $cipher->keyLength()));

        return new self($material, $cipher);
    }

    /**
     * Create from raw key bytes.
     */
    public static function fromRaw(string $material, Cipher $cipher = Cipher::Aes256Gcm): self
    {
        if ($material === '') {
            throw KeyException::emptyKey();
        }

        $key = new self($material, $cipher);

        if (!$key->isValid) {
            throw KeyException::invalidLength($cipher->keyLength(), $key->length);
        }

        return $key;
    }

    /**
     * Create from base64-encoded key string.
     */
    public static function fromBase64(string $encoded, Cipher $cipher = Cipher::Aes256Gcm): self
    {
        // Strip "base64:" prefix if present
        if (str_starts_with($encoded, 'base64:')) {
            $encoded = substr($encoded, 7);
        }

        $decoded = base64_decode($encoded, true);

        if ($decoded === false) {
            throw KeyException::invalidBase64();
        }

        return self::fromRaw($decoded, $cipher);
    }

    // ── Access ─────────────────────────────────────────────────

    /**
     * Get the raw key material.
     */
    public function material(): string
    {
        if ($this->destroyed) {
            throw KeyException::destroyed();
        }

        return $this->keyMaterial;
    }

    /**
     * Get key as base64 string (prefixed with "base64:").
     */
    public function base64(): string
    {
        return 'base64:' . base64_encode($this->material());
    }

    /**
     * Get key as hex string.
     */
    public function hex(): string
    {
        return bin2hex($this->material());
    }

    /**
     * Wipe key material from memory.
     */
    public function destroy(): void
    {
        if (!$this->destroyed) {
            $zeroed = str_repeat("\0", strlen($this->keyMaterial));
            $this->keyMaterial = $zeroed;
            $this->destroyed = true;
        }
    }

    /**
     * Whether the key has been destroyed.
     */
    public function isDestroyed(): bool
    {
        return $this->destroyed;
    }

    // ── Security Guards ────────────────────────────────────────

    /**
     * @return never
     */
    public function __serialize(): array
    {
        throw new KeyException('Encryption keys must not be serialized.');
    }

    /**
     * @param array<string, mixed> $data
     * @return never
     */
    public function __unserialize(array $data): void
    {
        throw new KeyException('Encryption keys must not be unserialized.');
    }

    /**
     * @return never
     */
    public function __toString(): string
    {
        throw new KeyException('Encryption keys must not be converted to string.');
    }

    /**
     * Wipe key material on garbage collection.
     */
    public function __destruct()
    {
        $this->destroy();
    }
}
