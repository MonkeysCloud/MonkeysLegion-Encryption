<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Key;

use MonkeysLegion\Encryption\Exception\DecryptionException;

/**
 * Multi-key chain for graceful key rotation.
 *
 * Encrypts with the current key, decrypts trying all keys (current + previous).
 * Uses PHP 8.4 property hooks.
 */
final class KeyChain
{
    /**
     * Whether there are previous keys in the chain.
     */
    public bool $hasPreviousKeys {
        get => $this->previousKeys !== [];
    }

    /**
     * Total number of keys (current + previous).
     */
    public int $keyCount {
        get => 1 + count($this->previousKeys);
    }

    /**
     * @param Key       $currentKey   The active key for encryption.
     * @param list<Key> $previousKeys Old keys for decryption fallback (newest first).
     */
    public function __construct(
        private readonly Key $currentKey,
        private readonly array $previousKeys = [],
    ) {}

    /**
     * Create a key chain with only a current key.
     */
    public static function single(Key $key): self
    {
        return new self($key);
    }

    /**
     * Create a key chain with rotation support.
     *
     * @param list<Key> $previousKeys
     */
    public static function withRotation(Key $currentKey, array $previousKeys): self
    {
        return new self($currentKey, $previousKeys);
    }

    /**
     * Get the current (active) key.
     */
    public function current(): Key
    {
        return $this->currentKey;
    }

    /**
     * Get previous keys for decryption fallback.
     *
     * @return list<Key>
     */
    public function previous(): array
    {
        return $this->previousKeys;
    }

    /**
     * Get all keys: current first, then previous.
     *
     * @return list<Key>
     */
    public function all(): array
    {
        return [$this->currentKey, ...$this->previousKeys];
    }

    /**
     * Try to decrypt with each key in the chain until one succeeds.
     *
     * @template T
     * @param callable(Key): T $decryptor
     * @return T
     *
     * @throws DecryptionException If no key can decrypt the payload.
     */
    public function tryDecrypt(callable $decryptor): mixed
    {
        $lastException = null;

        foreach ($this->all() as $key) {
            try {
                return $decryptor($key);
            } catch (\Throwable $e) {
                $lastException = $e;
                continue;
            }
        }

        throw DecryptionException::noKeyDecrypted();
    }
}
