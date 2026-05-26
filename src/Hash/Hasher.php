<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Hash;

use MonkeysLegion\Encryption\Contracts\HasherInterface;
use MonkeysLegion\Encryption\Enum\HashAlgorithm;

/**
 * Password hasher supporting Bcrypt, Argon2i, and Argon2id.
 */
final class Hasher implements HasherInterface
{
    /**
     * @param HashAlgorithm        $algorithm Default hashing algorithm.
     * @param array<string, mixed> $options   Algorithm-specific options.
     */
    public function __construct(
        private readonly HashAlgorithm $algorithm = HashAlgorithm::Argon2id,
        private readonly array $options = [],
    ) {}

    /**
     * Hash the given value.
     */
    public function hash(string $value): string
    {
        return password_hash($value, $this->algorithm->phpAlgo(), $this->buildOptions());
    }

    /**
     * Verify a value against a hash.
     */
    public function verify(string $value, string $hash): bool
    {
        return password_verify($value, $hash);
    }

    /**
     * Check if a hash needs rehashing.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm->phpAlgo(), $this->buildOptions());
    }

    /**
     * Get information about a hash.
     */
    public function info(string $hash): HashInfo
    {
        return HashInfo::fromHash($hash);
    }

    // ── Internal ───────────────────────────────────────────────

    /**
     * @return array<string, mixed>
     */
    private function buildOptions(): array
    {
        if ($this->algorithm === HashAlgorithm::Bcrypt) {
            return [
                'cost' => $this->options['rounds'] ?? 12,
            ];
        }

        if ($this->algorithm->isArgon()) {
            return [
                'memory_cost' => $this->options['memory'] ?? PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
                'time_cost'   => $this->options['time'] ?? PASSWORD_ARGON2_DEFAULT_TIME_COST,
                'threads'     => $this->options['threads'] ?? PASSWORD_ARGON2_DEFAULT_THREADS,
            ];
        }

        return $this->options;
    }
}
