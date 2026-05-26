<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Hmac;

use MonkeysLegion\Encryption\Contracts\HmacInterface;
use MonkeysLegion\Encryption\Enum\HmacAlgorithm;
use MonkeysLegion\Encryption\Exception\EncryptionException;

/**
 * HMAC signing and verification service.
 */
final class HmacSigner implements HmacInterface
{
    public function __construct(
        private readonly string $defaultKey = '',
    ) {}

    /**
     * Sign data and return the hex-encoded MAC.
     */
    public function sign(
        string $data,
        ?string $key = null,
        HmacAlgorithm $algorithm = HmacAlgorithm::Sha256,
    ): string {
        $signingKey = $key ?? $this->defaultKey;

        if ($signingKey === '') {
            throw new EncryptionException('HMAC key must not be empty.');
        }

        return hash_hmac($algorithm->value, $data, $signingKey);
    }

    /**
     * Sign data and return the raw binary MAC.
     */
    public function signRaw(
        string $data,
        ?string $key = null,
        HmacAlgorithm $algorithm = HmacAlgorithm::Sha256,
    ): string {
        $signingKey = $key ?? $this->defaultKey;

        if ($signingKey === '') {
            throw new EncryptionException('HMAC key must not be empty.');
        }

        return hash_hmac($algorithm->value, $data, $signingKey, true);
    }

    /**
     * Verify a MAC against data using constant-time comparison.
     */
    public function verify(
        string $data,
        string $mac,
        ?string $key = null,
        HmacAlgorithm $algorithm = HmacAlgorithm::Sha256,
    ): bool {
        $expected = $this->sign($data, $key, $algorithm);

        return hash_equals($expected, $mac);
    }

    /**
     * Sign and return a structured result.
     */
    public function signResult(
        string $data,
        ?string $key = null,
        HmacAlgorithm $algorithm = HmacAlgorithm::Sha256,
    ): HmacResult {
        return new HmacResult(
            mac: $this->sign($data, $key, $algorithm),
            algorithm: $algorithm,
            data: $data,
        );
    }
}
