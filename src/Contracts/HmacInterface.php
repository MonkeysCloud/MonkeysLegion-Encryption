<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Contracts;

use MonkeysLegion\Encryption\Enum\HmacAlgorithm;

/**
 * Contract for HMAC signing and verification.
 */
interface HmacInterface
{
    /**
     * Sign data and return the hex-encoded MAC.
     */
    public function sign(string $data, ?string $key = null, HmacAlgorithm $algorithm = HmacAlgorithm::Sha256): string;

    /**
     * Verify a MAC against data (constant-time comparison).
     */
    public function verify(
        string $data,
        string $mac,
        ?string $key = null,
        HmacAlgorithm $algorithm = HmacAlgorithm::Sha256,
    ): bool;
}
