<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Exception;

use RuntimeException;

/**
 * Base exception for all encryption-related errors.
 */
class EncryptionException extends RuntimeException
{
    public static function wrap(string $message, ?\Throwable $previous = null): self
    {
        return new self($message, 0, $previous);
    }
}
