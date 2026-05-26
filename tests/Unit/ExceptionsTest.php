<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Exception\KeyException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ExceptionsTest extends TestCase
{
    // ── DecryptionException ───────────────────────────────────

    #[Test]
    public function decryption_exception_invalid_payload(): void
    {
        $e = DecryptionException::invalidPayload();

        self::assertInstanceOf(DecryptionException::class, $e);
        self::assertStringContainsString('tampered', $e->getMessage());
    }

    #[Test]
    public function decryption_exception_mac_mismatch(): void
    {
        $e = DecryptionException::macMismatch();

        self::assertStringContainsString('MAC', $e->getMessage());
    }

    #[Test]
    public function decryption_exception_unsupported_cipher(): void
    {
        $e = DecryptionException::unsupportedCipher('fake-cipher');

        self::assertStringContainsString('fake-cipher', $e->getMessage());
    }

    #[Test]
    public function decryption_exception_no_key_decrypted(): void
    {
        $e = DecryptionException::noKeyDecrypted();

        self::assertStringContainsString('Unable to decrypt', $e->getMessage());
    }

    #[Test]
    public function decryption_extends_encryption_exception(): void
    {
        $e = DecryptionException::invalidPayload();

        self::assertInstanceOf(EncryptionException::class, $e);
    }

    // ── EncryptionException ───────────────────────────────────

    #[Test]
    public function encryption_exception_wrap(): void
    {
        $previous = new \RuntimeException('inner');
        $e = EncryptionException::wrap('outer', $previous);

        self::assertSame('outer', $e->getMessage());
        self::assertSame($previous, $e->getPrevious());
    }

    #[Test]
    public function encryption_exception_extends_runtime(): void
    {
        $e = new EncryptionException('test');

        self::assertInstanceOf(\RuntimeException::class, $e);
    }

    // ── KeyException ──────────────────────────────────────────

    #[Test]
    public function key_exception_invalid_length(): void
    {
        $e = KeyException::invalidLength(32, 16);

        self::assertStringContainsString('32', $e->getMessage());
        self::assertStringContainsString('16', $e->getMessage());
    }

    #[Test]
    public function key_exception_empty_key(): void
    {
        $e = KeyException::emptyKey();

        self::assertStringContainsString('empty', $e->getMessage());
    }

    #[Test]
    public function key_exception_invalid_base64(): void
    {
        $e = KeyException::invalidBase64();

        self::assertStringContainsString('base64', $e->getMessage());
    }

    #[Test]
    public function key_exception_destroyed(): void
    {
        $e = KeyException::destroyed();

        self::assertStringContainsString('destroyed', $e->getMessage());
    }

    #[Test]
    public function key_exception_generation_failed(): void
    {
        $e = KeyException::generationFailed('out of entropy');

        self::assertStringContainsString('out of entropy', $e->getMessage());
    }

    #[Test]
    public function key_exception_extends_encryption_exception(): void
    {
        $e = KeyException::emptyKey();

        self::assertInstanceOf(EncryptionException::class, $e);
    }
}
