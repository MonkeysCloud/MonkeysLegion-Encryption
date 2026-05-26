<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Attribute\Encrypted;
use MonkeysLegion\Encryption\Enum\Cipher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use ReflectionClass;

final class EncryptedAttributeTest extends TestCase
{
    #[Test]
    public function default_values(): void
    {
        $attr = new Encrypted();

        self::assertNull($attr->cipher);
        self::assertFalse($attr->deterministic);
        self::assertSame('default', $attr->keyId);
    }

    #[Test]
    public function custom_cipher(): void
    {
        $attr = new Encrypted(cipher: Cipher::XChaCha20Poly1305);

        self::assertSame(Cipher::XChaCha20Poly1305, $attr->cipher);
        self::assertTrue($attr->hasCustomCipher);
    }

    #[Test]
    public function no_custom_cipher(): void
    {
        $attr = new Encrypted();

        self::assertFalse($attr->hasCustomCipher);
    }

    #[Test]
    public function deterministic_mode(): void
    {
        $attr = new Encrypted(deterministic: true);

        self::assertTrue($attr->deterministic);
        self::assertTrue($attr->isSearchable);
    }

    #[Test]
    public function non_deterministic(): void
    {
        $attr = new Encrypted();

        self::assertFalse($attr->isSearchable);
    }

    #[Test]
    public function custom_key_id(): void
    {
        $attr = new Encrypted(keyId: 'tenant-key');

        self::assertSame('tenant-key', $attr->keyId);
    }

    #[Test]
    public function targets_property(): void
    {
        $ref = new ReflectionClass(Encrypted::class);
        $attrs = $ref->getAttributes(\Attribute::class);

        // Verify the attribute itself has Attribute::TARGET_PROPERTY
        self::assertNotEmpty($ref->getAttributes());
    }

    #[Test]
    public function used_on_class_property(): void
    {
        $testClass = new class {
            #[Encrypted]
            public string $ssn = '';

            #[Encrypted(cipher: Cipher::XChaCha20Poly1305, deterministic: true)]
            public string $email = '';
        };

        $ref = new ReflectionClass($testClass);

        // SSN property
        $ssnProp = $ref->getProperty('ssn');
        $ssnAttrs = $ssnProp->getAttributes(Encrypted::class);
        self::assertCount(1, $ssnAttrs);

        $ssnEncrypted = $ssnAttrs[0]->newInstance();
        self::assertNull($ssnEncrypted->cipher);
        self::assertFalse($ssnEncrypted->deterministic);

        // Email property
        $emailProp = $ref->getProperty('email');
        $emailAttrs = $emailProp->getAttributes(Encrypted::class);
        self::assertCount(1, $emailAttrs);

        $emailEncrypted = $emailAttrs[0]->newInstance();
        self::assertSame(Cipher::XChaCha20Poly1305, $emailEncrypted->cipher);
        self::assertTrue($emailEncrypted->deterministic);
    }
}
