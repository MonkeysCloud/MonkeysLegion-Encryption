<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\KeyException;
use MonkeysLegion\Encryption\Key\DerivedKey;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyDerivation;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class KeyDerivationTest extends TestCase
{
    #[Test]
    public function derive_raw_bytes(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = random_bytes(32);

        $derived = $kdf->derive($master, 'context-v1', 32);

        self::assertSame(32, strlen($derived));
    }

    #[Test]
    public function same_context_same_output(): void
    {
        $salt = random_bytes(16);
        $kdf = new KeyDerivation(salt: $salt);
        $master = random_bytes(32);

        $a = $kdf->derive($master, 'same-context');
        $b = $kdf->derive($master, 'same-context');

        self::assertSame($a, $b);
    }

    #[Test]
    public function different_context_different_output(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = random_bytes(32);

        $a = $kdf->derive($master, 'encryption-v1');
        $b = $kdf->derive($master, 'authentication-v1');

        self::assertNotSame($a, $b);
    }

    #[Test]
    public function different_salt_different_output(): void
    {
        $master = random_bytes(32);
        $context = 'same-context';

        $a = (new KeyDerivation(salt: 'salt-a'))->derive($master, $context);
        $b = (new KeyDerivation(salt: 'salt-b'))->derive($master, $context);

        self::assertNotSame($a, $b);
    }

    #[Test]
    public function derive_key_returns_derived_key_object(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = Key::generate();

        $dk = $kdf->deriveKey($master, 'sub-key-v1');

        self::assertInstanceOf(DerivedKey::class, $dk);
        self::assertTrue($dk->isValid);
        self::assertSame(32, $dk->length); // Default AES-256-GCM
    }

    #[Test]
    public function derive_key_with_specific_cipher(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = Key::generate();

        $dk = $kdf->deriveKey($master, 'aes128', Cipher::Aes128Gcm);

        self::assertSame(16, $dk->length);
        self::assertSame(Cipher::Aes128Gcm, $dk->cipher);
    }

    #[Test]
    public function derived_key_to_key_works(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = Key::generate();

        $dk = $kdf->deriveKey($master, 'sub-key');
        $key = $dk->toKey();

        self::assertInstanceOf(Key::class, $key);
        self::assertSame($dk->material(), $key->material());
    }

    #[Test]
    public function derived_key_base64(): void
    {
        $kdf = new KeyDerivation(salt: random_bytes(16));
        $master = Key::generate();

        $dk = $kdf->deriveKey($master, 'test');
        $b64 = $dk->base64();

        self::assertSame($dk->material(), base64_decode($b64, true));
    }

    #[Test]
    public function empty_master_key_throws(): void
    {
        $kdf = new KeyDerivation();

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('must not be empty');

        $kdf->derive('', 'context');
    }

    #[Test]
    public function invalid_length_throws(): void
    {
        $kdf = new KeyDerivation();

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('Invalid derived key length');

        $kdf->derive(random_bytes(32), 'context', 0);
    }

    #[Test]
    public function no_salt_works(): void
    {
        $kdf = new KeyDerivation(); // No salt
        $master = random_bytes(32);

        $derived = $kdf->derive($master, 'context');
        self::assertSame(32, strlen($derived));
    }
}
