<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\EnvelopeEncrypter;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EnvelopeEncrypterTest extends TestCase
{
    #[Test]
    public function encrypt_decrypt_round_trip(): void
    {
        $masterKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $result = $env->encrypt('patient records');

        self::assertArrayHasKey('encrypted_data', $result);
        self::assertArrayHasKey('wrapped_key', $result);
        self::assertArrayHasKey('cipher', $result);

        $decrypted = $env->decrypt($result);
        self::assertSame('patient records', $decrypted);
    }

    #[Test]
    public function each_encryption_produces_unique_ciphertext(): void
    {
        $masterKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $a = $env->encrypt('same data');
        $b = $env->encrypt('same data');

        // Different DEKs → different ciphertext
        self::assertNotSame($a['encrypted_data'], $b['encrypted_data']);
        self::assertNotSame($a['wrapped_key'], $b['wrapped_key']);
    }

    #[Test]
    public function rewrap_with_new_master_key(): void
    {
        $oldMaster = Key::generate();
        $newMaster = Key::generate();
        $env = new EnvelopeEncrypter($oldMaster);

        $original = $env->encrypt('sensitive');

        // Re-wrap with new master key
        $rewrapped = $env->rewrap($original, $newMaster);

        // Data unchanged, key changed
        self::assertSame($original['encrypted_data'], $rewrapped['encrypted_data']);
        self::assertNotSame($original['wrapped_key'], $rewrapped['wrapped_key']);

        // Decrypt with new master key
        $newEnv = new EnvelopeEncrypter($newMaster);
        self::assertSame('sensitive', $newEnv->decrypt($rewrapped));
    }

    #[Test]
    public function wrong_master_key_throws(): void
    {
        $masterKey = Key::generate();
        $wrongKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $result = $env->encrypt('secret');

        $wrongEnv = new EnvelopeEncrypter($wrongKey);

        $this->expectException(DecryptionException::class);
        $wrongEnv->decrypt($result);
    }

    #[Test]
    public function tampered_wrapped_key_throws(): void
    {
        $masterKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $result = $env->encrypt('test');
        $result['wrapped_key'] = base64_encode('garbage');

        $this->expectException(DecryptionException::class);
        $env->decrypt($result);
    }

    #[Test]
    public function tampered_encrypted_data_throws(): void
    {
        $masterKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $result = $env->encrypt('test');
        $result['encrypted_data'] = base64_encode('garbage');

        $this->expectException(DecryptionException::class);
        $env->decrypt($result);
    }

    #[Test]
    #[DataProvider('cipherProvider')]
    public function works_with_different_ciphers(Cipher $cipher): void
    {
        $masterKey = Key::generate($cipher);
        $env = new EnvelopeEncrypter($masterKey, $cipher);

        $result = $env->encrypt('multi-cipher');
        self::assertSame($cipher->value, $result['cipher']);
        self::assertSame('multi-cipher', $env->decrypt($result));
    }

    #[Test]
    public function empty_string_round_trip(): void
    {
        $masterKey = Key::generate();
        $env = new EnvelopeEncrypter($masterKey);

        $result = $env->encrypt('');
        self::assertSame('', $env->decrypt($result));
    }

    /**
     * @return iterable<string, array{Cipher}>
     */
    public static function cipherProvider(): iterable
    {
        yield 'AES-256-GCM' => [Cipher::Aes256Gcm];
        yield 'AES-128-GCM' => [Cipher::Aes128Gcm];
        yield 'XChaCha20' => [Cipher::XChaCha20Poly1305];
    }
}
