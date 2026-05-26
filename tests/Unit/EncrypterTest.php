<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Encrypter;
use MonkeysLegion\Encryption\EncryptionResult;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyChain;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EncrypterTest extends TestCase
{
    // ── Round-trip per cipher ──────────────────────────────────

    #[Test]
    #[DataProvider('cipherProvider')]
    public function encrypt_decrypt_round_trip(Cipher $cipher): void
    {
        $key = Key::generate($cipher);
        $enc = new Encrypter($key, $cipher);

        $plain = 'Hello MonkeysLegion!';
        $encrypted = $enc->encryptString($plain);

        self::assertNotSame($plain, $encrypted);
        self::assertSame($plain, $enc->decryptString($encrypted));
    }

    #[Test]
    #[DataProvider('cipherProvider')]
    public function encrypt_with_serialization(Cipher $cipher): void
    {
        $key = Key::generate($cipher);
        $enc = new Encrypter($key, $cipher);

        $plain = 'Serialized value';
        $encrypted = $enc->encrypt($plain, true);
        $decrypted = $enc->decrypt($encrypted, true);

        self::assertSame($plain, $decrypted);
    }

    /**
     * @return iterable<string, array{Cipher}>
     */
    public static function cipherProvider(): iterable
    {
        yield 'AES-128-CBC' => [Cipher::Aes128Cbc];
        yield 'AES-256-CBC' => [Cipher::Aes256Cbc];
        yield 'AES-128-GCM' => [Cipher::Aes128Gcm];
        yield 'AES-256-GCM' => [Cipher::Aes256Gcm];
        yield 'XChaCha20-Poly1305' => [Cipher::XChaCha20Poly1305];
    }

    // ── Key rotation ──────────────────────────────────────────

    #[Test]
    public function key_rotation_decrypts_old_key(): void
    {
        $oldKey = Key::generate();
        $newKey = Key::generate();

        // Encrypt with old key
        $oldEnc = new Encrypter($oldKey);
        $encrypted = $oldEnc->encryptString('secret');

        // Rotate: new key + old as previous
        $chain = KeyChain::withRotation($newKey, [$oldKey]);
        $rotatedEnc = new Encrypter($chain);

        self::assertSame('secret', $rotatedEnc->decryptString($encrypted));
    }

    #[Test]
    public function key_rotation_encrypts_with_current_key(): void
    {
        $newKey = Key::generate();
        $oldKey = Key::generate();

        $chain = KeyChain::withRotation($newKey, [$oldKey]);
        $enc = new Encrypter($chain);

        $encrypted = $enc->encryptString('new data');

        // Should be decryptable with current key alone
        $singleEnc = new Encrypter($newKey);
        self::assertSame('new data', $singleEnc->decryptString($encrypted));
    }

    // ── Property hooks ────────────────────────────────────────

    #[Test]
    public function cipher_property_hook(): void
    {
        $key = Key::generate(Cipher::Aes128Gcm);
        $enc = new Encrypter($key, Cipher::Aes128Gcm);

        self::assertSame(Cipher::Aes128Gcm, $enc->cipher);
    }

    #[Test]
    public function using_rotation_property_hook(): void
    {
        $key = Key::generate();
        $enc = new Encrypter($key);
        self::assertFalse($enc->usingRotation);

        $chain = KeyChain::withRotation($key, [Key::generate()]);
        $enc2 = new Encrypter($chain);
        self::assertTrue($enc2->usingRotation);
    }

    // ── Structured result ─────────────────────────────────────

    #[Test]
    public function encrypt_result_returns_encryption_result(): void
    {
        $key = Key::generate();
        $enc = new Encrypter($key);

        $result = $enc->encryptResult('test');

        self::assertInstanceOf(EncryptionResult::class, $result);
        self::assertTrue($result->isAead);
        self::assertFalse($result->isSodium);
        self::assertSame('test', $enc->decryptString($result->payload));
    }

    // ── Tamper detection ──────────────────────────────────────

    #[Test]
    public function tampered_payload_throws(): void
    {
        $key = Key::generate();
        $enc = new Encrypter($key);

        $encrypted = $enc->encryptString('genuine');

        // Tamper by flipping a character
        $tampered = substr($encrypted, 0, -2) . 'XX';

        $this->expectException(DecryptionException::class);
        $enc->decryptString($tampered);
    }

    #[Test]
    public function wrong_key_throws(): void
    {
        $key1 = Key::generate();
        $key2 = Key::generate();

        $enc1 = new Encrypter($key1);
        $enc2 = new Encrypter($key2);

        $encrypted = $enc1->encryptString('secret');

        $this->expectException(DecryptionException::class);
        $enc2->decryptString($encrypted);
    }

    // ── getKey ─────────────────────────────────────────────────

    #[Test]
    public function get_key_returns_current_key(): void
    {
        $key = Key::generate();
        $enc = new Encrypter($key);

        self::assertSame($key, $enc->getKey());
    }
}
