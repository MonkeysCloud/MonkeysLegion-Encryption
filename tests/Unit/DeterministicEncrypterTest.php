<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\DeterministicEncrypter;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DeterministicEncrypterTest extends TestCase
{
    #[Test]
    public function same_input_produces_same_output(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $a = $det->encrypt('user@example.com');
        $b = $det->encrypt('user@example.com');

        self::assertSame($a, $b);
    }

    #[Test]
    public function different_input_produces_different_output(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $a = $det->encrypt('alice@example.com');
        $b = $det->encrypt('bob@example.com');

        self::assertNotSame($a, $b);
    }

    #[Test]
    public function decrypt_round_trip(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $encrypted = $det->encrypt('secret data');
        $decrypted = $det->decrypt($encrypted);

        self::assertSame('secret data', $decrypted);
    }

    #[Test]
    public function empty_string_round_trip(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $encrypted = $det->encrypt('');
        self::assertSame('', $det->decrypt($encrypted));
    }

    #[Test]
    public function aes128_cbc_works(): void
    {
        $key = Key::generate(Cipher::Aes128Cbc);
        $det = new DeterministicEncrypter($key, Cipher::Aes128Cbc);

        $encrypted = $det->encrypt('test');
        self::assertSame('test', $det->decrypt($encrypted));
    }

    #[Test]
    public function xchacha20_throws(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Deterministic encryption requires OpenSSL');

        new DeterministicEncrypter($key, Cipher::XChaCha20Poly1305);
    }

    #[Test]
    public function tampered_mac_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $encrypted = $det->encrypt('genuine');

        // Decode, tamper MAC, re-encode
        $json = json_decode(base64_decode($encrypted, true), true);
        $json['mac'] = hash('sha256', 'tampered');
        $tampered = base64_encode(json_encode($json));

        $this->expectException(DecryptionException::class);
        $det->decrypt($tampered);
    }

    #[Test]
    public function invalid_payload_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $det = new DeterministicEncrypter($key);

        $this->expectException(DecryptionException::class);
        $det->decrypt('not-valid-base64!!!');
    }

    #[Test]
    public function different_key_produces_different_output(): void
    {
        $key1 = Key::generate(Cipher::Aes256Cbc);
        $key2 = Key::generate(Cipher::Aes256Cbc);

        $det1 = new DeterministicEncrypter($key1);
        $det2 = new DeterministicEncrypter($key2);

        $a = $det1->encrypt('same input');
        $b = $det2->encrypt('same input');

        self::assertNotSame($a, $b);
    }
}
