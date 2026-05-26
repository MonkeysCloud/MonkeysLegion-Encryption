<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Cipher\SodiumCipher;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SodiumCipherTest extends TestCase
{
    #[Test]
    public function encrypt_decrypt_round_trip(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $payload = SodiumCipher::encrypt('sodium test', $key->material());

        self::assertArrayHasKey('iv', $payload);
        self::assertArrayHasKey('value', $payload);
        self::assertSame(Cipher::XChaCha20Poly1305->value, $payload['cipher']);

        $decrypted = SodiumCipher::decrypt($payload, $key->material());
        self::assertSame('sodium test', $decrypted);
    }

    #[Test]
    public function tampered_ciphertext_throws(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $payload = SodiumCipher::encrypt('sensitive', $key->material());

        // Tamper with the ciphertext
        $raw = base64_decode($payload['value'], true);
        $raw[0] = chr(ord($raw[0]) ^ 0xFF);
        $payload['value'] = base64_encode($raw);

        $this->expectException(DecryptionException::class);
        SodiumCipher::decrypt($payload, $key->material());
    }

    #[Test]
    public function tampered_nonce_throws(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $payload = SodiumCipher::encrypt('test', $key->material());

        // Tamper with the nonce
        $payload['iv'] = base64_encode(random_bytes(24));

        $this->expectException(DecryptionException::class);
        SodiumCipher::decrypt($payload, $key->material());
    }

    #[Test]
    public function wrong_key_throws(): void
    {
        $key1 = Key::generate(Cipher::XChaCha20Poly1305);
        $key2 = Key::generate(Cipher::XChaCha20Poly1305);

        $payload = SodiumCipher::encrypt('secret', $key1->material());

        $this->expectException(DecryptionException::class);
        SodiumCipher::decrypt($payload, $key2->material());
    }

    #[Test]
    public function empty_string_round_trip(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $payload = SodiumCipher::encrypt('', $key->material());
        $decrypted = SodiumCipher::decrypt($payload, $key->material());

        self::assertSame('', $decrypted);
    }

    #[Test]
    public function large_data_round_trip(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $data = str_repeat('A', 1024 * 100); // 100KB
        $payload = SodiumCipher::encrypt($data, $key->material());

        self::assertSame($data, SodiumCipher::decrypt($payload, $key->material()));
    }

    #[Test]
    public function invalid_base64_throws(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $payload = [
            'iv'     => '!!!not-base64!!!',
            'value'  => base64_encode('test'),
            'mac'    => '',
            'tag'    => '',
            'cipher' => Cipher::XChaCha20Poly1305->value,
        ];

        $this->expectException(DecryptionException::class);
        SodiumCipher::decrypt($payload, $key->material());
    }
}
