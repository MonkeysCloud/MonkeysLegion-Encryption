<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Cipher\OpenSslCipher;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class OpenSslCipherTest extends TestCase
{
    #[Test]
    #[DataProvider('opensslCipherProvider')]
    public function encrypt_decrypt_round_trip(Cipher $cipher): void
    {
        $key = Key::generate($cipher);
        $payload = OpenSslCipher::encrypt('hello world', $key->material(), $cipher);

        self::assertArrayHasKey('iv', $payload);
        self::assertArrayHasKey('value', $payload);
        self::assertArrayHasKey('cipher', $payload);
        self::assertSame($cipher->value, $payload['cipher']);

        $decrypted = OpenSslCipher::decrypt($payload, $key->material(), $cipher);
        self::assertSame('hello world', $decrypted);
    }

    #[Test]
    public function gcm_tampered_tag_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Gcm);
        $payload = OpenSslCipher::encrypt('sensitive', $key->material(), Cipher::Aes256Gcm);

        // Tamper with the tag
        $payload['tag'] = base64_encode(random_bytes(16));

        $this->expectException(DecryptionException::class);
        OpenSslCipher::decrypt($payload, $key->material(), Cipher::Aes256Gcm);
    }

    #[Test]
    public function cbc_tampered_mac_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $payload = OpenSslCipher::encrypt('sensitive', $key->material(), Cipher::Aes256Cbc);

        // Tamper with the MAC
        $payload['mac'] = hash('sha256', 'tampered');

        $this->expectException(DecryptionException::class);
        OpenSslCipher::decrypt($payload, $key->material(), Cipher::Aes256Cbc);
    }

    #[Test]
    public function cbc_tampered_value_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $payload = OpenSslCipher::encrypt('sensitive', $key->material(), Cipher::Aes256Cbc);

        // Tamper with the value
        $payload['value'] = base64_encode('garbage');

        $this->expectException(DecryptionException::class);
        OpenSslCipher::decrypt($payload, $key->material(), Cipher::Aes256Cbc);
    }

    #[Test]
    public function gcm_empty_string_round_trip(): void
    {
        $key = Key::generate(Cipher::Aes256Gcm);
        $payload = OpenSslCipher::encrypt('', $key->material(), Cipher::Aes256Gcm);
        $decrypted = OpenSslCipher::decrypt($payload, $key->material(), Cipher::Aes256Gcm);

        self::assertSame('', $decrypted);
    }

    #[Test]
    public function cbc_has_non_empty_mac(): void
    {
        $key = Key::generate(Cipher::Aes256Cbc);
        $payload = OpenSslCipher::encrypt('test', $key->material(), Cipher::Aes256Cbc);

        self::assertNotEmpty($payload['mac']);
        self::assertEmpty($payload['tag']);
    }

    #[Test]
    public function gcm_has_non_empty_tag(): void
    {
        $key = Key::generate(Cipher::Aes256Gcm);
        $payload = OpenSslCipher::encrypt('test', $key->material(), Cipher::Aes256Gcm);

        self::assertNotEmpty($payload['tag']);
        self::assertEmpty($payload['mac']);
    }

    #[Test]
    public function invalid_base64_iv_throws(): void
    {
        $key = Key::generate(Cipher::Aes256Gcm);
        $payload = [
            'iv'     => '!!!invalid-base64!!!',
            'value'  => base64_encode('test'),
            'mac'    => '',
            'tag'    => base64_encode(random_bytes(16)),
            'cipher' => Cipher::Aes256Gcm->value,
        ];

        $this->expectException(DecryptionException::class);
        OpenSslCipher::decrypt($payload, $key->material(), Cipher::Aes256Gcm);
    }

    /**
     * @return iterable<string, array{Cipher}>
     */
    public static function opensslCipherProvider(): iterable
    {
        yield 'AES-128-CBC' => [Cipher::Aes128Cbc];
        yield 'AES-256-CBC' => [Cipher::Aes256Cbc];
        yield 'AES-128-GCM' => [Cipher::Aes128Gcm];
        yield 'AES-256-GCM' => [Cipher::Aes256Gcm];
    }
}
