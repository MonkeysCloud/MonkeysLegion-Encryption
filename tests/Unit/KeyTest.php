<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\KeyException;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class KeyTest extends TestCase
{
    // ── Generation ────────────────────────────────────────────

    #[Test]
    #[DataProvider('cipherProvider')]
    public function generate_correct_length(Cipher $cipher): void
    {
        $key = Key::generate($cipher);

        self::assertSame($cipher->keyLength(), $key->length);
        self::assertTrue($key->isValid);
        self::assertSame($cipher, $key->cipher);
    }

    #[Test]
    public function generate_default_is_aes256gcm(): void
    {
        $key = Key::generate();

        self::assertSame(Cipher::Aes256Gcm, $key->cipher);
        self::assertSame(32, $key->length);
    }

    // ── Factories ─────────────────────────────────────────────

    #[Test]
    public function from_base64_round_trip(): void
    {
        $key = Key::generate();
        $encoded = $key->base64();

        $restored = Key::fromBase64($encoded);

        self::assertSame($key->material(), $restored->material());
    }

    #[Test]
    public function from_base64_strips_prefix(): void
    {
        $key = Key::generate();
        $encoded = $key->base64(); // "base64:..."

        self::assertTrue(str_starts_with($encoded, 'base64:'));

        $restored = Key::fromBase64($encoded);
        self::assertSame($key->material(), $restored->material());
    }

    #[Test]
    public function from_base64_without_prefix(): void
    {
        $raw = random_bytes(32);
        $encoded = base64_encode($raw);

        $key = Key::fromBase64($encoded);
        self::assertSame($raw, $key->material());
    }

    #[Test]
    public function from_raw_valid(): void
    {
        $material = random_bytes(32);
        $key = Key::fromRaw($material);

        self::assertSame($material, $key->material());
        self::assertTrue($key->isValid);
    }

    #[Test]
    public function from_raw_invalid_length_throws(): void
    {
        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('Invalid key length');

        Key::fromRaw(random_bytes(7), Cipher::Aes256Gcm);
    }

    #[Test]
    public function from_raw_empty_throws(): void
    {
        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('must not be empty');

        Key::fromRaw('');
    }

    #[Test]
    public function from_base64_invalid_throws(): void
    {
        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('not valid base64');

        Key::fromBase64('!!!not-valid!!!');
    }

    // ── Output formats ────────────────────────────────────────

    #[Test]
    public function hex_output(): void
    {
        $key = Key::generate();

        self::assertMatchesRegularExpression('/^[a-f0-9]+$/', $key->hex());
        self::assertSame(64, strlen($key->hex())); // 32 bytes = 64 hex chars
    }

    #[Test]
    public function base64_output_has_prefix(): void
    {
        $key = Key::generate();

        self::assertTrue(str_starts_with($key->base64(), 'base64:'));
    }

    // ── Memory safety ─────────────────────────────────────────

    #[Test]
    public function destroy_wipes_material(): void
    {
        $key = Key::generate();
        self::assertFalse($key->isDestroyed());

        $key->destroy();

        self::assertTrue($key->isDestroyed());
    }

    #[Test]
    public function access_after_destroy_throws(): void
    {
        $key = Key::generate();
        $key->destroy();

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('destroyed');

        $key->material();
    }

    #[Test]
    public function double_destroy_is_safe(): void
    {
        $key = Key::generate();
        $key->destroy();
        $key->destroy(); // Should not throw

        self::assertTrue($key->isDestroyed());
    }

    // ── Serialization guards ──────────────────────────────────

    #[Test]
    public function serialize_throws(): void
    {
        $key = Key::generate();

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('serialized');

        serialize($key);
    }

    #[Test]
    public function to_string_throws(): void
    {
        $key = Key::generate();

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('converted to string');

        (string) $key;
    }

    // ── Property hooks ────────────────────────────────────────

    #[Test]
    public function length_property_hook(): void
    {
        $key = Key::generate(Cipher::Aes128Gcm);
        self::assertSame(16, $key->length);

        $key256 = Key::generate(Cipher::Aes256Gcm);
        self::assertSame(32, $key256->length);
    }

    #[Test]
    public function is_valid_property_hook(): void
    {
        $key = Key::generate();
        self::assertTrue($key->isValid);
    }

    /**
     * @return iterable<string, array{Cipher}>
     */
    public static function cipherProvider(): iterable
    {
        foreach (Cipher::cases() as $cipher) {
            yield $cipher->label() => [$cipher];
        }
    }
}
