<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Testing\FakeEncrypter;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FakeEncrypterTest extends TestCase
{
    #[Test]
    public function encrypt_decrypt_string_round_trip(): void
    {
        $fake = new FakeEncrypter(Key::generate());

        $encrypted = $fake->encryptString('hello');
        $decrypted = $fake->decryptString($encrypted);

        self::assertSame('hello', $decrypted);
    }

    #[Test]
    public function encrypt_decrypt_with_serialization(): void
    {
        $fake = new FakeEncrypter(Key::generate());

        $encrypted = $fake->encrypt('test', true);
        $decrypted = $fake->decrypt($encrypted, true);

        self::assertSame('test', $decrypted);
    }

    #[Test]
    public function encrypt_count(): void
    {
        $fake = new FakeEncrypter(Key::generate());

        self::assertSame(0, $fake->encryptCount());

        $fake->encryptString('a');
        $fake->encryptString('b');

        self::assertSame(2, $fake->encryptCount());
    }

    #[Test]
    public function decrypt_count(): void
    {
        $fake = new FakeEncrypter(Key::generate());
        $encrypted = $fake->encryptString('test');

        $fake->decryptString($encrypted);
        $fake->decryptString($encrypted);

        self::assertSame(2, $fake->decryptCount());
    }

    #[Test]
    public function recorded_tracks_all_operations(): void
    {
        $fake = new FakeEncrypter(Key::generate());

        $encrypted = $fake->encryptString('a');
        $fake->decryptString($encrypted);

        $records = $fake->recorded();
        self::assertCount(2, $records);
        self::assertSame('encrypt', $records[0]['operation']);
        self::assertSame('decrypt', $records[1]['operation']);
    }

    #[Test]
    public function assert_nothing_encrypted_passes_when_clean(): void
    {
        $fake = new FakeEncrypter(Key::generate());

        // Should not throw
        $fake->assertNothingEncrypted();
        self::assertTrue(true); // Assertion passed
    }

    #[Test]
    public function assert_nothing_encrypted_throws_when_used(): void
    {
        $fake = new FakeEncrypter(Key::generate());
        $fake->encryptString('something');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Expected no encryption operations');

        $fake->assertNothingEncrypted();
    }

    #[Test]
    public function get_key_returns_provided_key(): void
    {
        $key = Key::generate();
        $fake = new FakeEncrypter($key);

        self::assertSame($key, $fake->getKey());
    }
}
