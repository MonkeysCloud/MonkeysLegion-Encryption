<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Crypt;
use MonkeysLegion\Encryption\Encrypter;
use MonkeysLegion\Encryption\Key\Key;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use RuntimeException;

final class CryptTest extends TestCase
{
    protected function tearDown(): void
    {
        Crypt::reset();
    }

    #[Test]
    public function encrypt_decrypt_round_trip(): void
    {
        $key = Key::generate();
        Crypt::setInstance(new Encrypter($key));

        $encrypted = Crypt::encryptString('hello');
        $decrypted = Crypt::decryptString($encrypted);

        self::assertSame('hello', $decrypted);
    }

    #[Test]
    public function encrypt_with_serialization(): void
    {
        $key = Key::generate();
        Crypt::setInstance(new Encrypter($key));

        $encrypted = Crypt::encrypt('serialized');
        $decrypted = Crypt::decrypt($encrypted);

        self::assertSame('serialized', $decrypted);
    }

    #[Test]
    public function without_serialization(): void
    {
        $key = Key::generate();
        Crypt::setInstance(new Encrypter($key));

        $encrypted = Crypt::encrypt('raw', false);
        $decrypted = Crypt::decrypt($encrypted, false);

        self::assertSame('raw', $decrypted);
    }

    #[Test]
    public function get_key(): void
    {
        $key = Key::generate();
        Crypt::setInstance(new Encrypter($key));

        self::assertSame($key, Crypt::getKey());
    }

    #[Test]
    public function get_instance(): void
    {
        $key = Key::generate();
        $enc = new Encrypter($key);
        Crypt::setInstance($enc);

        self::assertSame($enc, Crypt::getInstance());
    }

    #[Test]
    public function uninitialized_throws(): void
    {
        Crypt::reset();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Crypt has not been initialized');

        Crypt::encryptString('test');
    }

    #[Test]
    public function get_instance_uninitialized_throws(): void
    {
        Crypt::reset();

        $this->expectException(RuntimeException::class);

        Crypt::getInstance();
    }

    #[Test]
    public function reset_clears_instance(): void
    {
        $key = Key::generate();
        Crypt::setInstance(new Encrypter($key));

        // Works before reset
        Crypt::encryptString('test');

        Crypt::reset();

        $this->expectException(RuntimeException::class);
        Crypt::encryptString('test');
    }

    #[Test]
    public function replace_instance(): void
    {
        $key1 = Key::generate();
        $key2 = Key::generate();

        Crypt::setInstance(new Encrypter($key1));
        $encrypted1 = Crypt::encryptString('data');

        Crypt::setInstance(new Encrypter($key2));
        $encrypted2 = Crypt::encryptString('data');

        // Different keys → different ciphertext
        self::assertNotSame($encrypted1, $encrypted2);

        // Can decrypt with current instance
        self::assertSame('data', Crypt::decryptString($encrypted2));
    }
}
