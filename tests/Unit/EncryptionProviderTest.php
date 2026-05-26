<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Contracts\EncrypterInterface;
use MonkeysLegion\Encryption\Contracts\HasherInterface;
use MonkeysLegion\Encryption\Contracts\HmacInterface;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Provider\EncryptionProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EncryptionProviderTest extends TestCase
{
    #[Test]
    public function register_returns_all_services(): void
    {
        $key = Key::generate();
        $services = EncryptionProvider::register([
            'cipher' => 'aes-256-gcm',
            'key'    => $key->base64(),
        ]);

        self::assertArrayHasKey('encrypter', $services);
        self::assertArrayHasKey('hasher', $services);
        self::assertArrayHasKey('hmac', $services);
        self::assertInstanceOf(EncrypterInterface::class, $services['encrypter']);
        self::assertInstanceOf(HasherInterface::class, $services['hasher']);
        self::assertInstanceOf(HmacInterface::class, $services['hmac']);
    }

    #[Test]
    public function register_encrypter_works(): void
    {
        $key = Key::generate();
        $services = EncryptionProvider::register([
            'key' => $key->base64(),
        ]);

        $enc = $services['encrypter'];
        $encrypted = $enc->encryptString('test');

        self::assertSame('test', $enc->decryptString($encrypted));
    }

    #[Test]
    public function register_with_rotation(): void
    {
        $currentKey = Key::generate();
        $oldKey = Key::generate();

        $services = EncryptionProvider::register([
            'key'           => $currentKey->base64(),
            'previous_keys' => $oldKey->base64(),
        ]);

        // Should be able to decrypt data from old key
        $oldEnc = new \MonkeysLegion\Encryption\Encrypter($oldKey);
        $encrypted = $oldEnc->encryptString('old-data');

        self::assertSame('old-data', $services['encrypter']->decryptString($encrypted));
    }

    #[Test]
    public function register_with_xchacha20(): void
    {
        $key = Key::generate(Cipher::XChaCha20Poly1305);
        $services = EncryptionProvider::register([
            'cipher' => 'xchacha20-poly1305',
            'key'    => $key->base64(),
        ]);

        $encrypted = $services['encrypter']->encryptString('sodium');
        self::assertSame('sodium', $services['encrypter']->decryptString($encrypted));
    }

    #[Test]
    public function register_hasher_with_custom_algorithm(): void
    {
        $key = Key::generate();
        $services = EncryptionProvider::register([
            'key'  => $key->base64(),
            'hash' => [
                'algorithm' => 'bcrypt',
                'rounds'    => 10,
            ],
        ]);

        $hash = $services['hasher']->hash('test');
        self::assertTrue(str_starts_with($hash, '$2y$10$'));
    }

    #[Test]
    public function register_hmac_with_custom_key(): void
    {
        $key = Key::generate();
        $services = EncryptionProvider::register([
            'key'  => $key->base64(),
            'hmac' => ['key' => 'custom-hmac-key'],
        ]);

        $mac = $services['hmac']->sign('data');
        self::assertTrue($services['hmac']->verify('data', $mac));
    }

    #[Test]
    public function register_defaults(): void
    {
        $key = Key::generate();
        $services = EncryptionProvider::register([
            'key' => $key->base64(),
        ]);

        // Hasher defaults to Argon2id
        $hash = $services['hasher']->hash('test');
        self::assertTrue(str_starts_with($hash, '$argon2id$'));
    }
}
