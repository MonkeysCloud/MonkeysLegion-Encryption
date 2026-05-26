<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Hash\HashInfo;
use MonkeysLegion\Encryption\Testing\FakeHasher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FakeHasherTest extends TestCase
{
    #[Test]
    public function hash_verify_round_trip(): void
    {
        $hasher = new FakeHasher();
        $hash = $hasher->hash('my-password');

        self::assertTrue($hasher->verify('my-password', $hash));
        self::assertFalse($hasher->verify('wrong', $hash));
    }

    #[Test]
    public function hash_has_prefix(): void
    {
        $hasher = new FakeHasher();
        $hash = $hasher->hash('test');

        self::assertTrue(str_starts_with($hash, 'fakehash:'));
        self::assertSame('fakehash:test', $hash);
    }

    #[Test]
    public function needs_rehash_returns_true_for_non_fake(): void
    {
        $hasher = new FakeHasher();

        self::assertTrue($hasher->needsRehash('$2y$10$real-hash'));
    }

    #[Test]
    public function needs_rehash_returns_false_for_fake(): void
    {
        $hasher = new FakeHasher();
        $hash = $hasher->hash('test');

        self::assertFalse($hasher->needsRehash($hash));
    }

    #[Test]
    public function info_returns_fake_hash_info(): void
    {
        $hasher = new FakeHasher();
        $hash = $hasher->hash('test');
        $info = $hasher->info($hash);

        self::assertInstanceOf(HashInfo::class, $info);
        self::assertSame('fake', $info->algorithmName);
        self::assertFalse($info->isBcrypt);
        self::assertFalse($info->isArgon2);
    }
}
