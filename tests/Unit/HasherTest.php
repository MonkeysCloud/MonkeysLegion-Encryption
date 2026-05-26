<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Enum\HashAlgorithm;
use MonkeysLegion\Encryption\Hash\HashInfo;
use MonkeysLegion\Encryption\Hash\Hasher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HasherTest extends TestCase
{
    // ── Argon2id (default) ────────────────────────────────────

    #[Test]
    public function argon2id_hash_verify(): void
    {
        $hasher = new Hasher();
        $hash = $hasher->hash('my-password');

        self::assertTrue($hasher->verify('my-password', $hash));
        self::assertFalse($hasher->verify('wrong-password', $hash));
    }

    #[Test]
    public function argon2id_produces_argon2id_hash(): void
    {
        $hasher = new Hasher(HashAlgorithm::Argon2id);
        $hash = $hasher->hash('test');

        self::assertTrue(str_starts_with($hash, '$argon2id$'));
    }

    #[Test]
    public function argon2id_custom_options(): void
    {
        $hasher = new Hasher(HashAlgorithm::Argon2id, [
            'memory'  => 32768,
            'time'    => 2,
            'threads' => 1,
        ]);

        $hash = $hasher->hash('test');
        self::assertTrue($hasher->verify('test', $hash));
    }

    // ── Bcrypt ────────────────────────────────────────────────

    #[Test]
    public function bcrypt_hash_verify(): void
    {
        $hasher = new Hasher(HashAlgorithm::Bcrypt);
        $hash = $hasher->hash('password');

        self::assertTrue($hasher->verify('password', $hash));
        self::assertFalse($hasher->verify('wrong', $hash));
        self::assertTrue(str_starts_with($hash, '$2y$'));
    }

    #[Test]
    public function bcrypt_custom_rounds(): void
    {
        $hasher = new Hasher(HashAlgorithm::Bcrypt, ['rounds' => 10]);
        $hash = $hasher->hash('test');

        self::assertTrue(str_starts_with($hash, '$2y$10$'));
    }

    // ── needsRehash ───────────────────────────────────────────

    #[Test]
    public function needs_rehash_returns_false_for_current(): void
    {
        $hasher = new Hasher(HashAlgorithm::Bcrypt, ['rounds' => 10]);
        $hash = $hasher->hash('test');

        self::assertFalse($hasher->needsRehash($hash));
    }

    #[Test]
    public function needs_rehash_returns_true_for_different_config(): void
    {
        $oldHasher = new Hasher(HashAlgorithm::Bcrypt, ['rounds' => 10]);
        $hash = $oldHasher->hash('test');

        $newHasher = new Hasher(HashAlgorithm::Bcrypt, ['rounds' => 12]);

        self::assertTrue($newHasher->needsRehash($hash));
    }

    // ── HashInfo ──────────────────────────────────────────────

    #[Test]
    public function info_returns_hash_info(): void
    {
        $hasher = new Hasher(HashAlgorithm::Argon2id);
        $hash = $hasher->hash('test');
        $info = $hasher->info($hash);

        self::assertInstanceOf(HashInfo::class, $info);
        self::assertTrue($info->isArgon2);
        self::assertFalse($info->isBcrypt);
        self::assertTrue($info->isKnown);
    }

    #[Test]
    public function hash_info_bcrypt(): void
    {
        $hasher = new Hasher(HashAlgorithm::Bcrypt);
        $hash = $hasher->hash('test');
        $info = $hasher->info($hash);

        self::assertTrue($info->isBcrypt);
        self::assertFalse($info->isArgon2);
    }

    #[Test]
    public function hash_info_from_hash_static(): void
    {
        $hasher = new Hasher(HashAlgorithm::Bcrypt);
        $hash = $hasher->hash('test');

        $info = HashInfo::fromHash($hash);

        self::assertTrue($info->isBcrypt);
        self::assertIsArray($info->options);
    }

    #[Test]
    public function hash_info_unknown_algorithm(): void
    {
        $info = new HashInfo(algorithmName: 'unknown', options: []);

        self::assertFalse($info->isKnown);
        self::assertFalse($info->isBcrypt);
        self::assertFalse($info->isArgon2);
    }

    // ── Each hash is unique ───────────────────────────────────

    #[Test]
    public function same_password_different_hashes(): void
    {
        $hasher = new Hasher();
        $a = $hasher->hash('same');
        $b = $hasher->hash('same');

        self::assertNotSame($a, $b);
        self::assertTrue($hasher->verify('same', $a));
        self::assertTrue($hasher->verify('same', $b));
    }
}
