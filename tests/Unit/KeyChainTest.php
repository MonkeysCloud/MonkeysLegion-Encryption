<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyChain;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class KeyChainTest extends TestCase
{
    #[Test]
    public function single_key_chain(): void
    {
        $key = Key::generate();
        $chain = KeyChain::single($key);

        self::assertSame($key, $chain->current());
        self::assertFalse($chain->hasPreviousKeys);
        self::assertSame(1, $chain->keyCount);
        self::assertSame([], $chain->previous());
    }

    #[Test]
    public function rotation_chain(): void
    {
        $current = Key::generate();
        $old1 = Key::generate();
        $old2 = Key::generate();

        $chain = KeyChain::withRotation($current, [$old1, $old2]);

        self::assertSame($current, $chain->current());
        self::assertTrue($chain->hasPreviousKeys);
        self::assertSame(3, $chain->keyCount);
        self::assertCount(2, $chain->previous());
    }

    #[Test]
    public function all_returns_current_plus_previous(): void
    {
        $current = Key::generate();
        $old = Key::generate();
        $chain = KeyChain::withRotation($current, [$old]);

        $all = $chain->all();

        self::assertCount(2, $all);
        self::assertSame($current, $all[0]);
        self::assertSame($old, $all[1]);
    }

    #[Test]
    public function try_decrypt_succeeds_on_first_key(): void
    {
        $key = Key::generate();
        $chain = KeyChain::single($key);

        $result = $chain->tryDecrypt(fn(Key $k): string => 'decrypted');

        self::assertSame('decrypted', $result);
    }

    #[Test]
    public function try_decrypt_falls_back_to_previous_key(): void
    {
        $current = Key::generate();
        $old = Key::generate();
        $chain = KeyChain::withRotation($current, [$old]);

        $callCount = 0;
        $result = $chain->tryDecrypt(function (Key $k) use ($old, &$callCount): string {
            $callCount++;
            if ($k !== $old) {
                throw new \RuntimeException('Wrong key');
            }
            return 'decrypted-with-old';
        });

        self::assertSame('decrypted-with-old', $result);
        self::assertSame(2, $callCount);
    }

    #[Test]
    public function try_decrypt_throws_when_all_fail(): void
    {
        $chain = KeyChain::withRotation(Key::generate(), [Key::generate()]);

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Unable to decrypt');

        $chain->tryDecrypt(fn(Key $k) => throw new \RuntimeException('fail'));
    }

    #[Test]
    public function property_hooks(): void
    {
        $single = KeyChain::single(Key::generate());
        self::assertFalse($single->hasPreviousKeys);
        self::assertSame(1, $single->keyCount);

        $rotation = KeyChain::withRotation(Key::generate(), [Key::generate(), Key::generate()]);
        self::assertTrue($rotation->hasPreviousKeys);
        self::assertSame(3, $rotation->keyCount);
    }
}
