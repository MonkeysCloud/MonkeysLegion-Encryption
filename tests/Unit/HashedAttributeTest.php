<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Attribute\Hashed;
use MonkeysLegion\Encryption\Enum\HashAlgorithm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use ReflectionClass;

final class HashedAttributeTest extends TestCase
{
    #[Test]
    public function default_values(): void
    {
        $attr = new Hashed();

        self::assertSame(HashAlgorithm::Argon2id, $attr->algorithm);
        self::assertSame([], $attr->options);
    }

    #[Test]
    public function custom_algorithm(): void
    {
        $attr = new Hashed(algorithm: HashAlgorithm::Bcrypt);

        self::assertSame(HashAlgorithm::Bcrypt, $attr->algorithm);
        self::assertTrue($attr->isBcrypt);
        self::assertFalse($attr->isArgon);
    }

    #[Test]
    public function argon_property_hook(): void
    {
        $attr = new Hashed(algorithm: HashAlgorithm::Argon2id);

        self::assertTrue($attr->isArgon);
        self::assertFalse($attr->isBcrypt);
    }

    #[Test]
    public function argon2i_is_argon(): void
    {
        $attr = new Hashed(algorithm: HashAlgorithm::Argon2i);

        self::assertTrue($attr->isArgon);
    }

    #[Test]
    public function custom_options(): void
    {
        $attr = new Hashed(
            algorithm: HashAlgorithm::Bcrypt,
            options: ['rounds' => 14],
        );

        self::assertSame(['rounds' => 14], $attr->options);
    }

    #[Test]
    public function used_on_class_property(): void
    {
        $testClass = new class {
            #[Hashed]
            public string $password = '';

            #[Hashed(algorithm: HashAlgorithm::Bcrypt, options: ['rounds' => 14])]
            public string $pin = '';
        };

        $ref = new ReflectionClass($testClass);

        // Password property
        $pwProp = $ref->getProperty('password');
        $pwAttrs = $pwProp->getAttributes(Hashed::class);
        self::assertCount(1, $pwAttrs);

        $pwHashed = $pwAttrs[0]->newInstance();
        self::assertSame(HashAlgorithm::Argon2id, $pwHashed->algorithm);

        // Pin property
        $pinProp = $ref->getProperty('pin');
        $pinAttrs = $pinProp->getAttributes(Hashed::class);
        self::assertCount(1, $pinAttrs);

        $pinHashed = $pinAttrs[0]->newInstance();
        self::assertSame(HashAlgorithm::Bcrypt, $pinHashed->algorithm);
        self::assertSame(['rounds' => 14], $pinHashed->options);
    }
}
