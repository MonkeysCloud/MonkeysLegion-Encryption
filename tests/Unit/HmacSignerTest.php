<?php

declare(strict_types=1);

namespace MonkeysLegion\Encryption\Tests\Unit;

use MonkeysLegion\Encryption\Enum\HmacAlgorithm;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Hmac\HmacResult;
use MonkeysLegion\Encryption\Hmac\HmacSigner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HmacSignerTest extends TestCase
{
    #[Test]
    public function sign_verify_round_trip(): void
    {
        $signer = new HmacSigner('my-secret');
        $mac = $signer->sign('hello');

        self::assertTrue($signer->verify('hello', $mac));
    }

    #[Test]
    public function tampered_data_fails_verify(): void
    {
        $signer = new HmacSigner('my-secret');
        $mac = $signer->sign('original');

        self::assertFalse($signer->verify('tampered', $mac));
    }

    #[Test]
    public function tampered_mac_fails_verify(): void
    {
        $signer = new HmacSigner('my-secret');
        $signer->sign('data');

        self::assertFalse($signer->verify('data', 'wrong-mac'));
    }

    #[Test]
    #[DataProvider('algorithmProvider')]
    public function different_algorithms(HmacAlgorithm $algo): void
    {
        $signer = new HmacSigner('secret');
        $mac = $signer->sign('test', null, $algo);

        // Hex length = output bytes * 2
        self::assertSame($algo->outputLength() * 2, strlen($mac));
        self::assertTrue($signer->verify('test', $mac, null, $algo));
    }

    #[Test]
    public function sign_raw_binary(): void
    {
        $signer = new HmacSigner('secret');
        $raw = $signer->signRaw('test');

        self::assertSame(32, strlen($raw)); // SHA-256 = 32 bytes
    }

    #[Test]
    public function sign_raw_sha512(): void
    {
        $signer = new HmacSigner('secret');
        $raw = $signer->signRaw('test', null, HmacAlgorithm::Sha512);

        self::assertSame(64, strlen($raw)); // SHA-512 = 64 bytes
    }

    #[Test]
    public function custom_key_overrides_default(): void
    {
        $signer = new HmacSigner('default-key');
        $macDefault = $signer->sign('data');
        $macCustom = $signer->sign('data', 'custom-key');

        self::assertNotSame($macDefault, $macCustom);
        self::assertTrue($signer->verify('data', $macCustom, 'custom-key'));
        self::assertFalse($signer->verify('data', $macCustom));
    }

    #[Test]
    public function empty_key_throws(): void
    {
        $signer = new HmacSigner('');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('HMAC key must not be empty');

        $signer->sign('data');
    }

    #[Test]
    public function empty_custom_key_throws(): void
    {
        $signer = new HmacSigner('default');

        $this->expectException(EncryptionException::class);

        $signer->sign('data', '');
    }

    // ── HmacResult ────────────────────────────────────────────

    #[Test]
    public function sign_result_structured(): void
    {
        $signer = new HmacSigner('secret');
        $result = $signer->signResult('payload');

        self::assertInstanceOf(HmacResult::class, $result);
        self::assertNotEmpty($result->mac);
        self::assertSame(HmacAlgorithm::Sha256, $result->algorithm);
        self::assertSame('payload', $result->data);
    }

    #[Test]
    public function hmac_result_verify(): void
    {
        $signer = new HmacSigner('secret');
        $result = $signer->signResult('data');

        self::assertTrue($result->verify($result->mac));
        self::assertFalse($result->verify('wrong'));
    }

    #[Test]
    public function hmac_result_length_hook(): void
    {
        $result = new HmacResult(
            mac: hash_hmac('sha256', 'test', 'key'),
            algorithm: HmacAlgorithm::Sha256,
            data: 'test',
        );

        self::assertSame(64, $result->length); // Hex string length
    }

    #[Test]
    public function hmac_result_to_string(): void
    {
        $signer = new HmacSigner('secret');
        $result = $signer->signResult('data');

        self::assertSame($result->mac, (string) $result);
    }

    /**
     * @return iterable<string, array{HmacAlgorithm}>
     */
    public static function algorithmProvider(): iterable
    {
        yield 'SHA-256' => [HmacAlgorithm::Sha256];
        yield 'SHA-384' => [HmacAlgorithm::Sha384];
        yield 'SHA-512' => [HmacAlgorithm::Sha512];
    }
}
