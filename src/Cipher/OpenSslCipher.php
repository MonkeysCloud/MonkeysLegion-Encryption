<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Cipher;

use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;

/**
 * AES cipher implementation using OpenSSL (CBC and GCM modes).
 */
final class OpenSslCipher
{
    /**
     * Encrypt data with the given cipher and key.
     *
     * @return array{iv: string, value: string, mac: string, tag: string, cipher: string}
     */
    public static function encrypt(string $data, string $key, Cipher $cipher): array
    {
        $iv = random_bytes(max(1, $cipher->ivLength()));

        if ($cipher->isAead()) {
            return self::encryptGcm($data, $key, $iv, $cipher);
        }

        return self::encryptCbc($data, $key, $iv, $cipher);
    }

    /**
     * Decrypt data.
     *
     * @param array{iv: string, value: string, mac: string, tag: string, cipher: string} $payload
     */
    public static function decrypt(array $payload, string $key, Cipher $cipher): string
    {
        if ($cipher->isAead()) {
            return self::decryptGcm($payload, $key, $cipher);
        }

        return self::decryptCbc($payload, $key, $cipher);
    }

    // ── GCM (AEAD) ────────────────────────────────────────────

    /**
     * @return array{iv: string, value: string, mac: string, tag: string, cipher: string}
     */
    private static function encryptGcm(string $data, string $key, string $iv, Cipher $cipher): array
    {
        $tag = '';
        $encrypted = openssl_encrypt(
            $data,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16,
        );

        if ($encrypted === false) {
            throw new EncryptionException('OpenSSL GCM encryption failed: ' . (openssl_error_string() ?: 'unknown'));
        }

        return [
            'iv'     => base64_encode($iv),
            'value'  => base64_encode($encrypted),
            'mac'    => '',
            'tag'    => base64_encode($tag ?? ''),
            'cipher' => $cipher->value,
        ];
    }

    /**
     * @param array{iv: string, value: string, mac: string, tag: string, cipher: string} $payload
     */
    private static function decryptGcm(array $payload, string $key, Cipher $cipher): string
    {
        $iv = base64_decode($payload['iv'], true);
        $value = base64_decode($payload['value'], true);
        $tag = base64_decode($payload['tag'], true);

        if ($iv === false || $value === false || $tag === false) {
            throw DecryptionException::invalidPayload();
        }

        $decrypted = openssl_decrypt(
            $value,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($decrypted === false) {
            throw DecryptionException::macMismatch();
        }

        return $decrypted;
    }

    // ── CBC (with HMAC) ────────────────────────────────────────

    /**
     * @return array{iv: string, value: string, mac: string, tag: string, cipher: string}
     */
    private static function encryptCbc(string $data, string $key, string $iv, Cipher $cipher): array
    {
        $encrypted = openssl_encrypt(
            $data,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($encrypted === false) {
            throw new EncryptionException('OpenSSL CBC encryption failed: ' . openssl_error_string());
        }

        $encodedValue = base64_encode($encrypted);
        $encodedIv = base64_encode($iv);

        // HMAC over iv + value for tamper detection
        $mac = hash_hmac('sha256', $encodedIv . $encodedValue, $key);

        return [
            'iv'     => $encodedIv,
            'value'  => $encodedValue,
            'mac'    => $mac,
            'tag'    => '',
            'cipher' => $cipher->value,
        ];
    }

    /**
     * @param array{iv: string, value: string, mac: string, tag: string, cipher: string} $payload
     */
    private static function decryptCbc(array $payload, string $key, Cipher $cipher): string
    {
        // Verify MAC
        $expectedMac = hash_hmac('sha256', $payload['iv'] . $payload['value'], $key);

        if (!hash_equals($expectedMac, $payload['mac'])) {
            throw DecryptionException::macMismatch();
        }

        $iv = base64_decode($payload['iv'], true);
        $value = base64_decode($payload['value'], true);

        if ($iv === false || $value === false) {
            throw DecryptionException::invalidPayload();
        }

        $decrypted = openssl_decrypt(
            $value,
            $cipher->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($decrypted === false) {
            throw DecryptionException::invalidPayload();
        }

        return $decrypted;
    }
}
