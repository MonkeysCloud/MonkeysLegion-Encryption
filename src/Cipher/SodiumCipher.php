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
 * XChaCha20-Poly1305 cipher implementation using libsodium.
 */
final class SodiumCipher
{
    /**
     * Encrypt data with XChaCha20-Poly1305.
     *
     * @return array{iv: string, value: string, mac: string, tag: string, cipher: string}
     */
    public static function encrypt(string $data, string $key): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $data,
            '', // additional data
            $nonce,
            $key,
        );

        return [
            'iv'     => base64_encode($nonce),
            'value'  => base64_encode($ciphertext),
            'mac'    => '',
            'tag'    => '',
            'cipher' => Cipher::XChaCha20Poly1305->value,
        ];
    }

    /**
     * Decrypt data with XChaCha20-Poly1305.
     *
     * @param array{iv: string, value: string, mac: string, tag: string, cipher: string} $payload
     */
    public static function decrypt(array $payload, string $key): string
    {
        $nonce = base64_decode($payload['iv'], true);
        $ciphertext = base64_decode($payload['value'], true);

        if ($nonce === false || $ciphertext === false) {
            throw DecryptionException::invalidPayload();
        }

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                '', // additional data
                $nonce,
                $key,
            );
        } catch (\SodiumException $e) {
            throw DecryptionException::macMismatch();
        }

        if ($plaintext === false) {
            throw DecryptionException::macMismatch();
        }

        return $plaintext;
    }
}
