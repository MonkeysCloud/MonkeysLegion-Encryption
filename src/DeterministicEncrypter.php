<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption;

use MonkeysLegion\Encryption\Cipher\OpenSslCipher;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Key\Key;

/**
 * Deterministic encrypter — same plaintext → same ciphertext.
 *
 * Uses HMAC-derived IV (SIV-like construction) for searchable encrypted fields.
 *
 * WARNING: Less secure than random IV encryption. Use ONLY for indexed/searchable
 * database fields where you need to query encrypted values.
 */
final class DeterministicEncrypter
{
    private readonly Cipher $cipher;

    /**
     * @param Key    $key    The encryption key.
     * @param Cipher $cipher Must be a non-AEAD cipher (CBC recommended).
     */
    public function __construct(
        private readonly Key $key,
        Cipher $cipher = Cipher::Aes256Cbc,
    ) {
        if ($cipher->requiresSodium()) {
            throw new EncryptionException(
                'Deterministic encryption requires OpenSSL cipher (CBC). XChaCha20 is not supported.',
            );
        }

        $this->cipher = $cipher;
    }

    /**
     * Encrypt a value deterministically (same input → same output).
     */
    public function encrypt(string $value): string
    {
        $iv = $this->deriveIv($value);

        $encrypted = openssl_encrypt(
            $value,
            $this->cipher->value,
            $this->key->material(),
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($encrypted === false) {
            throw new EncryptionException('Deterministic encryption failed.');
        }

        $encodedValue = base64_encode($encrypted);
        $encodedIv = base64_encode($iv);
        $mac = hash_hmac('sha256', $encodedIv . $encodedValue, $this->key->material());

        $payload = json_encode([
            'iv'     => $encodedIv,
            'value'  => $encodedValue,
            'mac'    => $mac,
            'tag'    => '',
            'cipher' => $this->cipher->value,
        ], JSON_THROW_ON_ERROR);

        return base64_encode($payload);
    }

    /**
     * Decrypt a deterministically encrypted value.
     */
    public function decrypt(string $payload): string
    {
        $json = base64_decode($payload, true);

        if ($json === false) {
            throw DecryptionException::invalidPayload();
        }

        $data = json_decode($json, true);

        if (
            !is_array($data)
            || !is_string($data['iv'] ?? null)
            || !is_string($data['value'] ?? null)
            || !is_string($data['mac'] ?? null)
        ) {
            throw DecryptionException::invalidPayload();
        }

        // Verify MAC
        $expectedMac = hash_hmac('sha256', $data['iv'] . $data['value'], $this->key->material());

        if (!hash_equals($expectedMac, $data['mac'])) {
            throw DecryptionException::macMismatch();
        }

        $iv = base64_decode($data['iv'], true);
        $value = base64_decode($data['value'], true);

        if ($iv === false || $value === false) {
            throw DecryptionException::invalidPayload();
        }

        $decrypted = openssl_decrypt(
            $value,
            $this->cipher->value,
            $this->key->material(),
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($decrypted === false) {
            throw DecryptionException::invalidPayload();
        }

        return $decrypted;
    }

    /**
     * Derive a deterministic IV from the plaintext using HMAC.
     * This ensures the same plaintext always produces the same ciphertext.
     */
    private function deriveIv(string $plaintext): string
    {
        $hmac = hash_hmac('sha256', $plaintext, $this->key->material(), true);

        return substr($hmac, 0, $this->cipher->ivLength());
    }
}
