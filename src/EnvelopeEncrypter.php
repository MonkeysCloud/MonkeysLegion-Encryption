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
use MonkeysLegion\Encryption\Cipher\SodiumCipher;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Key\Key;

/**
 * Envelope encryption — per-record data keys wrapped by a master KEK.
 *
 * Pattern:
 * 1. Generate random data encryption key (DEK) per record
 * 2. Encrypt data with DEK
 * 3. Encrypt DEK with master key (KEK)
 * 4. Store wrapped DEK + encrypted data together
 */
final class EnvelopeEncrypter
{
    /**
     * @param Key    $masterKey The key encryption key (KEK).
     * @param Cipher $cipher    Cipher for both data and key encryption.
     */
    public function __construct(
        private readonly Key $masterKey,
        private readonly Cipher $cipher = Cipher::Aes256Gcm,
    ) {}

    /**
     * Encrypt data using envelope encryption.
     *
     * @return array{encrypted_data: string, wrapped_key: string, cipher: string}
     */
    public function encrypt(string $data): array
    {
        // Generate a random data encryption key (DEK)
        $dek = random_bytes(max(1, $this->cipher->keyLength()));

        // Encrypt the data with the DEK
        $encryptedData = $this->encryptWithKey($data, $dek);

        // Wrap (encrypt) the DEK with the master key (KEK)
        $wrappedKey = $this->encryptWithKey($dek, $this->masterKey->material());

        return [
            'encrypted_data' => $encryptedData,
            'wrapped_key'    => $wrappedKey,
            'cipher'         => $this->cipher->value,
        ];
    }

    /**
     * Decrypt envelope-encrypted data.
     *
     * @param array{encrypted_data: string, wrapped_key: string, cipher: string} $envelope
     */
    public function decrypt(array $envelope): string
    {
        // Unwrap the DEK using the master key
        $dek = $this->decryptWithKey($envelope['wrapped_key'], $this->masterKey->material());

        // Decrypt the data using the unwrapped DEK
        return $this->decryptWithKey($envelope['encrypted_data'], $dek);
    }

    /**
     * Re-wrap an existing envelope with a new master key.
     *
     * @param array{encrypted_data: string, wrapped_key: string, cipher: string} $envelope
     *
     * @return array{encrypted_data: string, wrapped_key: string, cipher: string}
     */
    public function rewrap(array $envelope, Key $newMasterKey): array
    {
        // Unwrap DEK with current master key
        $dek = $this->decryptWithKey($envelope['wrapped_key'], $this->masterKey->material());

        // Re-wrap DEK with new master key
        $newWrappedKey = $this->encryptWithKey($dek, $newMasterKey->material());

        // Wipe DEK from memory
        sodium_memzero($dek);

        return [
            'encrypted_data' => $envelope['encrypted_data'],
            'wrapped_key'    => $newWrappedKey,
            'cipher'         => $envelope['cipher'],
        ];
    }

    // ── Internal ───────────────────────────────────────────────

    private function encryptWithKey(string $data, string $key): string
    {
        $payload = $this->cipher->requiresSodium()
            ? SodiumCipher::encrypt($data, $key)
            : OpenSslCipher::encrypt($data, $key, $this->cipher);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return base64_encode($json);
    }

    private function decryptWithKey(string $payload, string $key): string
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
            || !is_string($data['cipher'] ?? null)
        ) {
            throw DecryptionException::invalidPayload();
        }

        /** @var array{iv: string, value: string, mac: string, tag: string, cipher: string} $validated */
        $validated = [
            'iv'     => $data['iv'],
            'value'  => $data['value'],
            'mac'    => is_string($data['mac'] ?? null) ? $data['mac'] : '',
            'tag'    => is_string($data['tag'] ?? null) ? $data['tag'] : '',
            'cipher' => $data['cipher'],
        ];

        return $this->cipher->requiresSodium()
            ? SodiumCipher::decrypt($validated, $key)
            : OpenSslCipher::decrypt($validated, $key, $this->cipher);
    }
}
