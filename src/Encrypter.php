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
use MonkeysLegion\Encryption\Contracts\EncrypterInterface;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Exception\DecryptionException;
use MonkeysLegion\Encryption\Exception\EncryptionException;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyChain;

/**
 * Main encrypter — delegates to OpenSSL or Sodium cipher based on cipher enum.
 *
 * Supports key rotation via KeyChain.
 * Uses PHP 8.4 property hooks.
 */
final class Encrypter implements EncrypterInterface
{
    private readonly KeyChain $keyChain;

    /**
     * The active cipher algorithm.
     */
    public Cipher $cipher {
        get => $this->activeCipher;
    }

    /**
     * Whether key rotation is active.
     */
    public bool $usingRotation {
        get => $this->keyChain->hasPreviousKeys;
    }

    private readonly Cipher $activeCipher;

    /**
     * @param Key|KeyChain $key    The key or key chain.
     * @param Cipher       $cipher The cipher to use.
     */
    public function __construct(
        Key|KeyChain $key,
        Cipher $cipher = Cipher::Aes256Gcm,
    ) {
        $this->keyChain = $key instanceof KeyChain ? $key : KeyChain::single($key);
        $this->activeCipher = $cipher;
    }

    // ── EncrypterInterface ─────────────────────────────────────

    public function encrypt(string $value, bool $serialize = true): string
    {
        $data = $serialize ? serialize($value) : $value;

        return $this->doEncrypt($data);
    }

    public function decrypt(string $payload, bool $unserialize = true): string
    {
        $decrypted = $this->doDecrypt($payload);

        if ($unserialize) {
            $result = @unserialize($decrypted);

            if ($result === false && $decrypted !== serialize(false)) {
                return $decrypted;
            }

            return is_string($result) ? $result : $decrypted;
        }

        return $decrypted;
    }

    public function encryptString(string $value): string
    {
        return $this->encrypt($value, false);
    }

    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    public function getKey(): Key
    {
        return $this->keyChain->current();
    }

    // ── Extended API ───────────────────────────────────────────

    /**
     * Encrypt and return a structured result.
     */
    public function encryptResult(string $value): EncryptionResult
    {
        return new EncryptionResult(
            payload: $this->encryptString($value),
            cipher: $this->activeCipher,
        );
    }

    // ── Internal ───────────────────────────────────────────────

    private function doEncrypt(string $data): string
    {
        $key = $this->keyChain->current()->material();

        $payload = $this->activeCipher->requiresSodium()
            ? SodiumCipher::encrypt($data, $key)
            : OpenSslCipher::encrypt($data, $key, $this->activeCipher);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return base64_encode($json);
    }

    private function doDecrypt(string $payload): string
    {
        // Try with key chain (current + previous keys)
        return $this->keyChain->tryDecrypt(
            fn(Key $key): string => $this->decryptWithKey($payload, $key),
        );
    }

    private function decryptWithKey(string $payload, Key $key): string
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

        $cipher = Cipher::tryFrom($data['cipher']);

        if ($cipher === null) {
            throw DecryptionException::unsupportedCipher($data['cipher']);
        }

        /** @var array{iv: string, value: string, mac: string, tag: string, cipher: string} $validated */
        $validated = [
            'iv'     => $data['iv'],
            'value'  => $data['value'],
            'mac'    => is_string($data['mac'] ?? null) ? $data['mac'] : '',
            'tag'    => is_string($data['tag'] ?? null) ? $data['tag'] : '',
            'cipher' => $data['cipher'],
        ];

        return $cipher->requiresSodium()
            ? SodiumCipher::decrypt($validated, $key->material())
            : OpenSslCipher::decrypt($validated, $key->material(), $cipher);
    }
}
