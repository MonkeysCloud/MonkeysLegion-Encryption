<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Provider;

use MonkeysLegion\Encryption\Contracts\EncrypterInterface;
use MonkeysLegion\Encryption\Contracts\HasherInterface;
use MonkeysLegion\Encryption\Contracts\HmacInterface;
use MonkeysLegion\Encryption\Encrypter;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Enum\HashAlgorithm;
use MonkeysLegion\Encryption\Hash\Hasher;
use MonkeysLegion\Encryption\Hmac\HmacSigner;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyChain;

/**
 * PSR-11 service provider for encryption services.
 */
final class EncryptionProvider
{
    /**
     * Register encryption services from config.
     *
     * @param array<string, mixed> $config
     *
     * @return array{encrypter: EncrypterInterface, hasher: HasherInterface, hmac: HmacInterface}
     */
    public static function register(array $config = []): array
    {
        $cipherValue = is_string($config['cipher'] ?? null) ? $config['cipher'] : 'aes-256-gcm';
        $cipher = Cipher::from($cipherValue);

        // Parse key
        $keyString = is_string($config['key'] ?? null) ? $config['key'] : '';
        $currentKey = Key::fromBase64($keyString, $cipher);

        // Parse previous keys for rotation
        $previousKeys = [];
        $previousKeysString = is_string($config['previous_keys'] ?? null) ? $config['previous_keys'] : '';

        if ($previousKeysString !== '') {
            foreach (explode(',', $previousKeysString) as $prevKeyStr) {
                $trimmed = trim($prevKeyStr);
                if ($trimmed !== '') {
                    $previousKeys[] = Key::fromBase64($trimmed, $cipher);
                }
            }
        }

        $keyChain = $previousKeys !== []
            ? KeyChain::withRotation($currentKey, $previousKeys)
            : KeyChain::single($currentKey);

        // Build services
        $encrypter = new Encrypter($keyChain, $cipher);

        /** @var array<string, mixed> $hashConfig */
        $hashConfig = is_array($config['hash'] ?? null) ? $config['hash'] : [];
        $hashAlgoValue = is_string($hashConfig['algorithm'] ?? null) ? $hashConfig['algorithm'] : 'argon2id';
        $hashAlgo = HashAlgorithm::from($hashAlgoValue);
        $hasher = new Hasher($hashAlgo, $hashConfig);

        /** @var array<string, mixed> $hmacConfig */
        $hmacConfig = is_array($config['hmac'] ?? null) ? $config['hmac'] : [];
        $hmacKey = is_string($hmacConfig['key'] ?? null) ? $hmacConfig['key'] : $keyString;
        $hmac = new HmacSigner($hmacKey);

        return [
            'encrypter' => $encrypter,
            'hasher'    => $hasher,
            'hmac'      => $hmac,
        ];
    }
}
