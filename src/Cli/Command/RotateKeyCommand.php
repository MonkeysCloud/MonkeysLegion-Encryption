<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Cli\Command;

use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Key\Key;
use MonkeysLegion\Encryption\Key\KeyGenerator;

/**
 * CLI command: encryption:rotate-key
 *
 * Generate a new encryption key and display rotation instructions.
 */
final class RotateKeyCommand
{
    public const string NAME = 'encryption:rotate-key';
    public const string DESCRIPTION = 'Generate a new key and show rotation steps';

    /**
     * Execute the command.
     *
     * @param array<string, string> $options
     *
     * @return array{new_key: string, instructions: string}
     */
    public function execute(array $options = []): array
    {
        $cipherValue = $options['cipher'] ?? 'aes-256-gcm';
        $cipher = Cipher::from($cipherValue);

        $newKey = KeyGenerator::generateBase64($cipher);

        $instructions = <<<INSTRUCTIONS
        Key Rotation Steps:
        
        1. Copy your CURRENT ENCRYPTION_KEY value
        2. Set ENCRYPTION_PREVIOUS_KEYS to include the old key:
           ENCRYPTION_PREVIOUS_KEYS="{old_key_here}"
        3. Set ENCRYPTION_KEY to the new key:
           ENCRYPTION_KEY="{$newKey}"
        4. Deploy the configuration change
        5. Existing data will be decrypted with the old key, new data encrypted with the new key
        6. Once all data is re-encrypted, remove old keys from ENCRYPTION_PREVIOUS_KEYS
        
        New Key: {$newKey}
        Cipher:  {$cipher->label()}
        INSTRUCTIONS;

        return [
            'new_key'      => $newKey,
            'instructions' => $instructions,
        ];
    }

    /**
     * Get usage help text.
     */
    public static function help(): string
    {
        return <<<HELP
        Usage: encryption:rotate-key [options]

        Options:
          --cipher=CIPHER   Cipher algorithm (default: aes-256-gcm)

        This command generates a new encryption key and provides step-by-step
        instructions for performing a zero-downtime key rotation using the
        ENCRYPTION_PREVIOUS_KEYS environment variable.
        HELP;
    }
}
