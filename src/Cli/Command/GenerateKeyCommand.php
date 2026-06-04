<?php

declare(strict_types=1);

/**
 * MonkeysLegion Framework — Encryption Package
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */

namespace MonkeysLegion\Encryption\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\Cli\Command\MakerHelpers;
use MonkeysLegion\Encryption\Enum\Cipher;
use MonkeysLegion\Encryption\Key\KeyGenerator;

/**
 * CLI command: encryption:generate-key
 *
 * Generate a cryptographically secure encryption key.
 */
#[CommandAttr('encryption:generate-key', 'Generate a new encryption key')]
final class GenerateKeyCommand extends Command
{
    use MakerHelpers;

    public const string NAME = 'encryption:generate-key';
    public const string DESCRIPTION = 'Generate a new encryption key';

    public function handle(): int
    {
        $help = $this->option('help', false);
        if ($help) {
            $this->line(self::help());
            return 0;
        }
        $cipherValue = $this->option('cipher', 'aes-256-gcm');
        $cipher = Cipher::from($cipherValue);
        $format = $this->option('format', 'base64');

        $key = match ($format) {
            'hex'    => KeyGenerator::generateHex($cipher),
            'raw'    => KeyGenerator::generateRaw($cipher),
            default  => KeyGenerator::generateBase64($cipher),
        };

        $this->printColored("Generated Key: ", 'green');
        $this->line($key);

        return 0;
    }

    /**
     * Get usage help text.
     */
    private static function help(): string
    {
        return <<<HELP
        Usage: encryption:generate-key [options]

        Options:
          --cipher=CIPHER   Cipher algorithm (default: aes-256-gcm)
                            Options: aes-128-cbc, aes-256-cbc, aes-128-gcm, aes-256-gcm, xchacha20-poly1305
          --format=FORMAT   Output format (default: base64)
                            Options: base64, hex, raw

        Examples:
          encryption:generate-key
          encryption:generate-key --cipher=xchacha20-poly1305
          encryption:generate-key --format=hex
        HELP;
    }
}
