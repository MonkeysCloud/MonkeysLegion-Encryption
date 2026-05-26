# MonkeysLegion Encryption

Enterprise-grade **standalone cryptography** for the MonkeysLegion v2 framework.

AES-256-GCM • XChaCha20-Poly1305 • HMAC signing • key rotation • envelope encryption • deterministic encryption • HKDF key derivation • password hashing • PHP 8.4 property hooks • PHPStan Level 9

---

## Installation

```bash
composer require monkeyscloud/monkeyslegion-encryption
```

**Requirements:** PHP ≥ 8.4 · ext-openssl · ext-sodium · ext-mbstring

---

## Quick Start

```php
use MonkeysLegion\Encryption\Encrypter;
use MonkeysLegion\Encryption\Key\Key;

$key = Key::generate();
$encrypter = new Encrypter($key);

$encrypted = $encrypter->encryptString('sensitive data');
$decrypted = $encrypter->decryptString($encrypted); // "sensitive data"
```

---

## Supported Ciphers

```php
use MonkeysLegion\Encryption\Enum\Cipher;

Cipher::Aes128Cbc         // AES-128-CBC + HMAC-SHA256
Cipher::Aes256Cbc         // AES-256-CBC + HMAC-SHA256
Cipher::Aes128Gcm         // AES-128-GCM (AEAD)
Cipher::Aes256Gcm         // AES-256-GCM (AEAD) — DEFAULT
Cipher::XChaCha20Poly1305 // XChaCha20-Poly1305 (libsodium AEAD)
```

```php
// Use a specific cipher
$key = Key::generate(Cipher::XChaCha20Poly1305);
$encrypter = new Encrypter($key, Cipher::XChaCha20Poly1305);
```

---

## Key Generation

```php
use MonkeysLegion\Encryption\Key\{Key, KeyGenerator};
use MonkeysLegion\Encryption\Enum\Cipher;

// Generate a key
$key = Key::generate();                          // AES-256-GCM default
$key = Key::generate(Cipher::XChaCha20Poly1305); // Sodium

// Output formats
echo $key->base64(); // "base64:r4nd0m..."
echo $key->hex();    // "6162636465..."

// From existing key
$key = Key::fromBase64('base64:YOUR_KEY_HERE');
$key = Key::fromRaw($rawBytes, Cipher::Aes256Gcm);

// Static generator
$base64 = KeyGenerator::generateBase64();
$hex    = KeyGenerator::generateHex(Cipher::XChaCha20Poly1305);

// Memory safety
$key->destroy();              // Wipes key material from memory
$key->isDestroyed();          // true
```

---

## Key Rotation (Graceful)

```php
use MonkeysLegion\Encryption\Key\{Key, KeyChain};
use MonkeysLegion\Encryption\Encrypter;

$currentKey = Key::fromBase64($newKeyString);
$oldKey     = Key::fromBase64($previousKeyString);

$keyChain = KeyChain::withRotation($currentKey, [$oldKey]);
$encrypter = new Encrypter($keyChain);

// New data encrypted with current key
$encrypted = $encrypter->encryptString('new data');

// Old data decrypted by trying all keys (current → previous)
$decrypted = $encrypter->decryptString($oldEncryptedPayload);

// Property hooks
$encrypter->usingRotation;      // true
$keyChain->hasPreviousKeys;     // true
$keyChain->keyCount;            // 2
```

---

## Envelope Encryption (Per-Record Keys)

```php
use MonkeysLegion\Encryption\EnvelopeEncrypter;

$envelope = new EnvelopeEncrypter($masterKey);

// Encrypt — generates random DEK per record
$result = $envelope->encrypt('patient medical records');
// ['encrypted_data' => '...', 'wrapped_key' => '...', 'cipher' => 'aes-256-gcm']

// Decrypt — unwraps DEK then decrypts data
$data = $envelope->decrypt($result);

// Re-wrap with new master key (zero-downtime rotation)
$newResult = $envelope->rewrap($result, $newMasterKey);
```

---

## Deterministic Encryption (Searchable Fields)

```php
use MonkeysLegion\Encryption\DeterministicEncrypter;

$det = new DeterministicEncrypter($key);

// Same input → same output (for indexed DB columns)
$a = $det->encrypt('user@example.com');
$b = $det->encrypt('user@example.com');
assert($a === $b); // true — searchable!

$email = $det->decrypt($a); // "user@example.com"
```

> ⚠️ **WARNING:** Less secure than random-IV encryption. Use only for searchable indexed fields.

---

## HMAC Signing

```php
use MonkeysLegion\Encryption\Hmac\HmacSigner;
use MonkeysLegion\Encryption\Enum\HmacAlgorithm;

$signer = new HmacSigner($secretKey);

// Sign
$mac = $signer->sign('webhook payload');

// Verify (constant-time comparison)
$valid = $signer->verify('webhook payload', $mac); // true

// Different algorithms
$mac512 = $signer->sign('data', null, HmacAlgorithm::Sha512);

// Structured result
$result = $signer->signResult('data');
echo $result->mac;
echo $result->length;
$result->verify($incomingMac);
```

---

## Password Hashing

```php
use MonkeysLegion\Encryption\Hash\Hasher;
use MonkeysLegion\Encryption\Enum\HashAlgorithm;

// Default: Argon2id
$hasher = new Hasher();
$hash = $hasher->hash('my-password');
$valid = $hasher->verify('my-password', $hash); // true

// Check if needs upgrade
if ($hasher->needsRehash($hash)) {
    $newHash = $hasher->hash('my-password');
}

// Hash info
$info = $hasher->info($hash);
$info->isArgon2;  // true (property hook)
$info->isBcrypt;  // false (property hook)

// Bcrypt with custom rounds
$bcrypt = new Hasher(HashAlgorithm::Bcrypt, ['rounds' => 14]);

// Argon2id with custom options
$argon = new Hasher(HashAlgorithm::Argon2id, [
    'memory'  => 131072,
    'time'    => 6,
    'threads' => 4,
]);
```

---

## Key Derivation (HKDF)

```php
use MonkeysLegion\Encryption\Key\{Key, KeyDerivation};

$kdf = new KeyDerivation(salt: random_bytes(16));
$masterKey = Key::generate();

// Derive sub-keys with context labels
$encKey  = $kdf->deriveKey($masterKey, 'encryption-v1');
$authKey = $kdf->deriveKey($masterKey, 'authentication-v1');

// Use derived keys
$encrypter = new Encrypter($encKey->toKey());

// Raw derivation
$raw = $kdf->derive($masterKey->material(), 'session-key', 32);
```

---

## Property Hooks (PHP 8.4)

```php
// Key
$key->length;      // int (hook)
$key->isValid;     // bool (hook)

// KeyChain
$chain->hasPreviousKeys; // bool (hook)
$chain->keyCount;        // int (hook)

// DerivedKey
$dk->length;    // int (hook)
$dk->isValid;   // bool (hook)

// Encrypter
$enc->cipher;         // Cipher enum (hook)
$enc->usingRotation;  // bool (hook)

// EncryptionResult
$result->isAead;    // bool (hook)
$result->isSodium;  // bool (hook)

// HashInfo
$info->isBcrypt;  // bool (hook)
$info->isArgon2;  // bool (hook)
$info->isKnown;   // bool (hook)

// HmacResult
$hmac->length;  // int (hook)
```

---

## `#[Encrypted]` Attribute (Entity-Level Encryption)

```php
use MonkeysLegion\Encryption\Attribute\Encrypted;
use MonkeysLegion\Encryption\Enum\Cipher;

class Patient
{
    #[Encrypted]
    public string $ssn;                              // Auto-encrypt/decrypt

    #[Encrypted(cipher: Cipher::XChaCha20Poly1305)]
    public string $medicalRecord;                    // Custom cipher per field

    #[Encrypted(deterministic: true)]
    public string $email;                            // Searchable encrypted field

    #[Encrypted(keyId: 'tenant-key')]
    public string $apiSecret;                        // Multi-tenant key isolation
}

// Property hooks
$attr = new Encrypted(deterministic: true);
$attr->isSearchable;    // true  (hook)
$attr->hasCustomCipher; // false (hook)
```

> 💡 **Competitive:** This is MonkeysLegion's answer to Laravel's `encrypted` cast — but attribute-first, per-field cipher selection, and searchable (deterministic) mode built-in.

---

## `#[Hashed]` Attribute (Password Fields)

```php
use MonkeysLegion\Encryption\Attribute\Hashed;
use MonkeysLegion\Encryption\Enum\HashAlgorithm;

class User
{
    #[Hashed]
    public string $password;                          // Auto-hash (Argon2id default)

    #[Hashed(algorithm: HashAlgorithm::Bcrypt, options: ['rounds' => 14])]
    public string $pin;                               // Bcrypt with custom cost

    #[Hashed(algorithm: HashAlgorithm::Argon2i)]
    public string $legacyPassword;                    // Argon2i
}

// Property hooks
$attr = new Hashed();
$attr->isArgon;  // true
$attr->isBcrypt; // false
```

---

## `Crypt` Static Facade

```php
use MonkeysLegion\Encryption\Crypt;
use MonkeysLegion\Encryption\Encrypter;
use MonkeysLegion\Encryption\Key\Key;

// Bootstrap (done once by the framework)
$key = Key::fromBase64(getenv('ENCRYPTION_KEY'));
Crypt::setInstance(new Encrypter($key));

// Application code — clean, static API
$encrypted = Crypt::encryptString('api-token-xyz');
$decrypted = Crypt::decryptString($encrypted);

// With serialization
$encrypted = Crypt::encrypt(['user_id' => 42]);
$data      = Crypt::decrypt($encrypted);

// Access the key
$key = Crypt::getKey();

// Reset for tests
Crypt::reset();
```

---

## Testing (Fakes)

```php
use MonkeysLegion\Encryption\Testing\{FakeEncrypter, FakeHasher};

// FakeEncrypter — reversible base64 round-trip
$fake = new FakeEncrypter($key);
$encrypted = $fake->encryptString('hello');
$decrypted = $fake->decryptString($encrypted); // "hello"

$fake->encryptCount();  // 1
$fake->decryptCount();  // 1
$fake->assertNothingEncrypted(); // throws if any operations recorded

// FakeHasher — plaintext round-trip
$hasher = new FakeHasher();
$hash = $hasher->hash('password');        // "fakehash:password"
$hasher->verify('password', $hash);       // true
```

---

## CLI Commands

```bash
# Generate a new key
php artisan encryption:generate-key
php artisan encryption:generate-key --cipher=xchacha20-poly1305
php artisan encryption:generate-key --format=hex

# Rotate key (with instructions)
php artisan encryption:rotate-key
```

---

## DI Integration

```php
use MonkeysLegion\Encryption\Provider\EncryptionProvider;

$services = EncryptionProvider::register([
    'cipher' => 'aes-256-gcm',
    'key'    => 'base64:YOUR_KEY',
    'previous_keys' => 'base64:OLD_KEY_1,base64:OLD_KEY_2',
    'hash' => [
        'algorithm' => 'argon2id',
        'memory'    => 65536,
        'time'      => 4,
        'threads'   => 4,
    ],
    'hmac' => [
        'key' => 'your-hmac-key',
    ],
]);

$encrypter = $services['encrypter']; // EncrypterInterface
$hasher    = $services['hasher'];    // HasherInterface
$hmac      = $services['hmac'];     // HmacInterface
```

---

## Configuration (`config/encryption.mlc`)

```mlc
encryption {
    cipher        = ${ENCRYPTION_CIPHER:-aes-256-gcm}
    key           = ${ENCRYPTION_KEY}
    previous_keys = ${ENCRYPTION_PREVIOUS_KEYS:-}

    hash {
        algorithm = ${HASH_ALGO:-argon2id}
        bcrypt_rounds = ${BCRYPT_ROUNDS:-12}
        argon_memory  = ${ARGON_MEMORY:-65536}
        argon_threads = ${ARGON_THREADS:-4}
        argon_time    = ${ARGON_TIME:-4}
    }

    hmac {
        algorithm = ${HMAC_ALGO:-sha256}
        key       = ${HMAC_KEY:-}
    }
}
```

---

## License

MIT © 2026 MonkeysCloud Team
