# Changelog

All notable changes to `monkeyscloud/monkeyslegion-encryption` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-26

### Added

- **Encrypter** — Main encryption service with AES-256-GCM default, serialization modes, key rotation via `KeyChain`.
- **OpenSSL Cipher** — AES-128-CBC, AES-256-CBC (HMAC-SHA256), AES-128-GCM, AES-256-GCM (AEAD).
- **Sodium Cipher** — XChaCha20-Poly1305 (AEAD via libsodium).
- **Deterministic Encryption** — Same-input → same-output for searchable indexed DB columns.
- **Envelope Encryption** — Per-record DEK with wrapped key; supports zero-downtime master key rotation (`rewrap`).
- **Key Management** — `Key`, `KeyChain` (rotation), `KeyGenerator`, `KeyDerivation` (HKDF), `DerivedKey`.
- **Memory-Safe Keys** — `Key::destroy()` wipes material; serialization and `__toString` blocked.
- **Password Hashing** — `Hasher` with Argon2id (default) and Bcrypt; `needsRehash()` detection; `HashInfo` inspection.
- **HMAC Signing** — `HmacSigner` with SHA-256/384/512; constant-time verification; structured `HmacResult`.
- **Contracts** — `EncrypterInterface`, `HasherInterface`, `HmacInterface`, `KeyDerivationInterface`.
- **Exceptions** — `EncryptionException`, `DecryptionException`, `KeyException` with static factories.
- **CLI Commands** — `GenerateKeyCommand`, `RotateKeyCommand`.
- **DI Provider** — `EncryptionProvider::register()` for PSR-11 container integration.
- **Testing Fakes** — `FakeEncrypter` (base64 round-trip + counters), `FakeHasher` (plaintext round-trip).
- **Backed Enums** — `Cipher`, `HashAlgorithm`, `HmacAlgorithm`.
- **PHP 8.4 Property Hooks** — `Key::$length`, `$isValid`; `Encrypter::$cipher`, `$usingRotation`; `HashInfo::$isBcrypt`, `$isArgon2`.
- **`#[Encrypted]` Attribute** — Auto-encrypt/decrypt entity fields (competitive with Laravel's `encrypted` cast).
- **`#[Hashed]` Attribute** — Auto-hash entity password fields on set.
- **`Crypt` Static Facade** — `Crypt::encrypt()`, `::decrypt()`, `::encryptString()`, `::decryptString()`.
- **Configuration** — `config/encryption.mlc` with env-variable support.
- **Comprehensive Test Suite** — 90%+ coverage across all components.
