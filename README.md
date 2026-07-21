# encrypt-man

[![Crates.io](https://img.shields.io/crates/v/encrypt-man.svg)](https://crates.io/crates/encrypt-man)
[![Documentation](https://docs.rs/encrypt-man/badge.svg)](https://docs.rs/encrypt-man)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

AES-256-GCM encryption for application settings with HKDF key derivation.

## Features

- **AES-256-GCM** authenticated encryption — guarantees confidentiality + integrity
- **HKDF-SHA256** key derivation — derive purpose-specific keys safely from one master key
- **Random nonces** — encrypting the same plaintext twice yields distinct ciphertexts
- **Zeroize on drop** — master key memory is zeroed out automatically on drop
- **Context isolation** — prevents cross-domain ciphertext substitution attacks

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
encrypt-man = "0.1"
```

## Quick Start

```rust
use encrypt_man::{encrypt, decrypt, generate_master_key};

let master_key = generate_master_key();

let encrypted = encrypt(&master_key, "my_database_password")?;
let decrypted = decrypt(&master_key, &encrypted)?;

assert_eq!(decrypted, "my_database_password");
```

## Usage

### Basic encrypt/decrypt

```rust
use encrypt_man::{encrypt, decrypt, MasterKey};

let key = MasterKey::generate();
let ct = encrypt(&key, "secret")?;
let pt = decrypt(&key, &ct)?;
```

### Multiple contexts with one key

```rust
use encrypt_man::{encrypt_with_context, decrypt_with_context, MasterKey};

let key = MasterKey::generate();

// Database passwords
let db_ct = encrypt_with_context(&key, "database", "postgres://...")?;

// API keys
let api_ct = encrypt_with_context(&key, "api-keys", "sk-12345")?;

// Same plaintext, different contexts → different ciphertext
assert_ne!(db_ct, api_ct);

// Decrypt with the matching context
let db_pt = decrypt_with_context(&key, "database", &db_ct)?;
```

### URL-safe encoding (JWTs, cookies, URLs)

```rust
use encrypt_man::{encrypt_with_encoding, decrypt_with_encoding, generate_master_key, Encoding};

let key = generate_master_key();

let encrypted = encrypt_with_encoding(&key, "jwt", "token", Encoding::UrlSafeNoPad)?;
let decrypted = decrypt_with_encoding(&key, "jwt", &encrypted, Encoding::UrlSafeNoPad)?;

assert_eq!(decrypted, "token");
```

### Storing and restoring the master key

```rust
use encrypt_man::MasterKey;

// Generate a new key
let key = MasterKey::generate();

// Export raw bytes (e.g., to store in OS keychain / Vault)
let bytes = *key.as_bytes();

// Reconstruct key later
let restored = MasterKey::from_bytes(bytes);
```

## How It Works

```text
master_key ──► HKDF-SHA256(context) ──► AES-256 key
                                              │
plaintext + random 12-byte nonce ─────────────┴──► AES-256-GCM ──► version || nonce || ciphertext ──► Base64
```

- **Key Derivation**: HKDF-SHA256 generates domain-separated subkeys from a single master key.
- **Authenticated Encryption**: AES-256-GCM detects any payload tampering during decryption.
- **Fresh Nonce**: 12 random bytes generated per encryption call to maintain security guarantees.
- **Version Byte**: Reserved for future algorithm migrations.

## Security Considerations

- **Secure Storage**: Always store the master key in a key management service (KMS), OS keychain, or encrypted secret store.
- **Context Separation**: Use distinct context strings for different application domains (e.g., `"db"`, `"oauth"`) to prevent cross-context substitution.
- **Integrity Validation**: Decryption will fail with an error if the payload has been tampered with or corrupted.
- **Memory Security**: `MasterKey` implements `Zeroize` to scrub key bytes from RAM when dropped.

## When NOT to use this crate

This crate is designed for encrypting small strings (passwords, API keys, tokens). It is **not** suitable for:

- **Password hashing** — use [argon2](https://crates.io/crates/argon2) or [bcrypt](https://crates.io/crates/bcrypt) instead.
- **File encryption** — use a streaming AEAD like [ChaCha20Poly1305](https://crates.io/crates/chacha20poly1305) with proper chunking.
- **Database-at-rest encryption** — use your database's built-in encryption (e.g., PostgreSQL `pgcrypto`, MySQL `AES_ENCRYPT`).
- **Large data** — this crate allocates the entire plaintext/ciphertext in memory.

## Minimum Supported Rust Version

MSRV: **1.85** (edition 2024)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
