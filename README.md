# encrypted-settings

AES-256-GCM encryption for application settings with HKDF key derivation.

## Features

- **AES-256-GCM** authenticated encryption — confidentiality + integrity
- **HKDF-SHA256** key derivation — derive purpose-specific keys from one master key
- **Random nonces** — encrypting the same plaintext twice produces different ciphertext
- **Zeroize on drop** — master key memory is cleared when dropped
- **Context isolation** — one master key can safely serve multiple encryption contexts

## Quick Start

```rust
use encrypted_settings::{encrypt, decrypt, generate_master_key};

let master_key = generate_master_key();

let encrypted = encrypt(&master_key, "my_database_password").unwrap();
let decrypted = decrypt(&master_key, &encrypted).unwrap();

assert_eq!(decrypted, "my_database_password");
```

## Usage

### Basic encrypt/decrypt

```rust
use encrypted_settings::{encrypt, decrypt, MasterKey};

let key = MasterKey::generate();
let ct = encrypt(&key, "secret").unwrap();
let pt = decrypt(&key, &ct).unwrap();
```

### Multiple contexts with one key

```rust
use encrypted_settings::{encrypt_with_context, decrypt_with_context, MasterKey};

let key = MasterKey::generate();

// Database passwords
let db_ct = encrypt_with_context(&key, "database", "postgres://...")?;

// API keys
let api_ct = encrypt_with_context(&key, "api-keys", "sk-12345")?;

// Same plaintext, different contexts → different ciphertext
assert_ne!(db_ct, api_ct);

// Decrypt with the same context
let db_pt = decrypt_with_context(&key, "database", &db_ct)?;
```

### Storing the master key

```rust
use encrypted_settings::MasterKey;

// Generate a new key
let key = MasterKey::generate();

// Get raw bytes for storage (e.g., OS keychain)
let bytes = *key.as_bytes();

// Later, reconstruct from stored bytes
let restored = MasterKey::from_bytes(bytes);
```

## How It Works

```
master_key → HKDF-SHA256(context) → AES-256 key
plaintext + random 12-byte nonce → AES-256-GCM → ciphertext
nonce || ciphertext → base64 → encoded string
```

- **Key derivation**: HKDF-SHA256 with a context string ensures one master key
  can produce independent keys for different purposes.
- **Encryption**: AES-256-GCM provides authenticated encryption — any tampering
  with the ciphertext is detected.
- **Nonce**: 12 random bytes generated per encryption call. Never reused.

## Security Considerations

- **Store the master key securely** — use OS keychain, hardware security module,
  or encrypted file. Never hardcode or commit it.
- **Different contexts for different purposes** — prevents cross-context attacks
  when one master key encrypts data for multiple subsystems.
- **Zeroize on drop** — `MasterKey` memory is cleared when dropped, reducing
  the window for memory dump attacks.

## Minimum Supported Rust Version

MSRV: **1.75** (edition 2024)

## License

MIT OR Apache-2.0
