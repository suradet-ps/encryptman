#![forbid(unsafe_code)]

//! # encryptman
//!
//! AES-256-GCM encryption for application settings with HKDF key derivation.
//!
//! This crate provides a simple, secure way to encrypt and decrypt string values
//! using a master key. It uses HKDF-SHA256 for key derivation and AES-256-GCM
//! for authenticated encryption. Each encryption call generates a fresh random
//! nonce, so encrypting the same plaintext twice produces different ciphertext.
//!
//! ## Quick Start
//!
//! ```rust
//! use encryptman::{encrypt, decrypt, generate_master_key};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a master key (store this securely — e.g., OS keychain)
//!     let master_key = generate_master_key()?;
//!
//!     // Encrypt
//!     let ciphertext = encrypt(&master_key, "my_database_password")?;
//!
//!     // Decrypt
//!     let plaintext = decrypt(&master_key, &ciphertext)?;
//!     assert_eq!(plaintext, "my_database_password");
//!     Ok(())
//! }
//! ```
//!
//! ## Design
//!
//! The encryption pipeline:
//!
//! 1. **Key derivation**: HKDF-SHA256 derives a unique AES key from the master
//!    key using the application context as the `info` parameter (RFC 5869).
//! 2. **Encryption**: AES-256-GCM encrypts the plaintext with a random 12-byte
//!    nonce. The nonce is prepended to the ciphertext.
//! 3. **Encoding**: The version + nonce + ciphertext is base64-encoded for safe
//!    storage.
//!
//! ```text
//! master_key → HKDF-SHA256("encryptman:{context}") → AES key
//! plaintext + random nonce (+ optional AAD) → AES-256-GCM → ciphertext
//! version || nonce || ciphertext → base64 → encoded string
//! ```
//!
//! ## Associated data (AAD)
//!
//! A ciphertext can be bound to a public record identifier (a user id, a
//! settings key, a file path) with [`encrypt_with_aad`] and
//! [`decrypt_with_aad`] (or the byte variants, [`encrypt_bytes_with_aad`]
//! and [`decrypt_bytes_with_aad`]). AES-GCM authenticates the AAD without
//! encrypting it or storing it in the ciphertext: the same AAD must be
//! supplied at decryption time, so a ciphertext moved to a different
//! record fails to decrypt. AAD is public, not secret, and an empty AAD is
//! byte-for-byte equivalent to the plain context API.
//!
//! ## Key rotation
//!
//! [`reencrypt`] moves a ciphertext from an old master key to a new one.
//! The plaintext exists only inside the function and is zeroized before it
//! returns, so callers never have to hold it themselves.
//!
//! ## When NOT to use this crate
//!
//! This crate is designed for encrypting small strings (passwords, API keys,
//! tokens). It is **not** suitable for:
//!
//! - **Password hashing** — use [`argon2`](https://crates.io/crates/argon2) or
//!   [`bcrypt`](https://crates.io/crates/bcrypt) instead.
//! - **File encryption** — use a streaming AEAD like
//!   [`XSalsa20Poly1305`](https://crates.io/crates/xsalsa20poly1305) or
//!   [`ChaCha20Poly1305`](https://crates.io/crates/chacha20poly1305) with
//!   proper chunking.
//! - **Database-at-rest encryption** — use your database's built-in encryption
//!   (e.g., PostgreSQL `pgcrypto`, MySQL `AES_ENCRYPT`).
//! - **Large data** — this crate allocates the entire plaintext/ciphertext in
//!   memory. For large data, use streaming encryption.

mod encoding;
mod encrypt;
mod error;
mod format;
mod key;

pub use encoding::Encoding;
pub use encrypt::{
    decrypt, decrypt_bytes_with_aad, decrypt_bytes_with_context, decrypt_with_aad,
    decrypt_with_context, decrypt_with_encoding, encrypt, encrypt_bytes_with_aad,
    encrypt_bytes_with_context, encrypt_with_aad, encrypt_with_context, encrypt_with_encoding,
    reencrypt,
};
pub use error::CryptoError;
pub use key::{MasterKey, generate_master_key};
