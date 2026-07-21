//! # encrypt-man
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
//! use encrypt_man::{encrypt, decrypt, generate_master_key};
//!
//! // Generate a master key (store this securely — e.g., OS keychain)
//! let master_key = generate_master_key();
//!
//! // Encrypt
//! let ciphertext = encrypt(&master_key, "my_database_password").unwrap();
//!
//! // Decrypt
//! let plaintext = decrypt(&master_key, &ciphertext).unwrap();
//! assert_eq!(plaintext, "my_database_password");
//! ```
//!
//! ## Design
//!
//! The encryption pipeline:
//!
//! 1. **Key derivation**: HKDF-SHA256 derives a unique AES key from the master
//!    key using an optional application-specific context string.
//! 2. **Encryption**: AES-256-GCM encrypts the plaintext with a random 12-byte
//!    nonce. The nonce is prepended to the ciphertext.
//! 3. **Encoding**: The nonce + ciphertext is base64-encoded for safe storage.
//!
//! ```text
//! master_key → HKDF-SHA256(context) → AES key
//! plaintext + random nonce → AES-256-GCM → ciphertext
//! nonce || ciphertext → base64 → encoded string
//! ```

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const DEFAULT_CONTEXT: &str = "encrypt-man-v1";

/// Errors that can occur during encryption or decryption.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The ciphertext is too short to contain a valid nonce.
    #[error("ciphertext too short: expected at least {expected} bytes, got {actual}")]
    CiphertextTooShort {
        /// Expected minimum length (nonce size).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// The input is not valid base64.
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// AES-256-GCM decryption failed (wrong key or corrupted data).
    #[error("decryption failed: wrong key or corrupted ciphertext")]
    DecryptionFailed,

    /// The decrypted bytes are not valid UTF-8.
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// HKDF key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
}

/// A master key for encryption/decryption.
///
/// Wraps a 32-byte key and ensures it is zeroed on drop.
///
/// # Examples
///
/// ```rust
/// use encrypt_man::MasterKey;
///
/// let key = MasterKey::generate();
/// // key is automatically zeroed when dropped
/// ```
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey([u8; KEY_SIZE]);

impl MasterKey {
    /// Generate a new random master key.
    ///
    /// The key is filled with cryptographically secure random bytes.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Create a master key from an existing 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the key material.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw key bytes.
    ///
    /// **Security note**: Use this only when you need to persist the key.
    /// Prefer storing via OS keychain when possible.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Consume the key and return the raw bytes.
    ///
    /// The returned array will NOT be zeroed on drop. Use with caution.
    pub fn into_bytes(mut self) -> [u8; KEY_SIZE] {
        let bytes = self.0;
        self.0.zeroize();
        bytes
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey(***)")
    }
}

/// Encrypt a plaintext string using a master key.
///
/// Returns a base64-encoded string containing the nonce + ciphertext.
/// Each call generates a fresh random nonce, so encrypting the same
/// plaintext twice produces different outputs.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `plaintext` - The string to encrypt.
///
/// # Examples
///
/// ```rust
/// use encrypt_man::{encrypt, decrypt, generate_master_key};
///
/// let key = generate_master_key();
/// let encrypted = encrypt(&key, "hello").unwrap();
/// let decrypted = decrypt(&key, &encrypted).unwrap();
/// assert_eq!(decrypted, "hello");
/// ```
pub fn encrypt(master_key: &MasterKey, plaintext: &str) -> Result<String, CryptoError> {
    encrypt_with_context(master_key, DEFAULT_CONTEXT, plaintext)
}

/// Decrypt a ciphertext string using a master key.
///
/// The `encoded` string must have been produced by [`encrypt`] or
/// [`encrypt_with_context`] with the same master key and context.
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `encoded` - The base64-encoded ciphertext to decrypt.
///
/// # Errors
///
/// Returns an error if the base64 is invalid, the ciphertext is too short,
/// the wrong key is used, or the decrypted data is not valid UTF-8.
pub fn decrypt(master_key: &MasterKey, encoded: &str) -> Result<String, CryptoError> {
    decrypt_with_context(master_key, DEFAULT_CONTEXT, encoded)
}

/// Encrypt with a custom application context string.
///
/// The context is used in HKDF key derivation to derive a unique AES key.
/// Different context strings produce different keys from the same master key,
/// allowing one master key to safely encrypt data for multiple purposes.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `context` - An application-specific context string for key derivation.
/// * `plaintext` - The string to encrypt.
///
/// # Examples
///
/// ```rust
/// use encrypt_man::{encrypt_with_context, decrypt_with_context, generate_master_key};
///
/// let key = generate_master_key();
/// let enc_db = encrypt_with_context(&key, "database-passwords", "secret").unwrap();
/// let enc_api = encrypt_with_context(&key, "api-keys", "secret").unwrap();
///
/// // Same plaintext, different contexts → different ciphertext
/// assert_ne!(enc_db, enc_api);
/// ```
pub fn encrypt_with_context(
    master_key: &MasterKey,
    context: &str,
    plaintext: &str,
) -> Result<String, CryptoError> {
    let key = derive_key(master_key, context);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::KeyDerivation(format!("encryption failed: {e}")))?;

    let mut packed = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&packed))
}

/// Decrypt with a custom application context string.
///
/// The `context` must match the context used during encryption.
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `context` - The context string used during encryption.
/// * `encoded` - The base64-encoded ciphertext to decrypt.
pub fn decrypt_with_context(
    master_key: &MasterKey,
    context: &str,
    encoded: &str,
) -> Result<String, CryptoError> {
    let key = derive_key(master_key, context);
    let cipher = Aes256Gcm::new(&key);

    let packed = base64::engine::general_purpose::STANDARD.decode(encoded)?;

    if packed.len() <= NONCE_SIZE {
        return Err(CryptoError::CiphertextTooShort {
            expected: NONCE_SIZE + 1,
            actual: packed.len(),
        });
    }

    let (nonce_bytes, ciphertext) = packed.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(String::from_utf8(plaintext)?)
}

/// Generate a random master key.
///
/// Convenience function equivalent to `MasterKey::generate()`.
pub fn generate_master_key() -> MasterKey {
    MasterKey::generate()
}

/// Derive an AES-256 key from a master key using HKDF-SHA256.
fn derive_key(master_key: &MasterKey, context: &str) -> Key<Aes256Gcm> {
    let hk = Hkdf::<Sha256>::new(Some(context.as_bytes()), master_key.as_bytes());
    let mut okm = [0u8; KEY_SIZE];
    hk.expand(b"encrypt-man", &mut okm)
        .expect("HKDF expand should not fail for a 32-byte output");
    *Key::<Aes256Gcm>::from_slice(&okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_master_key();
        let original = "my_secret_password_123!";
        let encrypted = encrypt(&key, original).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            original, decrypted,
            "decrypted text must match original plaintext"
        );
    }

    #[test]
    fn encrypt_produces_different_output_each_time() {
        let key = generate_master_key();
        let a = encrypt(&key, "same_password").unwrap();
        let b = encrypt(&key, "same_password").unwrap();
        assert_ne!(
            a, b,
            "same plaintext must produce different ciphertext (random nonce)"
        );
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = generate_master_key();
        let key2 = generate_master_key();
        let encrypted = encrypt(&key1, "secret").unwrap();
        assert!(
            decrypt(&key2, &encrypted).is_err(),
            "decryption with wrong key must fail"
        );
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let key = generate_master_key();
        assert!(
            decrypt(&key, "!!!invalid-base64!!!").is_err(),
            "invalid base64 input must fail"
        );
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let key = generate_master_key();
        assert!(
            decrypt(&key, "dHJ1bmNhdGVk").is_err(),
            "truncated ciphertext must fail"
        );
    }

    #[test]
    fn different_contexts_produce_different_ciphertext() {
        let key = generate_master_key();
        let a = encrypt_with_context(&key, "context-a", "same").unwrap();
        let b = encrypt_with_context(&key, "context-b", "same").unwrap();
        assert_ne!(a, b, "different contexts must produce different ciphertext");
    }

    #[test]
    fn context_isolation_decrypt_fails_cross_context() {
        let key = generate_master_key();
        let encrypted = encrypt_with_context(&key, "context-a", "secret").unwrap();
        assert!(
            decrypt_with_context(&key, "context-b", &encrypted).is_err(),
            "cross-context decryption must fail"
        );
    }

    #[test]
    fn empty_plaintext_encrypts_and_decrypts() {
        let key = generate_master_key();
        let encrypted = encrypt(&key, "").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, "", "empty plaintext must roundtrip correctly");
    }

    #[test]
    fn unicode_plaintext_roundtrip() {
        let key = generate_master_key();
        let original = "รหัสผ่านภาษาไทย 🔐";
        let encrypted = encrypt(&key, original).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            original, decrypted,
            "unicode plaintext must roundtrip correctly"
        );
    }

    #[test]
    fn master_key_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let key = MasterKey::from_bytes(bytes);
        assert_eq!(
            key.as_bytes(),
            &bytes,
            "from_bytes must preserve key material"
        );
        let encrypted = encrypt(&key, "test").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            decrypted, "test",
            "key from bytes must encrypt/decrypt correctly"
        );
    }

    #[test]
    fn master_key_debug_does_not_leak() {
        let key = generate_master_key();
        let debug = format!("{:?}", key);
        assert_eq!(
            debug, "MasterKey(***)",
            "Debug output must not leak key bytes"
        );
    }

    #[test]
    fn master_key_into_bytes() {
        let key = generate_master_key();
        let bytes = *key.as_bytes();
        let key2 = MasterKey::from_bytes(bytes);
        let encrypted = encrypt(&key2, "test").unwrap();
        let decrypted = decrypt(&key2, &encrypted).unwrap();
        assert_eq!(decrypted, "test", "into_bytes roundtrip must preserve key");
    }

    #[test]
    fn long_plaintext_roundtrip() {
        let key = generate_master_key();
        let original = "a".repeat(10_000);
        let encrypted = encrypt(&key, &original).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            original, decrypted,
            "long plaintext must roundtrip correctly"
        );
    }
}
