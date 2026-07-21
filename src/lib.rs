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
//!    key using the application context as the `info` parameter (RFC 5869).
//! 2. **Encryption**: AES-256-GCM encrypts the plaintext with a random 12-byte
//!    nonce. The nonce is prepended to the ciphertext.
//! 3. **Encoding**: The version + nonce + ciphertext is base64-encoded for safe
//!    storage.
//!
//! ```text
//! master_key → HKDF-SHA256("encryptman:{context}") → AES key
//! plaintext + random nonce → AES-256-GCM → ciphertext
//! version || nonce || ciphertext → base64 → encoded string
//! ```
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
const VERSION: u8 = 0x01;
const DEFAULT_CONTEXT: &str = "encryptman-v1";

/// Ciphertext encoding variant.
///
/// Selects the base64 character set used for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Standard base64 (RFC 4648 §4). Safe for files, env vars, databases.
    Standard,

    /// URL-safe base64 without padding (RFC 4648 §5). Safe for URLs, JWTs,
    /// cookies, and web applications where `+`/`/` characters are problematic.
    UrlSafeNoPad,
}

impl Encoding {
    /// Encode raw bytes into a base64 string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// let encoded = Encoding::Standard.encode(b"hello");
    /// assert_eq!(encoded, "aGVsbG8=");
    /// ```
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            Encoding::Standard => base64::engine::general_purpose::STANDARD.encode(data),
            Encoding::UrlSafeNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data),
        }
    }

    /// Decode a base64 string into raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64 for this encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use encryptman::Encoding;
    ///
    /// let bytes = Encoding::Standard.decode("aGVsbG8=").unwrap();
    /// assert_eq!(bytes, b"hello");
    /// ```
    pub fn decode(&self, data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        match self {
            Encoding::Standard => base64::engine::general_purpose::STANDARD.decode(data),
            Encoding::UrlSafeNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data),
        }
    }
}

/// Errors that can occur during encryption or decryption.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The ciphertext is too short to contain a valid version + nonce.
    #[error("ciphertext too short: expected at least {expected} bytes, got {actual}")]
    CiphertextTooShort {
        /// Expected minimum length (version + nonce size).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// The input is not valid base64.
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// The ciphertext version byte is unrecognized.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// AES-256-GCM decryption failed (wrong key or corrupted data).
    #[error("decryption failed: wrong key or corrupted ciphertext")]
    DecryptionFailed,

    /// The decrypted bytes are not valid UTF-8.
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// HKDF key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// The provided byte slice is not exactly 32 bytes.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected length (32 bytes).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },
}

/// A master key for encryption/decryption.
///
/// Wraps a 32-byte key and ensures it is zeroed on drop.
///
/// # Examples
///
/// ```rust
/// use encryptman::MasterKey;
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
    /// **Security note**: The returned byte array is **no longer protected by
    /// Zeroize**. It will not be cleared on drop. The caller is responsible for
    /// handling the bytes securely — e.g., zeroing them when no longer needed,
    /// or ensuring they do not end up in logs, swap files, or core dumps.
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

impl TryFrom<&[u8]> for MasterKey {
    type Error = CryptoError;

    /// Create a master key from a byte slice.
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if the slice is not exactly
    /// 32 bytes.
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl TryFrom<Vec<u8>> for MasterKey {
    type Error = CryptoError;

    /// Create a master key from a `Vec<u8>`.
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if the vector is not exactly
    /// 32 bytes.
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(vec.as_slice())
    }
}

/// Encrypt a plaintext string using a master key.
///
/// Returns a base64-encoded string containing the version + nonce + ciphertext.
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
/// use encryptman::{encrypt, decrypt, generate_master_key};
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

/// Encrypt a plaintext string with a custom context and encoding.
///
/// The context is used in HKDF key derivation (`info` parameter) to derive a
/// unique AES key. Different context strings produce different keys from the
/// same master key, allowing one master key to safely encrypt data for multiple
/// purposes.
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
/// use encryptman::{encrypt_with_context, decrypt_with_context, generate_master_key};
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
    encrypt_bytes_with_context(master_key, context, plaintext.as_bytes())
        .map(|bytes| Encoding::Standard.encode(&bytes))
}

/// Decrypt a ciphertext string with a custom context.
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
    decrypt_with_encoding(master_key, context, encoded, Encoding::Standard)
}

/// Encrypt a plaintext string with a custom context and encoding.
///
/// The context is used in HKDF key derivation (`info` parameter) to derive a
/// unique AES key. The encoding determines the base64 character set used.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `context` - An application-specific context string for key derivation.
/// * `plaintext` - The string to encrypt.
/// * `encoding` - The base64 encoding to use.
///
/// # Examples
///
/// ```rust
/// use encryptman::{encrypt_with_encoding, decrypt_with_encoding, generate_master_key, Encoding};
///
/// let key = generate_master_key();
/// let encrypted = encrypt_with_encoding(&key, "jwt", "token", Encoding::UrlSafeNoPad).unwrap();
/// let decrypted = decrypt_with_encoding(&key, "jwt", &encrypted, Encoding::UrlSafeNoPad).unwrap();
/// assert_eq!(decrypted, "token");
/// ```
pub fn encrypt_with_encoding(
    master_key: &MasterKey,
    context: &str,
    plaintext: &str,
    encoding: Encoding,
) -> Result<String, CryptoError> {
    encrypt_bytes_with_context(master_key, context, plaintext.as_bytes())
        .map(|bytes| encoding.encode(&bytes))
}

/// Decrypt a ciphertext string with a custom context and encoding.
///
/// The `context` and `encoding` must match those used during encryption.
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `context` - The context string used during encryption.
/// * `encoded` - The base64-encoded ciphertext to decrypt.
/// * `encoding` - The base64 encoding to use.
pub fn decrypt_with_encoding(
    master_key: &MasterKey,
    context: &str,
    encoded: &str,
    encoding: Encoding,
) -> Result<String, CryptoError> {
    let packed = encoding.decode(encoded)?;
    let plaintext = decrypt_bytes_with_context(master_key, context, &packed)?;
    Ok(String::from_utf8(plaintext)?)
}

/// Encrypt arbitrary bytes with a custom context.
///
/// Returns the raw ciphertext bytes: `version || nonce || ciphertext`.
/// This is useful when you need to store or transmit binary data.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `context` - An application-specific context string for key derivation.
/// * `plaintext` - The bytes to encrypt.
pub fn encrypt_bytes_with_context(
    master_key: &MasterKey,
    context: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(master_key, context)?;
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{e}")))?;

    let mut packed = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    packed.push(VERSION);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);

    Ok(packed)
}

/// Decrypt arbitrary bytes with a custom context.
///
/// Expects the input to be `version || nonce || ciphertext` (raw bytes, not
/// base64-encoded).
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `context` - The context string used during encryption.
/// * `packed` - The raw ciphertext bytes to decrypt.
pub fn decrypt_bytes_with_context(
    master_key: &MasterKey,
    context: &str,
    packed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let min_len = 1 + NONCE_SIZE + 1;
    if packed.len() < min_len {
        return Err(CryptoError::CiphertextTooShort {
            expected: min_len,
            actual: packed.len(),
        });
    }

    let (version, rest) = packed
        .split_first()
        .ok_or(CryptoError::CiphertextTooShort {
            expected: min_len,
            actual: packed.len(),
        })?;

    if *version != VERSION {
        return Err(CryptoError::UnsupportedVersion(*version));
    }

    let key = derive_key(master_key, context)?;
    let cipher = Aes256Gcm::new(&key);

    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Generate a random master key.
///
/// Convenience function equivalent to `MasterKey::generate()`.
pub fn generate_master_key() -> MasterKey {
    MasterKey::generate()
}

/// Derive an AES-256 key from a master key using HKDF-SHA256.
///
/// Uses the master key as input keying material (IKM) and the application
/// context as the `info` parameter, following RFC 5869.
fn derive_key(master_key: &MasterKey, context: &str) -> Result<Key<Aes256Gcm>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut okm = [0u8; KEY_SIZE];
    let info = format!("encryptman:{context}");
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::KeyDerivation(format!("{e}")))?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
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

    #[test]
    fn try_from_ref_slice_valid() {
        let bytes = [1u8; 32];
        let key = MasterKey::try_from(bytes.as_slice()).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn try_from_ref_slice_wrong_length() {
        let bytes = [1u8; 16];
        let result = MasterKey::try_from(bytes.as_slice());
        assert!(result.is_err(), "wrong length must fail");
    }

    #[test]
    fn try_from_vec_valid() {
        let vec = vec![2u8; 32];
        let key = MasterKey::try_from(vec).unwrap();
        assert_eq!(key.as_bytes(), &[2u8; 32]);
    }

    #[test]
    fn try_from_vec_wrong_length() {
        let vec = vec![2u8; 64];
        let result = MasterKey::try_from(vec);
        assert!(result.is_err(), "wrong length must fail");
    }

    #[test]
    fn version_byte_in_ciphertext() {
        let key = generate_master_key();
        let encrypted = encrypt(&key, "test").unwrap();
        let packed = Encoding::Standard.decode(&encrypted).unwrap();
        assert_eq!(packed[0], VERSION, "first byte must be version");
    }

    #[test]
    fn unsupported_version_fails() {
        let key = generate_master_key();
        let encrypted = encrypt(&key, "test").unwrap();
        let mut packed = Encoding::Standard.decode(&encrypted).unwrap();
        packed[0] = 0xFF;
        let result = decrypt_bytes_with_context(&key, DEFAULT_CONTEXT, &packed);
        assert!(result.is_err(), "unsupported version must fail");
    }

    #[test]
    fn binary_plaintext_roundtrip() {
        let key = generate_master_key();
        let original: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let packed = encrypt_bytes_with_context(&key, "binary", &original).unwrap();
        let decrypted = decrypt_bytes_with_context(&key, "binary", &packed).unwrap();
        assert_eq!(
            original, decrypted,
            "binary plaintext must roundtrip correctly"
        );
    }

    #[test]
    fn url_safe_no_pad_encoding() {
        let key = generate_master_key();
        let packed = encrypt_bytes_with_context(&key, "test", b"hello").unwrap();
        let encoded = Encoding::UrlSafeNoPad.encode(&packed);
        assert!(
            !encoded.contains('+') && !encoded.contains('/'),
            "URL-safe encoding must not contain + or /"
        );
        assert!(
            !encoded.contains('='),
            "URL-safe no-pad encoding must not contain ="
        );
    }

    #[test]
    fn encrypt_with_encoding_standard_roundtrip() {
        let key = generate_master_key();
        let encrypted = encrypt_with_encoding(&key, "ctx", "secret", Encoding::Standard).unwrap();
        let decrypted = decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::Standard).unwrap();
        assert_eq!(decrypted, "secret", "Standard encoding roundtrip must work");
    }

    #[test]
    fn encrypt_with_encoding_url_safe_roundtrip() {
        let key = generate_master_key();
        let encrypted =
            encrypt_with_encoding(&key, "ctx", "secret", Encoding::UrlSafeNoPad).unwrap();
        let decrypted =
            decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::UrlSafeNoPad).unwrap();
        assert_eq!(decrypted, "secret", "URL-safe encoding roundtrip must work");
    }

    #[test]
    fn encoding_mismatch_fails() {
        let key = generate_master_key();
        let encrypted =
            encrypt_with_encoding(&key, "ctx", "secret", Encoding::UrlSafeNoPad).unwrap();
        let result = decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::Standard);
        assert!(result.is_err(), "decoding with wrong encoding must fail");
    }

    #[test]
    fn encoding_produces_different_base64() {
        let key = generate_master_key();
        let packed = encrypt_bytes_with_context(&key, "ctx", b"test-data>?>").unwrap();
        let std = Encoding::Standard.encode(&packed);
        let url = Encoding::UrlSafeNoPad.encode(&packed);
        assert_ne!(
            std, url,
            "Standard and URL-safe must produce different output"
        );
        assert!(
            !url.contains('+') && !url.contains('/') && !url.contains('='),
            "URL-safe output must not contain +, /, or ="
        );
    }
}
