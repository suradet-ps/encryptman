//! Error type for every fallible encryptman operation.

use thiserror::Error;

/// Errors that can occur during encryption or decryption.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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
    #[error("encryption failed")]
    EncryptionFailed,

    /// The operating system's secure random number generator is unavailable.
    #[error("failed to acquire secure randomness")]
    RandomnessFailed,

    /// The provided byte slice is not exactly 32 bytes.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected length (32 bytes).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },
}
