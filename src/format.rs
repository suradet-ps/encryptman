//! Ciphertext format constants and the packed layout.
//!
//! This module is the single source of truth for the on-the-wire byte
//! layout: `version (1 byte) || nonce (12 bytes) || ciphertext || tag
//! (16 bytes)`, where the ciphertext and tag are the AES-256-GCM output.
//!
//! The layout is frozen for as long as the version byte is `0x01`; see
//! the roadmap (Phase 5, `docs/FORMAT.md`) for the compatibility policy.

use crate::CryptoError;

/// Size of the AES-256 key in bytes.
pub(crate) const KEY_SIZE: usize = 32;

/// Size of the AES-256-GCM nonce in bytes.
pub(crate) const NONCE_SIZE: usize = 12;

/// Current ciphertext format version byte.
pub(crate) const VERSION: u8 = 0x01;

/// Default HKDF context used by the context-free convenience functions.
pub(crate) const DEFAULT_CONTEXT: &str = "encryptman-v1";

/// Minimum length of a packed ciphertext: version + nonce + at least one
/// byte of GCM output (the tag alone is 16 bytes; anything shorter fails
/// authentication).
pub(crate) const MIN_PACKED_SIZE: usize = 1 + NONCE_SIZE + 1;

/// Pack a nonce and GCM ciphertext into the versioned wire format.
pub(crate) fn pack(nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    packed.push(VERSION);
    packed.extend_from_slice(nonce);
    packed.extend_from_slice(ciphertext);
    packed
}

/// Validate and split the versioned wire format into its nonce and
/// AES-256-GCM ciphertext parts.
///
/// # Errors
///
/// Returns [`CryptoError::CiphertextTooShort`] when the input cannot
/// contain a version byte plus nonce, and
/// [`CryptoError::UnsupportedVersion`] when the version byte is not
/// [`VERSION`].
pub(crate) fn unpack(packed: &[u8]) -> Result<(&[u8; NONCE_SIZE], &[u8]), CryptoError> {
    if packed.len() < MIN_PACKED_SIZE {
        return Err(CryptoError::CiphertextTooShort {
            expected: MIN_PACKED_SIZE,
            actual: packed.len(),
        });
    }

    let (version, rest) = packed
        .split_first()
        .ok_or(CryptoError::CiphertextTooShort {
            expected: MIN_PACKED_SIZE,
            actual: packed.len(),
        })?;

    if *version != VERSION {
        return Err(CryptoError::UnsupportedVersion(*version));
    }

    let (nonce, ciphertext) = rest.split_at(NONCE_SIZE);
    let nonce = nonce
        .try_into()
        .map_err(|_| CryptoError::CiphertextTooShort {
            expected: MIN_PACKED_SIZE,
            actual: packed.len(),
        })?;

    Ok((nonce, ciphertext))
}
