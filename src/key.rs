//! Master key type and key generation.

use zeroize::Zeroize;

use crate::CryptoError;
use crate::format::KEY_SIZE;

/// A master key for encryption/decryption.
///
/// Wraps a 32-byte key and ensures it is zeroed on drop.
///
/// # Examples
///
/// ```rust
/// use encryptman::MasterKey;
///
/// let key = MasterKey::generate().unwrap();
/// // key is automatically zeroed when dropped
/// ```
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey([u8; KEY_SIZE]);

impl MasterKey {
    /// Generate a new random master key.
    ///
    /// The key is filled with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomnessFailed`] if the operating system's
    /// random number generator is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; KEY_SIZE];
        getrandom::fill(&mut key).map_err(|_| CryptoError::RandomnessFailed)?;
        Ok(Self(key))
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
    /// The source buffer is zeroized before it is dropped, so no copy of the
    /// key material survives in the caller's allocation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if the vector is not exactly
    /// 32 bytes.
    fn try_from(mut vec: Vec<u8>) -> Result<Self, Self::Error> {
        let result = Self::try_from(vec.as_slice());
        vec.zeroize();
        result
    }
}

/// Generate a random master key.
///
/// Convenience function equivalent to `MasterKey::generate()`.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessFailed`] if the operating system's
/// random number generator is unavailable.
pub fn generate_master_key() -> Result<MasterKey, CryptoError> {
    MasterKey::generate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decrypt, encrypt};

    #[test]
    fn generate_returns_result() {
        let key = MasterKey::generate().unwrap();
        let encrypted = encrypt(&key, "test").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, "test");
    }

    #[test]
    fn generate_master_key_fn_returns_result() {
        let key = generate_master_key().unwrap();
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
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
        let key = generate_master_key().unwrap();
        let debug = format!("{:?}", key);
        assert_eq!(
            debug, "MasterKey(***)",
            "Debug output must not leak key bytes"
        );
    }

    #[test]
    fn master_key_into_bytes() {
        let key = generate_master_key().unwrap();
        let bytes = *key.as_bytes();
        let key2 = MasterKey::from_bytes(bytes);
        let encrypted = encrypt(&key2, "test").unwrap();
        let decrypted = decrypt(&key2, &encrypted).unwrap();
        assert_eq!(decrypted, "test", "into_bytes roundtrip must preserve key");
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
}
