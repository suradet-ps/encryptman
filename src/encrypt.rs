//! Encryption and decryption entry points.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::CryptoError;
use crate::encoding::Encoding;
use crate::format::{DEFAULT_CONTEXT, KEY_SIZE, NONCE_SIZE, pack, unpack};
use crate::key::MasterKey;

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
/// let key = generate_master_key().unwrap();
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
/// let key = generate_master_key().unwrap();
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
/// let key = generate_master_key().unwrap();
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
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomnessFailed)?;
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::EncryptionFailed)?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(pack(&nonce_bytes, &ciphertext))
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
    let (nonce_bytes, ciphertext) = unpack(packed)?;

    let key = derive_key(master_key, context)?;
    let cipher = Aes256Gcm::new(&key);

    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::DecryptionFailed)?;

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derive an AES-256 key from a master key using HKDF-SHA256.
///
/// Uses the master key as input keying material (IKM) and the application
/// context as the `info` parameter, following RFC 5869. The HKDF output
/// buffer is zeroized before this function returns.
fn derive_key(master_key: &MasterKey, context: &str) -> Result<Key<Aes256Gcm>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut okm = [0u8; KEY_SIZE];
    let info = format!("encryptman:{context}");
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::KeyDerivation(format!("{e}")))?;
    let key = Key::<Aes256Gcm>::try_from(okm.as_slice())
        .map_err(|_| CryptoError::KeyDerivation("invalid key length".into()))?;
    okm.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::VERSION;
    use crate::generate_master_key;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_master_key().unwrap();
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
        let key = generate_master_key().unwrap();
        let a = encrypt(&key, "same_password").unwrap();
        let b = encrypt(&key, "same_password").unwrap();
        assert_ne!(
            a, b,
            "same plaintext must produce different ciphertext (random nonce)"
        );
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = generate_master_key().unwrap();
        let key2 = generate_master_key().unwrap();
        let encrypted = encrypt(&key1, "secret").unwrap();
        assert!(
            decrypt(&key2, &encrypted).is_err(),
            "decryption with wrong key must fail"
        );
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let key = generate_master_key().unwrap();
        assert!(
            decrypt(&key, "!!!invalid-base64!!!").is_err(),
            "invalid base64 input must fail"
        );
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let key = generate_master_key().unwrap();
        assert!(
            decrypt(&key, "dHJ1bmNhdGVk").is_err(),
            "truncated ciphertext must fail"
        );
    }

    #[test]
    fn different_contexts_produce_different_ciphertext() {
        let key = generate_master_key().unwrap();
        let a = encrypt_with_context(&key, "context-a", "same").unwrap();
        let b = encrypt_with_context(&key, "context-b", "same").unwrap();
        assert_ne!(a, b, "different contexts must produce different ciphertext");
    }

    #[test]
    fn context_isolation_decrypt_fails_cross_context() {
        let key = generate_master_key().unwrap();
        let encrypted = encrypt_with_context(&key, "context-a", "secret").unwrap();
        assert!(
            decrypt_with_context(&key, "context-b", &encrypted).is_err(),
            "cross-context decryption must fail"
        );
    }

    #[test]
    fn empty_plaintext_encrypts_and_decrypts() {
        let key = generate_master_key().unwrap();
        let encrypted = encrypt(&key, "").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, "", "empty plaintext must roundtrip correctly");
    }

    #[test]
    fn unicode_plaintext_roundtrip() {
        let key = generate_master_key().unwrap();
        let original = "รหัสผ่านภาษาไทย 🔐";
        let encrypted = encrypt(&key, original).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            original, decrypted,
            "unicode plaintext must roundtrip correctly"
        );
    }

    #[test]
    fn long_plaintext_roundtrip() {
        let key = generate_master_key().unwrap();
        let original = "a".repeat(10_000);
        let encrypted = encrypt(&key, &original).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(
            original, decrypted,
            "long plaintext must roundtrip correctly"
        );
    }

    #[test]
    fn version_byte_in_ciphertext() {
        let key = generate_master_key().unwrap();
        let encrypted = encrypt(&key, "test").unwrap();
        let packed = Encoding::Standard.decode(&encrypted).unwrap();
        assert_eq!(packed[0], VERSION, "first byte must be version");
    }

    #[test]
    fn unsupported_version_fails() {
        let key = generate_master_key().unwrap();
        let encrypted = encrypt(&key, "test").unwrap();
        let mut packed = Encoding::Standard.decode(&encrypted).unwrap();
        packed[0] = 0xFF;
        let result = decrypt_bytes_with_context(&key, DEFAULT_CONTEXT, &packed);
        assert!(result.is_err(), "unsupported version must fail");
    }

    #[test]
    fn binary_plaintext_roundtrip() {
        let key = generate_master_key().unwrap();
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
        let key = generate_master_key().unwrap();
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
        let key = generate_master_key().unwrap();
        let encrypted = encrypt_with_encoding(&key, "ctx", "secret", Encoding::Standard).unwrap();
        let decrypted = decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::Standard).unwrap();
        assert_eq!(decrypted, "secret", "Standard encoding roundtrip must work");
    }

    #[test]
    fn encrypt_with_encoding_url_safe_roundtrip() {
        let key = generate_master_key().unwrap();
        let encrypted =
            encrypt_with_encoding(&key, "ctx", "secret", Encoding::UrlSafeNoPad).unwrap();
        let decrypted =
            decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::UrlSafeNoPad).unwrap();
        assert_eq!(decrypted, "secret", "URL-safe encoding roundtrip must work");
    }

    #[test]
    fn encoding_mismatch_fails() {
        let key = generate_master_key().unwrap();
        let encrypted =
            encrypt_with_encoding(&key, "ctx", "secret", Encoding::UrlSafeNoPad).unwrap();
        let result = decrypt_with_encoding(&key, "ctx", &encrypted, Encoding::Standard);
        assert!(result.is_err(), "decoding with wrong encoding must fail");
    }

    #[test]
    fn encoding_produces_different_base64() {
        let key = generate_master_key().unwrap();
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
