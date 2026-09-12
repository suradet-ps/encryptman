//! Encryption and decryption entry points.

use aes_gcm::aead::{Aead, KeyInit, Payload};
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

/// Encrypt a plaintext string with a custom context and associated data.
///
/// Like [`encrypt_with_context`], but binds the ciphertext to the additional
/// authenticated data (AAD) `aad`. The AAD is authenticated by AES-GCM but
/// **not encrypted and not stored**: it is public, and its job is to bind a
/// ciphertext to its record (a user id, a settings key, a file path) so that
/// a ciphertext cannot be moved to a different record undetected.
///
/// The same `aad` must be supplied to [`decrypt_with_aad`]. An empty `aad`
/// is equivalent to the plain [`encrypt_with_context`] API, and ciphertexts
/// are interchangeable between the two.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `context` - An application-specific context string for key derivation.
/// * `plaintext` - The string to encrypt.
/// * `aad` - Additional authenticated data; public, not secret.
///
/// # Examples
///
/// ```rust
/// use encryptman::{encrypt_with_aad, decrypt_with_aad, generate_master_key};
///
/// let key = generate_master_key().unwrap();
///
/// // Bind the ciphertext to the record it belongs to.
/// let encrypted = encrypt_with_aad(&key, "settings", "s3cret", b"user:42").unwrap();
///
/// // Decryption requires the same record binding.
/// let decrypted = decrypt_with_aad(&key, "settings", &encrypted, b"user:42").unwrap();
/// assert_eq!(decrypted, "s3cret");
///
/// // A different record cannot decrypt it.
/// assert!(decrypt_with_aad(&key, "settings", &encrypted, b"user:43").is_err());
/// ```
pub fn encrypt_with_aad(
    master_key: &MasterKey,
    context: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, CryptoError> {
    encrypt_bytes_with_aad(master_key, context, plaintext.as_bytes(), aad)
        .map(|bytes| Encoding::Standard.encode(&bytes))
}

/// Decrypt a ciphertext string with a custom context and associated data.
///
/// The `context` must match the context used during encryption and the `aad`
/// must match the additional authenticated data used during encryption.
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `context` - The context string used during encryption.
/// * `encoded` - The base64-encoded ciphertext to decrypt.
/// * `aad` - The additional authenticated data used during encryption.
pub fn decrypt_with_aad(
    master_key: &MasterKey,
    context: &str,
    encoded: &str,
    aad: &[u8],
) -> Result<String, CryptoError> {
    let packed = Encoding::Standard.decode(encoded)?;
    let plaintext = decrypt_bytes_with_aad(master_key, context, &packed, aad)?;
    Ok(String::from_utf8(plaintext)?)
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
/// This function is the empty-AAD shorthand for [`encrypt_bytes_with_aad`].
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
    encrypt_bytes_with_aad(master_key, context, plaintext, &[])
}

/// Encrypt arbitrary bytes with a custom context and associated data.
///
/// Returns the raw ciphertext bytes: `version || nonce || ciphertext`. The
/// `aad` is authenticated by AES-GCM but not encrypted and not stored in the
/// output; the same `aad` is required at decryption time.
///
/// # Arguments
///
/// * `master_key` - The master key to encrypt with.
/// * `context` - An application-specific context string for key derivation.
/// * `plaintext` - The bytes to encrypt.
/// * `aad` - Additional authenticated data; public, not secret.
pub fn encrypt_bytes_with_aad(
    master_key: &MasterKey,
    context: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(master_key, context)?;
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomnessFailed)?;
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::EncryptionFailed)?;

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(pack(&nonce_bytes, &ciphertext))
}

/// Decrypt arbitrary bytes with a custom context.
///
/// Expects the input to be `version || nonce || ciphertext` (raw bytes, not
/// base64-encoded).
///
/// This function is the empty-AAD shorthand for [`decrypt_bytes_with_aad`].
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
    decrypt_bytes_with_aad(master_key, context, packed, &[])
}

/// Decrypt arbitrary bytes with a custom context and associated data.
///
/// Expects the input to be `version || nonce || ciphertext` (raw bytes, not
/// base64-encoded) and the `aad` that was supplied during encryption.
///
/// # Arguments
///
/// * `master_key` - The master key to decrypt with.
/// * `context` - The context string used during encryption.
/// * `packed` - The raw ciphertext bytes to decrypt.
/// * `aad` - The additional authenticated data used during encryption.
pub fn decrypt_bytes_with_aad(
    master_key: &MasterKey,
    context: &str,
    packed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (nonce_bytes, ciphertext) = unpack(packed)?;

    let key = derive_key(master_key, context)?;
    let cipher = Aes256Gcm::new(&key);

    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::DecryptionFailed)?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Re-encrypt a ciphertext under a new master key.
///
/// Decrypts `encoded` with `old_key`, re-encrypts the plaintext with
/// `new_key`, and zeroizes the intermediate plaintext before returning. This
/// is the building block for master-key rotation: the caller never has to
/// hold the plaintext in a variable of its own.
///
/// The `context` (and the [`Encoding::Standard`] encoding) is preserved; the
/// operation does not change which context a ciphertext belongs to.
///
/// Ciphertexts bound with AAD are not supported here, because `reencrypt`
/// has no way to know the AAD; decrypt and re-encrypt those with
/// [`decrypt_with_aad`] and [`encrypt_with_aad`] instead.
///
/// # Arguments
///
/// * `old_key` - The master key that currently protects `encoded`.
/// * `new_key` - The master key to protect the returned ciphertext with.
/// * `context` - The context the ciphertext was encrypted under.
/// * `encoded` - The base64-encoded ciphertext to rotate.
///
/// # Errors
///
/// Returns an error if `encoded` is not a valid ciphertext under `old_key`
/// and `context`, or if re-encryption fails.
///
/// # Examples
///
/// ```rust
/// use encryptman::{encrypt_with_context, decrypt_with_context, reencrypt, generate_master_key};
///
/// let old_key = generate_master_key().unwrap();
/// let new_key = generate_master_key().unwrap();
///
/// let before = encrypt_with_context(&old_key, "database", "postgres://...").unwrap();
/// let after = reencrypt(&old_key, &new_key, "database", &before).unwrap();
///
/// // The new key opens it; the old key no longer does.
/// assert_eq!(
///     decrypt_with_context(&new_key, "database", &after).unwrap(),
///     "postgres://..."
/// );
/// assert!(decrypt_with_context(&old_key, "database", &after).is_err());
/// ```
pub fn reencrypt(
    old_key: &MasterKey,
    new_key: &MasterKey,
    context: &str,
    encoded: &str,
) -> Result<String, CryptoError> {
    let mut plaintext = decrypt_with_context(old_key, context, encoded)?;
    let reencrypted = encrypt_with_context(new_key, context, &plaintext);
    plaintext.zeroize();
    reencrypted
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
    fn aad_roundtrip() {
        let key = generate_master_key().unwrap();
        let aad = b"user:42";

        let encrypted = encrypt_with_aad(&key, "settings", "secret", aad).unwrap();
        let decrypted = decrypt_with_aad(&key, "settings", &encrypted, aad).unwrap();
        assert_eq!(decrypted, "secret", "AAD string roundtrip must work");

        let packed = encrypt_bytes_with_aad(&key, "settings", b"\x00\xffbinary", aad).unwrap();
        let recovered = decrypt_bytes_with_aad(&key, "settings", &packed, aad).unwrap();
        assert_eq!(recovered, b"\x00\xffbinary", "AAD byte roundtrip must work");
    }

    #[test]
    fn wrong_aad_fails_with_generic_error() {
        let key = generate_master_key().unwrap();
        let encrypted = encrypt_with_aad(&key, "ctx", "secret", b"record-a").unwrap();
        let result = decrypt_with_aad(&key, "ctx", &encrypted, b"record-b");
        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "wrong AAD must fail with the generic error, got {result:?}"
        );
    }

    #[test]
    fn aad_isolation_from_empty_aad() {
        let key = generate_master_key().unwrap();

        // AAD-bound ciphertext must not decrypt without the AAD.
        let bound = encrypt_with_aad(&key, "ctx", "secret", b"record").unwrap();
        assert!(
            decrypt_with_context(&key, "ctx", &bound).is_err(),
            "AAD-bound ciphertext must not decrypt as unbound"
        );

        // An unbound ciphertext must not decrypt with an AAD.
        let unbound = encrypt_with_context(&key, "ctx", "secret").unwrap();
        assert!(
            decrypt_with_aad(&key, "ctx", &unbound, b"record").is_err(),
            "unbound ciphertext must not decrypt as AAD-bound"
        );
    }

    #[test]
    fn empty_aad_is_interchangeable_with_plain_api() {
        let key = generate_master_key().unwrap();

        let via_context = encrypt_bytes_with_context(&key, "ctx", b"data").unwrap();
        let via_empty_aad = decrypt_bytes_with_aad(&key, "ctx", &via_context, &[]).unwrap();
        assert_eq!(via_empty_aad, b"data");

        let via_aad = encrypt_bytes_with_aad(&key, "ctx", b"data", &[]).unwrap();
        let via_plain = decrypt_bytes_with_context(&key, "ctx", &via_aad).unwrap();
        assert_eq!(via_plain, b"data");
    }

    #[test]
    fn aad_is_not_stored_in_ciphertext() {
        let key = generate_master_key().unwrap();
        let small = encrypt_bytes_with_aad(&key, "ctx", b"data", b"a").unwrap();
        let large = encrypt_bytes_with_aad(&key, "ctx", b"data", &[0x42; 1024]).unwrap();
        assert_eq!(
            small.len(),
            large.len(),
            "AAD must be authenticated but not embedded in the ciphertext"
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
    fn reencrypt_moves_ciphertext_to_new_key() {
        let old_key = generate_master_key().unwrap();
        let new_key = generate_master_key().unwrap();
        let before = encrypt_with_context(&old_key, "db", "postgres://secret").unwrap();

        let after = reencrypt(&old_key, &new_key, "db", &before).unwrap();

        assert_ne!(after, before, "rotation must produce a fresh ciphertext");
        assert_eq!(
            decrypt_with_context(&new_key, "db", &after).unwrap(),
            "postgres://secret",
            "new key must open the rotated ciphertext"
        );
        assert!(
            decrypt_with_context(&old_key, "db", &after).is_err(),
            "old key must not open the rotated ciphertext"
        );
    }

    #[test]
    fn reencrypt_wrong_old_key_fails() {
        let old_key = generate_master_key().unwrap();
        let new_key = generate_master_key().unwrap();
        let stranger = generate_master_key().unwrap();
        let before = encrypt_with_context(&old_key, "db", "secret").unwrap();

        let result = reencrypt(&stranger, &new_key, "db", &before);
        assert!(result.is_err(), "wrong old key must fail");
    }

    #[test]
    fn reencrypt_tampered_ciphertext_fails() {
        let old_key = generate_master_key().unwrap();
        let new_key = generate_master_key().unwrap();
        let before = encrypt_with_context(&old_key, "db", "secret").unwrap();

        let mut packed = Encoding::Standard.decode(&before).unwrap();
        let last = packed.len() - 1;
        packed[last] ^= 0x01;
        let tampered = Encoding::Standard.encode(&packed);

        let result = reencrypt(&old_key, &new_key, "db", &tampered);
        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "tampered input must fail before re-encryption, got {result:?}"
        );
    }

    #[test]
    fn reencrypt_keeps_context_and_unicode() {
        let old_key = generate_master_key().unwrap();
        let new_key = generate_master_key().unwrap();
        let plaintext = "รหัสผ่าน 🔐";

        let before = encrypt_with_context(&old_key, "ctx-a", plaintext).unwrap();
        let after = reencrypt(&old_key, &new_key, "ctx-a", &before).unwrap();
        assert_eq!(
            decrypt_with_context(&new_key, "ctx-a", &after).unwrap(),
            plaintext
        );
        assert!(
            decrypt_with_context(&new_key, "ctx-b", &after).is_err(),
            "rotation must not change the context"
        );
    }

    #[test]
    fn reencrypt_rejects_aad_bound_ciphertext() {
        let old_key = generate_master_key().unwrap();
        let new_key = generate_master_key().unwrap();
        let bound = encrypt_with_aad(&old_key, "ctx", "secret", b"record").unwrap();

        let result = reencrypt(&old_key, &new_key, "ctx", &bound);
        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "AAD-bound ciphertext must not rotate through the AAD-less helper, got {result:?}"
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
