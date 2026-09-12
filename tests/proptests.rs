//! Property tests: invariants that must hold for *arbitrary* inputs.
//!
//! These complement the KATs (which pin the crate to published standards)
//! by proving the API-level promises over the whole input space: any
//! plaintext roundtrips, any tampering fails, contexts stay isolated,
//! AAD stays bound, key rotation preserves plaintext, encodings are
//! reversible, and key handling is exact.
//!
//! Each property runs 1000 cases in CI (the `proptest_config!` below), per
//! the Phase 2 acceptance criteria.

use encryptman::{
    Encoding, MasterKey, decrypt_bytes_with_aad, decrypt_bytes_with_context, decrypt_with_aad,
    decrypt_with_context, decrypt_with_encoding, encrypt_bytes_with_aad,
    encrypt_bytes_with_context, encrypt_with_aad, encrypt_with_context, encrypt_with_encoding,
    reencrypt,
};
use proptest::prelude::*;

/// Arbitrary byte strings up to 64 KiB.
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=64 * 1024)
}

/// Arbitrary short byte strings (for cheap properties that don't need bulk).
fn short_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=64)
}

fn arbitrary_context() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..=32).prop_map(|bytes| {
        // Contexts are opaque byte strings in the crate; ASCII is the
        // documented convention, but any UTF-8 must work.
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

fn any_key() -> impl Strategy<Value = MasterKey> {
    prop::array::uniform32(any::<u8>()).prop_map(MasterKey::from_bytes)
}

/// Test-runner configuration.
///
/// - 1000 cases per property (Phase 2 acceptance).
/// - Failure persistence disabled: proptest's default file-based
///   persistence calls `getcwd`/filesystem APIs, which Miri forbids under
///   isolation. Keeping Miri's isolation enabled (stronger UB detection)
///   is more valuable than persisting regression seeds; CI reports the
///   failing case either way.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// Any byte string up to 64 KiB must roundtrip through the raw-bytes API.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn roundtrip_arbitrary_bytes(key in any_key(), context in arbitrary_context(), plaintext in arbitrary_bytes()) {
        let ciphertext = encrypt_bytes_with_context(&key, &context, &plaintext).expect("encryption must not fail");
        let recovered = decrypt_bytes_with_context(&key, &context, &ciphertext).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);
    }
}

// Any UTF-8 string must roundtrip through the string API.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn roundtrip_arbitrary_strings(key in any_key(), context in arbitrary_context(), plaintext in "\\PC*") {
        let ciphertext = encrypt_with_context(&key, &context, &plaintext).expect("encryption must not fail");
        let recovered = decrypt_with_context(&key, &context, &ciphertext).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);
    }
}

// Same plaintext, two calls -> two different ciphertexts (fresh random
// nonces; no deterministic reuse).
proptest! {
    #![proptest_config(config())]
    #[test]
    fn ciphertext_is_unique_across_calls(key in any_key(), plaintext in short_bytes()) {
        let a = encrypt_bytes_with_context(&key, "ctx", &plaintext).expect("encryption must not fail");
        let b = encrypt_bytes_with_context(&key, "ctx", &plaintext).expect("encryption must not fail");
        prop_assert_ne!(&a, &b);
        prop_assert_ne!(encrypt_bytes_with_context(&key, "ctx2", &plaintext).expect("encryption must not fail"), a);
    }
}

// Encrypting under context A must never decrypt under context B, for any
// pair of (possibly equal) contexts other than A == B.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn contexts_are_isolated(key in any_key(), a in arbitrary_context(), b in arbitrary_context(), plaintext in short_bytes()) {
        let ciphertext = encrypt_bytes_with_context(&key, &a, &plaintext).expect("encryption must not fail");
        if a == b {
            let recovered = decrypt_bytes_with_context(&key, &a, &ciphertext).expect("decryption must not fail");
            prop_assert_eq!(&recovered, &plaintext);
        } else {
            let result = decrypt_bytes_with_context(&key, &b, &ciphertext);
            prop_assert!(result.is_err(), "context B must not decrypt context A's ciphertext");
        }
    }
}

// A different master key must never decrypt (same generic error as wrong
// context -- no oracle).
proptest! {
    #![proptest_config(config())]
    #[test]
    fn wrong_key_never_decrypts(
        key_a_bytes in prop::array::uniform32(any::<u8>()),
        key_b_bytes in prop::array::uniform32(any::<u8>()),
        context in arbitrary_context(),
        plaintext in short_bytes(),
    ) {
        prop_assume!(key_a_bytes != key_b_bytes);
        let key_a = MasterKey::try_from(key_a_bytes.as_slice()).expect("32 bytes is a valid key");
        let key_b = MasterKey::try_from(key_b_bytes.as_slice()).expect("32 bytes is a valid key");
        let ciphertext = encrypt_bytes_with_context(&key_a, &context, &plaintext).expect("encryption must not fail");
        let result = decrypt_bytes_with_context(&key_b, &context, &ciphertext);
        prop_assert!(result.is_err());
    }
}

// Flipping any single byte of a ciphertext must make decryption fail
// (integrity is complete: version, nonce, ciphertext, and tag are all
// authenticated or validated).
proptest! {
    #![proptest_config(config())]
    #[test]
    fn every_byte_tamper_fails(key in any_key(), plaintext in short_bytes(), position in 0usize..128) {
        let ciphertext = encrypt_bytes_with_context(&key, "tamper", &plaintext).expect("encryption must not fail");
        prop_assume!(!ciphertext.is_empty());
        if position >= ciphertext.len() {
            let recovered = decrypt_bytes_with_context(&key, "tamper", &ciphertext).expect("decryption must not fail");
            prop_assert_eq!(&recovered, &plaintext);
        } else {
            let mut tampered = ciphertext.clone();
            tampered[position] ^= 0x01;
            let result = decrypt_bytes_with_context(&key, "tamper", &tampered);
            if position == 0 {
                // The version byte is validated, not authenticated.
                prop_assert!(result.is_err());
            } else {
                prop_assert!(matches!(result, Err(encryptman::CryptoError::DecryptionFailed)));
            }
        }
    }
}

// Both encodings must be exact inverses, and must decode each other's
// output to the same bytes.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn encoding_roundtrips(bytes in arbitrary_bytes()) {
        for encoding in [Encoding::Standard, Encoding::UrlSafeNoPad] {
            let encoded = encoding.encode(&bytes);
            let decoded = encoding.decode(&encoded)?;
            prop_assert_eq!(&decoded, &bytes);
        }

        let standard = Encoding::Standard.encode(&bytes);
        let url_safe = Encoding::UrlSafeNoPad.encode(&bytes);
        prop_assert_eq!(
            Encoding::Standard.decode(&standard)?,
            Encoding::UrlSafeNoPad.decode(&url_safe)?,
            "both encodings must carry the same bytes"
        );
    }
}

// The URL-safe encoding must never emit the characters `+`, `/`, or `=`.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn url_safe_encoding_is_url_safe(bytes in arbitrary_bytes()) {
        let encoded = Encoding::UrlSafeNoPad.encode(&bytes);
        prop_assert!(!encoded.contains(['+', '/', '=']));
        prop_assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}

// `TryFrom<&[u8]>` must roundtrip 32-byte keys and reject every other
// length with `InvalidKeyLength`.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn key_from_bytes_roundtrips_exactly_32(key_bytes in prop::array::uniform32(any::<u8>())) {
        let key = MasterKey::try_from(key_bytes.as_slice()).expect("32 bytes is a valid key");
        prop_assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn key_rejects_all_non_32_lengths(len in 0usize..=64) {
        prop_assume!(len != 32);
        let bytes = vec![0u8; len];
        let result = MasterKey::try_from(bytes.as_slice());
        match result {
            Err(encryptman::CryptoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 32);
                prop_assert_eq!(actual, len);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }
}

// `TryFrom<Vec<u8>>` must behave identically to the slice conversion.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn key_from_vec_roundtrips_exactly_32(key_bytes in prop::array::uniform32(any::<u8>())) {
        let key = MasterKey::try_from(key_bytes.to_vec()).expect("32 bytes is a valid key");
        prop_assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn key_from_vec_rejects_all_non_32_lengths(len in 0usize..=64) {
        prop_assume!(len != 32);
        let result = MasterKey::try_from(vec![0u8; len]);
        match result {
            Err(encryptman::CryptoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 32);
                prop_assert_eq!(actual, len);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }
}

// A complete encrypt/decrypt cycle through the base64-string API with a
// custom context and encoding must roundtrip.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn string_api_with_encoding_roundtrips(
        key in any_key(),
        context in arbitrary_context(),
        plaintext in "\\PC*",
        encoding in prop_oneof![Just(Encoding::Standard), Just(Encoding::UrlSafeNoPad)],
    ) {
        let ciphertext = encrypt_with_context(&key, &context, &plaintext).expect("encryption must not fail");
        let recovered = decrypt_with_context(&key, &context, &ciphertext).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);

        let encoded = encrypt_with_encoding(&key, &context, &plaintext, encoding).expect("encryption must not fail");
        let recovered = decrypt_with_encoding(&key, &context, &encoded, encoding).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);
    }
}

// AAD roundtrips for arbitrary bytes: the same (context, aad) pair always
// recovers the plaintext.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn aad_roundtrip_arbitrary(
        key in any_key(),
        context in arbitrary_context(),
        plaintext in arbitrary_bytes(),
        aad in arbitrary_bytes(),
    ) {
        let ciphertext = encrypt_bytes_with_aad(&key, &context, &plaintext, &aad).expect("encryption must not fail");
        let recovered = decrypt_bytes_with_aad(&key, &context, &ciphertext, &aad).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);
    }
}

// The string AAD APIs must roundtrip arbitrary strings and reject a
// mismatched record binding.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn aad_string_api_roundtrips(
        key in any_key(),
        context in arbitrary_context(),
        plaintext in "\\PC*",
    ) {
        let aad = b"record:42";
        let encrypted = encrypt_with_aad(&key, &context, &plaintext, aad).expect("encryption must not fail");
        let recovered = decrypt_with_aad(&key, &context, &encrypted, aad).expect("decryption must not fail");
        prop_assert_eq!(&recovered, &plaintext);
        prop_assert!(decrypt_with_aad(&key, &context, &encrypted, b"record:43").is_err());
    }
}

// A ciphertext bound to AAD A must never decrypt under AAD B (including
// A = empty vs. B = non-empty), and vice versa -- only an error, never
// plaintext.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn wrong_aad_never_decrypts(
        key in any_key(),
        context in arbitrary_context(),
        plaintext in short_bytes(),
        aad_a in short_bytes(),
        aad_b in short_bytes(),
    ) {
        let ciphertext = encrypt_bytes_with_aad(&key, &context, &plaintext, &aad_a).expect("encryption must not fail");
        if aad_a == aad_b {
            let recovered = decrypt_bytes_with_aad(&key, &context, &ciphertext, &aad_a).expect("decryption must not fail");
            prop_assert_eq!(&recovered, &plaintext);
        } else {
            let result = decrypt_bytes_with_aad(&key, &context, &ciphertext, &aad_b);
            prop_assert!(result.is_err(), "AAD B must not decrypt an AAD-A ciphertext");
        }
    }
}

// The empty-AAD byte APIs must be exactly the non-AAD byte APIs: a
// ciphertext from one must decrypt through the other.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn empty_aad_is_the_plain_api(
        key in any_key(),
        context in arbitrary_context(),
        plaintext in short_bytes(),
    ) {
        let plain = encrypt_bytes_with_context(&key, &context, &plaintext).expect("encryption must not fail");
        let via_aad = decrypt_bytes_with_aad(&key, &context, &plain, &[]).expect("decryption must not fail");
        prop_assert_eq!(&via_aad, &plaintext);

        let with_aad = encrypt_bytes_with_aad(&key, &context, &plaintext, &[]).expect("encryption must not fail");
        let via_plain = decrypt_bytes_with_context(&key, &context, &with_aad).expect("decryption must not fail");
        prop_assert_eq!(&via_plain, &plaintext);
    }
}

// reencrypt must move a ciphertext from the old key to the new key without
// changing the plaintext, and the old key must no longer open it.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn reencrypt_rotates_to_the_new_key(
        old_key in any_key(),
        new_key in any_key(),
        context in arbitrary_context(),
        plaintext in "\\PC*",
    ) {
        let before = encrypt_with_context(&old_key, &context, &plaintext).expect("encryption must not fail");
        let after = reencrypt(&old_key, &new_key, &context, &before).expect("reencryption must not fail");

        let recovered = decrypt_with_context(&new_key, &context, &after).expect("new key must decrypt");
        prop_assert_eq!(&recovered, &plaintext);
        prop_assert_ne!(&after, &before, "rotation must produce fresh ciphertext");
        prop_assert!(
            decrypt_with_context(&old_key, &context, &after).is_err(),
            "old key must not decrypt the rotated ciphertext"
        );
    }
}

// The canonical encoding names must parse back to the same encoding.
proptest! {
    #![proptest_config(config())]
    #[test]
    fn encoding_names_roundtrip(
        encoding in prop_oneof![Just(Encoding::Standard), Just(Encoding::UrlSafeNoPad)],
    ) {
        let parsed = encoding.as_str().parse::<Encoding>().expect("canonical name must parse");
        prop_assert_eq!(parsed, encoding);
    }
}
