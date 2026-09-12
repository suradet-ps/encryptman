#![no_main]

use encryptman::{
    decrypt, decrypt_bytes_with_aad, decrypt_bytes_with_context, decrypt_with_aad,
    decrypt_with_context, decrypt_with_encoding, Encoding, MasterKey,
};
use libfuzzer_sys::fuzz_target;

/// Fixed fuzzing key (not a real key; fuzz inputs are arbitrary).
const KEY_BYTES: [u8; 32] = [0x42; 32];

// Feed arbitrary bytes through every decrypt entry point.
//
// Invariant: none of these may panic, hang, or allocate pathologically on
// any input -- no matter how hostile. The format is `version (1) || nonce
// (12) || ciphertext || tag (16)`, so inputs beyond ~128 bytes add nothing,
// but fuzzing longer inputs costs nothing either.
fuzz_target!(|data: &[u8]| {
    let key = MasterKey::from_bytes(KEY_BYTES);
    let input = String::from_utf8_lossy(data);

    let _ = decrypt(&key, &input);
    let _ = decrypt_with_context(&key, "fuzz", &input);
    let _ = decrypt_with_encoding(&key, "fuzz", &input, Encoding::Standard);
    let _ = decrypt_with_encoding(&key, "fuzz", &input, Encoding::UrlSafeNoPad);
    let _ = decrypt_bytes_with_context(&key, "fuzz", data);
    let _ = decrypt_with_aad(&key, "fuzz", &input, data);
    let _ = decrypt_bytes_with_aad(&key, "fuzz", data, data);
});