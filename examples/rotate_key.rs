//! Rotate a master key with `reencrypt`.
//!
//! The stored ciphertext is decrypted with the old key, re-encrypted with
//! the new key, and the intermediate plaintext is zeroized by the library,
//! so the secret never sits in a caller-visible variable.
//!
//! Run with: `cargo run --example rotate_key`

use encryptman::{decrypt_with_context, encrypt_with_context, generate_master_key, reencrypt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old_key = generate_master_key()?;
    let new_key = generate_master_key()?;

    let context = "database-urls";
    let secret = "postgres://app:hunter2@db.internal:5432/app";
    let stored = encrypt_with_context(&old_key, context, secret)?;

    let rotated = reencrypt(&old_key, &new_key, context, &stored)?;

    assert!(decrypt_with_context(&old_key, context, &rotated).is_err());
    assert_eq!(decrypt_with_context(&new_key, context, &rotated)?, secret);

    println!("rotated ciphertext: {rotated}");
    println!("old key rejected, new key decrypts: rotation succeeded");
    Ok(())
}
