//! Encrypt an application setting with a master key kept in the OS keychain.
//!
//! This is the canonical use case: the ciphertext lives in a settings file
//! or database, while the master key never touches disk. Requires a
//! keychain backend (macOS Keychain, Windows Credential Manager, or a
//! Linux Secret Service provider).
//!
//! Run with: `cargo run --example store_settings`

use encryptman::{Encoding, MasterKey, decrypt_with_context, encrypt_with_context};
use keyring::Entry;

const SERVICE: &str = "encryptman-store-settings-example";
const USER: &str = "master-key";
const CONTEXT: &str = "app-settings";

fn load_or_create_master_key(entry: &Entry) -> Result<MasterKey, Box<dyn std::error::Error>> {
    match entry.get_password() {
        Ok(encoded) => {
            let bytes = Encoding::Standard.decode(&encoded)?;
            Ok(MasterKey::try_from(bytes.as_slice())?)
        }
        Err(keyring::Error::NoEntry) => {
            let key = MasterKey::generate()?;
            entry.set_password(&Encoding::Standard.encode(key.as_bytes()))?;
            println!("generated a new master key and stored it in the OS keychain");
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let entry = Entry::new(SERVICE, USER)?;
    let key = load_or_create_master_key(&entry)?;

    // What would be written to settings.json (or a database row):
    let plaintext = r#"{"api_url":"https://api.example.com","token":"hunter2"}"#;
    let stored = encrypt_with_context(&key, CONTEXT, plaintext)?;
    println!("ciphertext to store in settings.json: {stored}");

    // On the next run, the ciphertext is read back and decrypted:
    let restored = decrypt_with_context(&key, CONTEXT, &stored)?;
    assert_eq!(restored, plaintext);
    println!("restored plaintext: {restored}");

    // Demo cleanup so repeated runs start from a fresh key:
    entry.delete_credential()?;
    println!("deleted the demo keychain entry");
    Ok(())
}
