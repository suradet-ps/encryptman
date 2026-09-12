# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-12

### Added

- **AAD (associated data) support**: `encrypt_with_aad()` /
  `decrypt_with_aad()` and the raw-byte variants `encrypt_bytes_with_aad()`
  / `decrypt_bytes_with_aad()` bind a ciphertext to a public record
  identifier (a user id, a settings key, a field name). AES-GCM
  authenticates the AAD but never encrypts or stores it, so the wire
  format is unchanged; an empty AAD is byte-for-byte the existing API.
- **`reencrypt()` key-rotation helper**: decrypts a ciphertext under the
  old key, re-encrypts it under the new key, and zeroizes the intermediate
  plaintext before returning. Context and Standard encoding are preserved;
  AAD-bound ciphertexts are documented as out of scope for this helper.
- **Encoding names for settings serialization**: `impl FromStr` for
  `Encoding` parses the canonical names `"standard"` and
  `"url_safe_no_pad"`, and `Encoding::as_str()` returns them. Unknown
  names return the new `CryptoError::InvalidEncoding`.
- **Module split** (internal only): `src/lib.rs` is now a thin crate root
  over `src/{key,encoding,error,format,encrypt}.rs`, with `format.rs` as
  the single source of truth for the packed layout. No public path changed.
- **CI**: a `cargo doc --no-deps --all-features` job with
  `RUSTDOCFLAGS="-D warnings"`, and a `cargo semver-checks` job checked
  against the published baseline.
- **Tests**: seven new property tests (AAD roundtrip and binding,
  empty-AAD equivalence, key rotation, encoding names), unit tests for
  every new API, and AAD paths in the `decrypt` fuzz target.

### Changed

- **BREAKING**: `CryptoError` gains the `InvalidEncoding` variant; an
  exhaustive `match` over `CryptoError` must now cover it.
- `Encoding::encode()` and `Encoding::as_str()` are `#[must_use]`.
- The CI panic gate scans every file under `src/` instead of only
  `src/lib.rs`.

### Security

- `reencrypt()` zeroizes the intermediate plaintext, so rotating a master
  key never leaves the secret in caller-visible memory.
- AAD binding is pinned by property tests: a ciphertext bound to one
  record cannot be decrypted as another, and the empty-AAD path is proven
  equivalent to the existing API.

## [0.3.1] - 2026-08-25

### Added

- **Known-answer tests** (`tests/kat.rs`): the primitive is pinned to the
  official NIST CAVP GCMVS test set (`gcmEncryptExtIV256.rsp` /
  `gcmDecrypt256.rsp`, CAVS 14.0) -- 6 encrypt vectors, 6 decrypt vectors,
  and 6 official tag-mismatch (`FAIL`) vectors. Every vector was
  cross-verified with OpenSSL 3 (via Node's `crypto` module) before being
  committed. The crate's own format (version byte, nonce/tag positions,
  HKDF wiring) is pinned against an independently computed fixture
  (OpenSSL HKDF + AES-256-GCM) including empty-plaintext, layout, version
  byte, wrong-key/wrong-context, and tamper-rejection checks.
- **Property tests** (`tests/proptests.rs`): 13 properties, 1000 cases
  each in CI -- roundtrips (arbitrary bytes up to 64 KiB, arbitrary
  strings, both encodings), ciphertext uniqueness, context isolation,
  wrong-key rejection, every-byte-tamper-fails, URL-safe charset,
  exact 32-byte key handling.
- **Fuzzing** (`fuzz/`): `decrypt` and `encoding` targets with committed
  corpus seeds; a nightly CI job runs each target for 60 s and fails on
  any crash artifact.
- **Miri CI job**: `cargo miri test --lib` and `--test kat` on nightly --
  the zeroize and memory-safety claims are now checked, not asserted.
- **MSRV CI job**: `cargo test --all-features` on rustc 1.85.0 exactly;
  a regression in the declared `rust-version` now fails CI.

## [0.3.0] - 2026-08-14

### Changed

- **BREAKING**: `MasterKey::generate()` and `generate_master_key()` now return
  `Result<MasterKey, CryptoError>` instead of panicking when the operating
  system's random number generator is unavailable. Migration: add `.unwrap()`
  or handle the new `CryptoError::RandomnessFailed` variant.
- **BREAKING**: `CryptoError::EncryptionFailed` no longer carries the
  underlying `aead` error string (unstable upstream surface). It is now a
  unit variant; `CryptoError` derives `PartialEq`, `Eq`, and `Clone`.
- Nonce generation no longer panics on RNG failure — it returns
  `CryptoError::RandomnessFailed`.
- `TryFrom<Vec<u8>> for MasterKey` now zeroizes the source buffer before it
  is dropped, on both success and error paths, so no copy of the key
  material survives in the caller's allocation.
- The HKDF output buffer in `derive_key()` is zeroized after the AES key is
  constructed.
- `aes-gcm` now enables its `zeroize` feature, scrubbing the internal GHASH
  key after each encryption/decryption call.

### Removed

- **BREAKING**: dropped the unused `rand` dependency (was declared but never
  used in code; `getrandom` is the only source of randomness).

### Security

- Added `#![forbid(unsafe_code)]` — the crate guarantees it contains no
  unsafe code.
- All public API panic paths removed: the crate returns `Result` everywhere
  an operation can fail. Verified by a CI grep gate that rejects
  `unwrap()` / `expect()` / `panic!` in non-test, non-doc code.

## [0.2.2] - 2026-08-06

### Changed

- Upgrade `aes-gcm` from 0.10 to 0.11 (`aead` 0.6)
- Replace `OsRng` with `getrandom` directly (removed in `rand_core` 0.10)
- Replace deprecated `Nonce::from_slice` / `Key::from_slice` with `TryFrom`
- Fix encrypt/decrypt to pass nonce by reference (`aead` 0.6 API)

## [0.2.1] - 2026-07-28

### Changed

- Rename project from `encrypt-man` to `encryptman`
- Update README installation version to match Cargo.toml
- Update CI pinned action SHAs to latest versions

## [0.2.0] - 2026-07-21

### Added

- `encrypt_with_encoding()` / `decrypt_with_encoding()` — encrypt with custom base64 encoding
- `encrypt_bytes_with_context()` / `decrypt_bytes_with_context()` — binary API for arbitrary data
- `Encoding` enum (`Standard`, `UrlSafeNoPad`) with public `encode()` / `decode()` methods
- `TryFrom<&[u8]>` and `TryFrom<Vec<u8>>` implementations for `MasterKey`
- `EncryptionFailed` error variant (separate from `KeyDerivation`)
- `UnsupportedVersion` error variant for unknown version bytes
- Version prefix byte (`0x01`) in ciphertext format for future compatibility
- CI workflow (quality, test, audit jobs)
- `rust-toolchain.toml` (pinned to stable)
- `missing_docs = "deny"` lint

### Changed

- **BREAKING**: HKDF now uses `info` parameter for context instead of `salt` (RFC 5869)
- **BREAKING**: Ciphertext format changed to `version || nonce || ciphertext`
- `derive_key()` now returns `Result` instead of panicking with `expect()`
- License split into `LICENSE-MIT` and `LICENSE-APACHE`
- README enhanced with badges, installation guide, URL-safe encoding example, and security notes

### Fixed

- `Encoding::encode()` / `decode()` are now `pub` (were private — dead API from outside crate)

## [0.1.0] - 2026-07-21

### Added

- `MasterKey` type with zeroize-on-drop
- `generate_master_key()` convenience function
- `encrypt()` / `decrypt()` with default context
- `encrypt_with_context()` / `decrypt_with_context()` for context-isolated encryption
- HKDF-SHA256 key derivation from master key
- AES-256-GCM authenticated encryption with random nonces
- Base64 encoding for safe storage
- Comprehensive test suite (14 tests)
