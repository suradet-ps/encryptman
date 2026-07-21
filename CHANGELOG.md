# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
