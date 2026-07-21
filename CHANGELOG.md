# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
