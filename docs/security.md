# Security model

This document is the threat model behind [`SECURITY.md`](../SECURITY.md):
what encryptman protects, what it does not, and why its choices are sound.

## What encryptman protects

- Confidentiality and integrity of small plaintext strings (passwords,
  API keys, tokens, connection strings) stored at rest, as long as the
  master key stays secret.
- Context separation: a ciphertext created for one context cannot be
  decrypted under another. HKDF-SHA256 derives an independent key per
  context using `info = "encryptman:{context}"`.
- Tamper detection: AES-256-GCM authentication. Any modification of the
  version byte, nonce, ciphertext, or tag fails with an error; no partial
  plaintext is ever returned.
- Forward compatibility: the version byte reserves room to migrate the
  format without abandoning existing ciphertexts.

## What encryptman does not protect

- **Key storage.** Where the master key lives is the caller's decision
  (store it in the OS keychain; see the sibling `encryptman-keyring`
  crate).
- **Passphrase-derived keys.** Turning human input into a key is a KDF
  problem (argon2 and friends). encryptman starts from a uniformly random
  32-byte key.
- **Side channels** beyond zeroizing key material: memory access
  patterns, cache timing, and power analysis are out of scope.
- **Large data.** The whole plaintext is held in memory by design; this
  is a small-strings library, not a file or streaming encryptor.
- **Multi-tenant isolation.** One master key is one trust domain;
  per-user key management is a different problem.

## Trust model

- The crate composes audited RustCrypto primitives: `aes-gcm` (AES-256-GCM),
  `hkdf` + `sha2` (HKDF-SHA256), and `getrandom` (OS entropy). encryptman
  supplies the format, context policy, and memory hygiene around them.
- The OS random number generator is trusted. If it fails, key and nonce
  generation return `RandomnessFailed` instead of panicking.
- The caller is trusted to keep the master key secret and to reuse the
  same context (and AAD, if used) at decrypt time.

## Nonce collision math

Every encryption draws a fresh random 96-bit nonce. For random nonces the
collision probability after `q` encryptions under one key is bounded by
`q^2 / 2^97`. At `q = 2^32` (~4.3 billion) encryptions the probability is
below `2^-33`; at `q = 2^48` it approaches `2^-1`. A settings store will
never come close. The number is documented so users can judge their own
workload instead of trusting a claim.

## Why empty-salt HKDF is safe here

RFC 5869 permits an empty salt; it is treated as `HashLen` zero bytes.
The salt separates keys derived from the same IKM across *deployments*.
Here the IKM is already a uniformly random master key, and separation
across *contexts* is the job of the `info` parameter
(`"encryptman:{context}"`). Distinct contexts therefore produce
independent keys, which is the property the API promises.

## Zeroization coverage

- `MasterKey` zeroizes on drop. The `TryFrom<Vec<u8>>` source buffer is
  zeroized on both success and error paths.
- The HKDF output buffer is zeroized after the AES key is built; the
  `aes-gcm` `zeroize` feature zeroizes the internal GHASH key.
- `reencrypt` zeroizes the intermediate plaintext so rotation never
  leaves the secret in a caller-visible variable.
- **Known upstream limit:** `Key<Aes256Gcm>` and the `Aes256` round keys
  are not zeroized on drop unless the `crypto-common` / `aes` `zeroize`
  features are enabled, which feature unification does not grant
  transitively. Revisit with a direct `aes` dependency if the threat
  model demands it.

## AAD semantics

AAD (associated data) is authenticated but never encrypted or stored.
The rule is strict: **if you pass AAD at encrypt time, you must pass the
identical AAD at decrypt time.** Empty AAD is byte-for-byte equivalent
to the context-only APIs, so existing ciphertexts keep working.

## Error behavior (no oracle)

Wrong key, wrong context, and corrupt ciphertext all produce the same
`DecryptionFailed` error after base64 and format parsing; the caller
cannot learn *which* input was wrong from the error type.
`CiphertextTooShort` and `UnsupportedVersion` reveal only structural
facts about the input, never key material.
