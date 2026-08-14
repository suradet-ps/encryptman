# encryptman Roadmap

This roadmap describes what encryptman is, honestly, from reading its own
code -- and where it should end up. Every claim below was verified by
reading the repo and running the toolchain before deciding what comes
next.

> **What encryptman is.** A small, opinionated Rust library for encrypting
> *small strings* (passwords, API keys, tokens, connection strings) at rest,
> with one master key. AES-256-GCM authenticated encryption, HKDF-SHA256
> context separation, random nonces, zeroize-on-drop key handling, a version
> byte for future format migration, and two base64 encodings. That is the
> whole job. Published on crates.io (v0.2.2, ~600 downloads as of
> 2026-08-14), dual-licensed MIT/Apache-2.0, MSRV 1.85 (edition 2024).
>
> **What encryptman is not.** Not a password hasher. Not a file encryptor.
> Not a key management system. Not a TLS or PKI library. Not a
> database-at-rest solution. Not a cross-language encryption framework.
> Not an attempt to replace RustCrypto primitives -- it wraps `aes-gcm`
> and adds the layer of opinion that keeps callers from making the common
> mistakes (reused nonces, CBC-without-MAC, keys without context
> separation). The README already says "When NOT to use this crate"
> honestly; this roadmap keeps that spirit.

Nothing here is called "done" on intent alone. The repo already has a real
CI pipeline (`.github/workflows/ci.yml`: `cargo fmt --check`, `cargo clippy
--all-targets --all-features` under `RUSTFLAGS="-D warnings"`, `cargo test
--all-features`, `actions-rust-lang/audit`; all Actions pinned to SHA), a
release workflow that auto-creates GitHub releases from the CHANGELOG, and
25 unit tests + 7 doc tests passing on stable. Every phase's acceptance is
checked against that pipeline.

---

## Design Principles

Every change to encryptman should reinforce one or more of these
principles. When a new feature is proposed, ask: "which principle does it
serve, and does it violate any other?"

1. **Correctness before cleverness.** A crypto library has one job: be
   right. No clever encodings, no exotic modes, no "optimizations" that
   add attack surface. AES-256-GCM with random 96-bit nonces is the boring,
   correct choice, and the crate stays on it.
2. **Fail loudly, never panic in the API.** Errors are `Result`s. The
   caller decides what to do. A library that panics on entropy failure
   (`.expect("failed to generate random bytes")`) steals that decision.
3. **Memory hygiene is a feature.** Key material is zeroized on drop.
   Intermediate key material (derived keys, HKDF output) must be zeroized
   too. A key byte left in RAM is a bug.
4. **Misuse resistance by construction.** The API makes it hard to use the
   crate wrong: random nonces are generated for you, contexts are
   mandatory where they matter, ciphertexts are authenticated (tampering
   is detected), and the ciphertext format is versioned so it can evolve.
5. **Minimal supply chain.** Every dependency must justify its existence.
   A crypto crate with a dead dependency (`rand`) is a supply-chain and
   audit-surface problem, not a style problem.
6. **Provable behavior over asserted behavior.** Roundtrip tests prove
   nothing an attacker cares about. Known-answer tests against published
   vectors (NIST), property tests, and fuzzing prove the crate does
   exactly what the spec says -- nothing more, nothing less.
7. **Honest scope.** The crate encrypts small strings. Documenting "When
   NOT to use this crate" is part of the product. Scope creep (password
   hashing, file encryption, key storage) would make it worse, not better.
8. **A library for the ecosystem, not a toy for the author.** A real
   contribution to the Rust ecosystem is a format spec others can
   implement, published test vectors, a maintained CI, a documented
   security process, and a versioning policy people can rely on. That is
   the difference between a crate and slopware.

---

## Security Goals

- **Confidentiality + integrity for every ciphertext** (GCM tag). No
  plaintext, no partial plaintext, and no "decrypted garbage" on
  tampering -- only an error.
- **Key separation across application domains** (HKDF `info`), so a
  ciphertext encrypted for `"database-passwords"` cannot be replayed or
  substituted into `"api-keys"`.
- **No key material in RAM longer than necessary.** Master key, derived
  key, and GHASH key all zeroized.
- **No panic paths in the public API.** RNG failure is reported, not
  fatal.
- **No oracle leaks.** Wrong key, wrong context, and corrupt ciphertext
  all produce the same generic `DecryptionFailed` error -- the caller
  learns nothing about *which* input was wrong.
- **Forward compatibility.** The version byte (`0x01`) guarantees that
  ciphertexts written today remain decryptable after format migration --
  provided the migration policy (Phase 5) is written down and tested.
- **A supply chain that can be audited.** Pinned Actions, `cargo audit`,
  license checking (`cargo-deny`), and a dead-dependency-free manifest.

---

## Engineering Goals

- Single-purpose library: small plaintext strings in, encrypted strings
  out. No I/O, no files, no network, no keychain calls.
- Every public function has docs, an example, a test, and (where it makes
  sense) a property test.
- Every security-relevant behavior is pinned by a known-answer test, not
  just a roundtrip.
- The ciphertext format is a published spec with published test vectors,
  so other implementations can interoperate.
- MSRV policy is explicit and CI-enforced (`rust-version = "1.85"`).
- CI runs: fmt, clippy (`-D warnings`), tests, doc tests, audit,
  `cargo-deny`, Miri (for zeroize discipline), MSRV check, and
  `wasm32` build checks.
- Releasing is a repeatable, automated process (`cargo publish` on tag),
  and every release notes its changes.
- Version bumps are deliberate and communicated: pre-1.0 `0.x` minor
  versions may break, `0.x.y` patches never do; at 1.0.0 the API is
  frozen under semantic versioning.

---

## Current State (verified against the repo, not assumed)

Everything below was verified by reading the repo and running the
toolchain on 2026-08-14:

- **Crate**: `encryptman` v0.2.2, edition 2024, `rust-version = "1.85"`,
  license MIT/Apache-2.0, repository `github.com/suradet-ps/encryptman`.
  Published on crates.io (613 downloads at time of writing).
- **Layout**: single module `src/lib.rs` (771 lines incl. tests). No
  `tests/`, `benches/`, `examples/`, or `docs/` directories. No
  `SECURITY.md`. `Cargo.lock` exists locally but is gitignored (standard
  for a library).
- **API surface** (all `pub`): `MasterKey` (generate / from_bytes /
  as_bytes / into_bytes, `TryFrom<&[u8]>`, `TryFrom<Vec<u8>>`, Debug
  redaction, Zeroize-on-drop); `Encoding` (`Standard`, `UrlSafeNoPad`);
  `CryptoError` (8 variants); free functions `encrypt`, `decrypt`,
  `encrypt_with_context`, `decrypt_with_context`,
  `encrypt_with_encoding`, `decrypt_with_encoding`,
  `encrypt_bytes_with_context`, `decrypt_bytes_with_context`,
  `generate_master_key`. A private `derive_key` (HKDF-SHA256, `info` =
  `"encryptman:{context}"`, empty salt).
- **Ciphertext format**: `version (0x01) || 12-byte random nonce ||
  AES-256-GCM ciphertext || 16-byte tag`, base64-encoded
  (`Standard` or `UrlSafeNoPad`).
- **Dependencies**: `aes-gcm 0.11`, `base64 0.23`, `getrandom 0.4`,
  `hkdf 0.13`, `rand 0.10`, `sha2 0.11`, `thiserror 2`, `zeroize 1`.
  `missing_docs = "deny"` lint set. **`rand` is not used anywhere in the
  code** (verified by search; only `getrandom::fill` is called) -- a dead
  dependency.
- **Tests**: 25 unit tests + 7 doc tests, all passing (`cargo test
  --all-features`). Covered: roundtrips, random-nonce uniqueness,
  wrong-key/wrong-context/tamper failures, base64 validity, truncated
  ciphertext, empty/unicode/10 KB plaintexts, key conversions, version
  byte checks, encoding variants. No known-answer tests, no property
  tests, no fuzzing.
- **CI** (`.github/workflows/ci.yml`): 3 jobs -- Quality (fmt + clippy
  with `-D warnings`), Test (`cargo test --all-features`), Audit
  (`actions-rust-lang/audit`). All Actions pinned to SHAs, `contents:
  read` permission. **Missing**: Miri, MSRV check, `cargo-deny` license
  check, wasm/no_std builds, doc build, `cargo semver-checks`,
  fuzzing.
- **Release** (`.github/workflows/release.yml`): on `v*` tag, creates a
  GitHub release with CHANGELOG body. **`cargo publish` to crates.io is
  not automated** (last publish was manual: 0.2.2 on 2026-08-06).
- **Changelog**: Keep a Changelog format, all 3 releases documented,
  including the 0.2.0 format break (`version || nonce || ciphertext`).
- **History**: 23 commits, conventional-ish messages, clean tree.
  Renamed twice (`encrypted-settings` → `encrypt-man` → `encryptman`).

### Ecosystem position (researched 2026-08-14, via crates.io API)

| Crate | Downloads | What it is | Relationship to encryptman |
|-------|-----------|------------|---------------------------|
| `aes-gcm` (RustCrypto) | 136M | The low-level AEAD primitive | encryptman wraps it; competing is pointless, composing is the point |
| `age` | 3.4M | File encryption (streaming, key/passphrase based) | Different niche; encryptman must not become a bad `age` |
| `magic-crypt` | 796K | AES-**CBC**, unauthenticated, cross-language | The footgun encryptman positions against: CBC with no MAC cannot detect tampering |
| `keyring` | 20M | OS keychain access | Complementary; encryptman says "store the master key in the keychain" and means *this crate* |
| `secrets` | 81K | Protected-access memory | Complementary; encryptman zeroizes, `secrets` mprotects |
| `cryptify` | 427K | Rust code obfuscator (name collision) | Unrelated; noted so nobody confuses the two |

The honest read: the niche "encrypt small config values safely" is served
mostly by `magic-crypt` (popular but unauthenticated) and by people
hand-rolling `aes-gcm` calls and getting nonces wrong. That is the gap
encryptman exists for -- and the roadmap below is about earning the
trust that a 2 KB niche deserves.

---

## Gaps found while reading the repo (these shape the phases below)

Not every gap is a bug. Some are hardening, some are proof, some are
ecosystem citizenship. All are real, and all were verified.

1. **`MasterKey::generate()` and nonce generation panic on RNG failure.**
   `getrandom::fill(&mut key).expect("failed to generate random bytes")`
   (src/lib.rs:193) and `.expect("failed to generate random nonce")`
   (src/lib.rs:431) turn an entropy failure into a process abort. On
   target platforms where `getrandom` can fail (early boot, exotic
   wasm/WASI environments), a library must return `Result`, not panic.
   **This is the highest-severity finding.** (Phase 1.)

2. **`TryFrom<Vec<u8>>` leaks key material in the source buffer.**
   (src/lib.rs:260-262) The Vec is copied into the zeroized `MasterKey`,
   but the Vec's own allocation is never zeroized -- key bytes remain in
   RAM after the conversion. The very type the crate offers for importing
   keys leaves a copy of the key behind. (Phase 1.)

3. **Derived keys are not zeroized.** `derive_key` produces
   `Key<Aes256Gcm>` and a GHASH key inside the cipher object, and
   `aes-gcm` is used **without its `zeroize` feature** (verified against
   the aes-gcm 0.11 manifest: the feature exists as an optional
   dependency, unenabled). Round keys and the GHASH key linger after
   every encrypt/decrypt call. The `MasterKey` zeroizes itself, but its
   children don't. (Phase 1.)

4. **`rand = "0.10.2"` is a dead dependency.** Referenced in
   `Cargo.toml`, never used in code. Every dependency is attack surface,
   audit surface, and compile time. A crypto crate should be lean.
   (Phase 1.)

5. **No known-answer tests (KATs).** The 25 tests are all roundtrips and
   failure paths. Nothing pins the ciphertext bytes to a published
   standard. If `aes-gcm` upstream changed its GCM behavior (it won't --
   but *prove* it), or if a future maintainer "optimizes" the format, no
   test would notice. NIST CAVP GCMVS / SP 800-38D Appendix C vectors
   should be embedded as fixtures. (Phase 2.)

6. **No property tests or fuzzing.** A crypto crate should be fuzzed
   (decrypt never panics, never returns plaintext on wrong input) and
   property-tested (roundtrip holds for arbitrary bytes/contexts;
   tampering any byte fails; contexts stay isolated). Neither exists.
   (Phase 2.)

7. **No Miri, sanitizer, or MSRV CI.** Zeroize guarantees are exactly
   what Miri's Stacked Borrows / tree borrows checking and the
   `stacked-borrows`-style test configs are for. CI runs stable only;
   `rust-version = "1.85"` is declared but never checked, so an MSRV
   regression could ship. (Phase 2.)

8. **No format spec and no cross-version compatibility test.** The
   version byte is a contract without a written contract. There is no
   `docs/FORMAT.md`, no documented migration policy (what changes bump
   the version byte? what is the deprecation path for `0x01`?), and no
   fixture test proving ciphertexts from earlier versions decrypt in
   current code. For a crate whose *only* job is producing durable
   ciphertexts, this is the documentation gap. (Phase 5.)

9. **No error ergonomics.** `CryptoError` is not `PartialEq`, not
   `Clone`, not `Display`-testable in match arms; `EncryptionFailed`
   carries a `String` from the `aead` layer (unstable surface, leaks
   internals into callers' error paths). Callers cannot exhaustively
   match or unit-test their own error handling. (Phase 3.)

10. **No AAD (associated data) support.** GCM's authenticated associated
    data is the standard way to bind a ciphertext to a record (e.g., a
    user id, a field name). HKDF context separates keys; AAD would
    additionally bind the *record* -- defense in depth that costs one
    parameter. (Phase 3.)

11. **No key-rotation helper.** Rotating a master key means decrypt with
    old key, re-encrypt with new key -- and doing it by hand invites
    callers to leave plaintext or keys in intermediate variables.
    A `reencrypt(old_key, new_key, context, ciphertext)` helper that
    zeroizes intermediates is a small, high-value API. (Phase 3.)

12. **No `#![forbid(unsafe_code)]`.** There is no unsafe code in the
    crate today, but a crate whose brand is memory hygiene should make
    it a compile-time guarantee, not a reviewer's observation.
    (Phase 1.)

13. **No benchmarks.** "Fast" is claimed nowhere, and that's fine -- but
    a settings-encryption crate that people wrap in hot paths (e.g.,
    encrypting on every save) should publish real numbers: overhead over
    raw `aes-gcm`, cost at 16 B / 1 KiB / 16 KiB, key-derivation cost.
    Without numbers, "fast" is a vibe. (Phase 4.)

14. **No `no_std` / WASM verification.** Every dependency (`aes-gcm`,
    `base64`, `hkdf`, `sha2`, `getrandom`) supports `no_std`; the crate
    does not even check whether it builds for `wasm32-unknown-unknown`
    or `wasm32-wasip1`. Settings encryption is *especially* relevant for
    web apps (localStorage secrets, JWT-adjacent values in browser
    workers). CI never compiles a non-native target. (Phase 4.)

15. **`cargo-deny` not used.** `actions-rust-lang/audit` covers
    advisories but not licenses. A dual-licensed crate distributing
    code that depends on `base64`/`sha2` etc. should verify license
    compliance automatically. (Phase 4.)

16. **No `SECURITY.md` and no advisory process.** Users of a crypto
    crate need to know: where to report a vulnerability, how it will be
    handled, and what the disclosure policy is. Absent today. (Phase 4.)

17. **Publishing is manual.** The release workflow creates a GitHub
    release but does not `cargo publish`. The 613-download crate was
    published by hand each time. Automation removes the "forgot to
    publish the fix" class of failure. (Phase 4.)

18. **No examples beyond doc comments.** A `examples/` directory with a
    complete "store DB password, restore it" walkthrough (with
    `keyring`), a "rotate your master key" example, and a web-worker
    example would serve the ecosystem better than any documentation
    prose. (Phase 4.)

19. **Single-file module layout.** Fine at 771 lines; the crate must not
    grow into one giant file as the API matures (AAD, reencrypt,
    vectors). The module split (`ciphertext`, `key`, `encoding`,
    `error`, `format`) is a Phase 3 refactor with zero behavior change
    and a test suite that makes it safe.

20. **README lacks the ciphertext format table and compatibility
    policy.** The "How It Works" diagram is good; what's missing is the
    byte-level contract and "what happens when we change the format" --
    the two things a library consumer actually depends on.

---

## Phases

The phases are ordered by risk to the *users* of the crate. Phase 1
fixes the bugs that are bugs today. Phase 2 proves the crate correct in
a way roundtrips can't. Phase 3 completes the API. Phase 4 makes the
crate a good ecosystem citizen. Phase 5 writes down the contract the
ciphertext format implies. Phase 6 is the gate to 1.0.0.

Versioning strategy (pre-1.0, semver): breaking API changes are allowed
in `0.x` minor bumps and must be called out in the CHANGELOG;
`0.x.y` patches never break. The ciphertext format is **not** governed
by crate semver -- it is governed by the version byte (Phase 5).

---

## Phase 1: Hardening -- fix the real bugs, prove the hygiene

The four findings that matter *right now*: panicking RNG paths, key
material left in RAM (source Vec, derived keys), a dead dependency, and
an unenforced `unsafe` guarantee.

**Status: COMPLETE -- ships in 0.3.0 (tag + publish pending)**

- [x] **No-panic API.** `MasterKey::generate()` and `generate_master_key()`
  return `Result<MasterKey, CryptoError>` (new `RandomnessFailed`
  variant); nonce generation returns `Err(CryptoError::RandomnessFailed)`
  instead of panicking. Docs and doc tests updated. This is the one
  intentional breaking change in the crate's short history -- done before
  1.0, advertised loudly in the CHANGELOG. **This was the priority item
  of the roadmap.**
- [x] **Zeroize the source of `TryFrom<Vec<u8>>`.** The source buffer is
  zeroized on both success and error paths before being dropped.
  `TryFrom<&[u8]>` stays as-is (the caller owns the slice; zeroizing
  borrowed data would be wrong).
- [x] **Enable `aes-gcm`'s `zeroize` feature.** `aes-gcm = { version =
  "0.11", features = ["zeroize"] }` zeroizes the internal GHASH key
  (verified against the aes-gcm 0.11 source). The HKDF output buffer
  (`okm`) is zeroized after `Aes256Gcm::new`.
  *Known upstream limit (documented, not fixable from this crate): the
  `Key<Aes256Gcm>` value and the `Aes256` round keys are not zeroized on
  drop -- `crypto-common` 0.1.6 and `aes` 0.9.2 lack `ZeroizeOnDrop` for
  these types unless their own `zeroize` features are enabled, which
  feature unification does not grant transitively. Revisit in Phase 3 via
  a direct `aes` dependency if memory hygiene demands it.*
- [x] **Remove the dead `rand` dependency.** Deleted from `Cargo.toml`;
  a `cargo machete` CI job fails on any new dead dependency.
- [x] **Add `#![forbid(unsafe_code)]`** to `src/lib.rs`. The crate is
  safe-only and it is now enforced at compile time.
- [x] **Grep gate in CI**: the quality job fails if `expect(`, `unwrap(`,
  or `panic!` appears outside `#[cfg(test)]` and doc comments. Simple,
  mechanical, permanent.
- [x] **Tests for the new error paths**: RNG failure is hard to force
  with `getrandom`, so the tests pin the *shape*: `generate()` returns
  `Result`, both key-generation paths roundtrip through encrypt/decrypt.

**Acceptance (all met by 0.3.0):** `cargo test --all-features` + `cargo
clippy -D warnings` green; `cargo tree` shows no `rand`; the CI grep gate
passes with zero matches in library code; `MasterKey::generate()` is
`Result`; the `TryFrom<Vec<u8>>` zeroization is enforced by code review
(a unit test cannot observe a moved buffer in safe Rust -- this is
exactly the case Miri covers in Phase 2); the CHANGELOG documents the
breaking API change.

---

## Phase 2: Correctness proof -- KATs, properties, fuzzing, Miri

Roundtrips are the *minimum* bar. This phase pins the crate to published
standards and hostile inputs.

### Known-answer tests (KATs)

- [ ] **Embed NIST AES-256-GCM vectors** as fixtures (NIST CAVP GCMVS
  test set; SP 800-38D Appendix C examples are the canonical small
  set). Add `tests/kat.rs` that:
  - Encrypts NIST plaintexts with fixed key + nonce and asserts the
    exact GCM ciphertext + tag bytes match NIST's published output.
  - Decrypts NIST ciphertexts through the crate's own format
    (wrapping them in `version || nonce || ciphertext` and base64) and
    asserts the plaintext comes back.
  - Asserts the tag bytes are 16 bytes and the tag is checked (flip
    one tag byte -> `DecryptionFailed`).
- [ ] **Format-layout KAT**: assert the packed layout byte-for-byte for
  a hand-computed example (version byte, nonce position, tag position)
  so a future refactor cannot silently reorder the format.

### Property tests

- [ ] **`proptest`**: roundtrip for arbitrary byte strings up to 64 KiB;
  ciphertext uniqueness across calls; context isolation (encrypt under
  A, decrypt under B always fails); encoding roundtrips (Standard and
  UrlSafeNoPad cross-decode); every-byte-tamper-fails (flip each byte of
  a small ciphertext in turn; each flip must fail decryption).
- [ ] **Key roundtrip properties**: `TryFrom<&[u8]>` then `as_bytes`
  roundtrip for 32-byte inputs; rejection of all non-32 lengths.

### Fuzzing

- [ ] **`cargo-fuzz` target `decrypt`**: feed arbitrary bytes through
  `decrypt` / `decrypt_with_context` / `decrypt_with_encoding`; invariant:
  no panic, no hang, no allocation blowup. 128-byte max input is plenty
  (format is `1 + 12 + 16 + payload`).
- [ ] **Fuzz target `encoding`**: arbitrary base64 strings through
  `Encoding::decode`; no panic, and `decode(encode(x)) == x` for valid
  inputs.
- [ ] **Fuzz in CI**: a nightly-only job running each target 60 s; the
  fuzz corpus is committed so regressions are caught.

### Memory-safety CI

- [ ] **Miri job** (`cargo miri test` on the crate) -- this is exactly
  the tool for the zeroize claims: it catches uninitialized/leaked reads
  that would break `Zeroize`. Run on nightly in CI.
- [ ] **MSRV job**: CI compiles and tests on `rustc 1.85` exactly,
  failing if the declared `rust-version` regresses.

**Acceptance:** KAT suite passes against published NIST vectors; proptest
runs 1000+ cases per property in CI; fuzz targets run in CI with zero
findings; Miri job green; MSRV job green; all of it is part of
`.github/workflows/ci.yml`.

---

## Phase 3: API completion -- AAD, rotation, ergonomics

- [ ] **AAD support.** Add `encrypt_with_aad(context, plaintext, aad)`
  and `decrypt_with_aad(context, encoded, aad)` (and byte variants).
  AAD binds the ciphertext to its record (user id, field name,
  `settings.json` path). Document that AAD is public, not secret -- its
  job is binding, not hiding. Document the rule: **if you use AAD at
  encrypt time, you must use it at decrypt time.**
- [ ] **`reencrypt` helper.** `reencrypt(old_key, new_key, context,
  ciphertext) -> Result<String>`: decrypt, re-encrypt, zeroize the
  intermediate plaintext. Document the key-rotation procedure in an
  example ("migrate the key on all stored settings without exposing
  plaintext to the calling code").
- [ ] **Error ergonomics.** Derive `PartialEq, Clone` on `CryptoError`
  (and `Eq` where variants allow); change `EncryptionFailed(String)` to
  a payload-less variant (the `aead` error string is unstable surface
  and leaks internals). Ensure `std::error::Error::source()` returns the
  underlying `aead` error via `#[source]` for debugging. Add
  `#[must_use]` to pure functions (`derive_key`, `Encoding::encode`).
- [ ] **Module split (behavior-preserving).** Reorganize `src/lib.rs`
  into `src/{lib.rs, key.rs, encoding.rs, error.rs, format.rs,
  encrypt.rs}` -- the test suite from Phase 1-2 makes this a
  mechanical, safe refactor. Single source of truth for the packed
  layout lives in `format.rs` with the format KATs from Phase 2.
- [ ] **`Encoding::from_str`** for `"standard"` / `"url_safe_no_pad"`
  (serialization round-trip for settings files), with tests.
- [ ] **Documentation pass**: every public item re-reviewed against the
  doc/example/test triple; `cargo doc --no-deps` with
  `RUSTDOCFLAGS="-D warnings"` in CI.

**Acceptance:** new APIs have docs, examples, tests, and property tests;
`cargo semver-checks` (added to CI) reports the intended diff; `cargo doc`
is warning-free; the module split ships with zero test changes beyond
import paths; CHANGELOG documents the 0.4.0 (breaking) bump.

---

## Phase 4: Ecosystem citizenship -- targets, benches, security process

- [ ] **`no_std` support.** Make the crate `#![no_std]` with an `alloc`
  fallback: `std` feature on by default (for `std::string` errors and
  `format!` in error messages); `no_std` builds with `alloc`. All
  dependencies already support this (verified: `aes-gcm`, `base64`,
  `hkdf`, `sha2`, `getrandom` all have `no_std`/`alloc` paths). CI
  compiles `--no-default-features`.
- [ ] **WASM verification.** CI jobs: `cargo build --target
  wasm32-unknown-unknown` and `--target wasm32-wasip1` (add targets to
  `rustup` in CI). This is the biggest untapped audience: web workers
  and WASM plugins encrypting settings with a key from the OS keychain
  via a bridge. If `getrandom` on `wasm32-unknown-unknown` requires
  `wasm-opt`/`js` features, document the configuration in a README
  section "WebAssembly".
- [ ] **Benchmarks (`criterion`).** `benches/encrypt.rs`:
  encrypt/decrypt at 16 B, 256 B, 1 KiB, 16 KiB; `derive_key` cost; and
  overhead vs. raw `aes-gcm` on the same machine. Publish numbers in
  `docs/perf-baseline.md` (machine description included). Add a CI
  "bench, don't gate" job (no flaky threshold gates; results are for
  humans).
- [ ] **`cargo-deny`.** Add `deny.toml` (advisories: warn; licenses:
  allow MIT/Apache-2.0/BSD/ISC/Zlib; bans: `rand`). Replace/augment the
  audit job with `cargo-deny check licenses advisories bans`. Pinned
  action SHA, as always.
- [ ] **`SECURITY.md`.** Report channel (GitHub private vulnerability
  disclosure), response expectations (acknowledgment within 48 h,
  fix-within-90-days intent), disclosure policy (coordinated), and the
  security-relevant invariants the crate promises (no panic on hostile
  input, zeroize behavior, format stability within a version byte).
- [ ] **`examples/` directory.**
  - `examples/store_settings.rs` -- encrypt a `settings.json` secret
    with `keyring`-stored master key (the canonical use case).
  - `examples/rotate_key.rs` -- uses `reencrypt` end-to-end.
  - `examples/web_worker.rs` -- the WASM path with a `fetch`-based
    key bridge (doc-only if a wasm runtime is too heavy).
- [ ] **Automated publishing.** Extend the release workflow: after the
  GitHub release, run `cargo publish` with a `CARGO_REGISTRY_TOKEN`
  secret, guarded by `cargo publish --dry-run` in CI on every tag
  push. Keep the CHANGELOG-body release step.
- [ ] **`docs/security.md`**: the crate's threat model, in prose:
  what it protects (plaintext at rest), what it doesn't (key storage,
  side channels, traffic), the nonce-collision math (2^96 random
  nonces: collision probability < 2^-32 after ~2^48 encryptions --
  i.e., not a practical concern for settings, documented anyway), and
  why empty-salt HKDF is fine for a single master key (RFC 5869 allows
  it; the `info` parameter does the domain separation).

**Acceptance:** crate builds on `wasm32` and `no_std` in CI; `cargo-deny`
clean; `SECURITY.md` published; benchmarks have real numbers in
`docs/perf-baseline.md`; release workflow publishes to crates.io
automatically; no new dead dependencies.

---

## Phase 5: The contract -- format spec and compatibility policy

The version byte exists. This phase writes down what it means, and
proves it with tests and vectors.

- [ ] **`docs/FORMAT.md`** -- a precise, implementable byte-level spec:
  - The packed layout: `version (u8) || nonce (12 bytes) || ciphertext
    (len+16 tag)` with byte offsets.
  - HKDF construction: IKM = master key (32 bytes), salt = empty,
    `info` = UTF-8 `"encryptman:{context}"`, OKM = 32 bytes. Note the
    `format!("encryptman:{context}")` behavior for non-ASCII contexts
    (document: contexts are opaque byte strings; callers should use
    ASCII identifiers).
  - Encoding: RFC 4648 §4 (Standard) and §5 without padding
    (UrlSafeNoPad); what is padded vs. unpadded and why.
  - **Compatibility policy**: what changes require a new version byte
    (nonce length, tag length, layout, KDF change, algorithm change)
    vs. what doesn't (new encodings, new optional AAD -- AAD is per-call
    and never stored). The `0x01` format is frozen once 1.0.0 ships;
    `0x02` is a documented migration, not a surprise.
  - **Deprecation path**: how long `0x01` decryption stays supported
    after `0x02` ships (proposal: at least two minor releases, flagged
    in docs and CHANGELOG).
- [ ] **Published test vectors** -- `tests/vectors/encryptman-vectors.json`:
  fixed master keys (e.g., `00..1f`), contexts, plaintexts, and the
  exact expected `packed` bytes and base64 strings. Rationale: any other
  language or future version of this crate can check its implementation
  against the same fixtures. This is the concrete "give back to the
  ecosystem" artifact -- a format nobody can implement independently
  without it is a format only one maintainer understands.
- [ ] **Cross-version fixture test.** Commit ciphertexts generated by
  `0.2.0` and `0.2.2` (and any future version) and a test asserting
  current code decrypts them. Regression-proof for the format's
  promise.
- [ ] **README section "Ciphertext format & compatibility"** pointing to
  `docs/FORMAT.md`, the version-byte contract, and the migration policy.

**Acceptance:** `docs/FORMAT.md` exists and is reviewable by someone who
has never seen the codebase; the vectors file round-trips against the
crate in CI; the cross-version fixture test is green; a second
implementation of the spec (even a throwaway 50-line Python script in
`examples/interop.py`, not shipped) decrypts the crate's output -- this
is the interop proof.

---

## Phase 6: v1.0.0 gate -- stabilization

The crate has been hardened (1), proven (2), completed (3), given a
maintenance process (4), and given a contract (5). Phase 6 is the
discipline to declare it stable.

- [ ] **API freeze review.** Walk the public API with
  `cargo semver-checks` against `0.5.0`; document every intentional
  change. Confirm the "no panic in public API" invariant across the
  entire surface (grep gate from Phase 1 is the enforcement).
- [ ] **Format freeze.** `docs/FORMAT.md` is marked "v1.0"; version
  byte `0x01` is frozen; migration policy is in place.
- [ ] **Maintenance promise in README.** A short section: MSRV policy
  (1.85; raised only in minor releases with notice), security
  response (link to SECURITY.md), deprecation policy (semver),
  contribution guide (CONTRIBUTING.md -- new file: how to run tests,
  fuzz, benches, the grep gate, what a good PR looks like).
- [ ] **Audit milestone.** One deliberate review pass: a `docs/audit.md`
  checklist (key handling, nonce handling, error paths, panic paths,
  zeroize coverage, format layout) completed and committed, dated, by
  someone other than the author where possible. Not a paid third-party
  audit (out of scope) -- an honest, documented, repeatable checklist
  is the realistic bar for a 600-download crate, and it can be upgraded
  later if adoption grows.
- [ ] **Release discipline.** `cargo release`-style checklist (or the
  automated workflow from Phase 4): tag, changelog, publish, announce.
  CHANGELOG gets an "Unreleased" section discipline from this point.
- [ ] **Version bump to 1.0.0** with a changelog entry that explains
  exactly what "1.0" means: API stable, format frozen, security
  process live.

**Acceptance:** semver-checks clean against the previous version; all CI
green on `main`; `docs/audit.md` committed with today's date; 1.0.0 tag
created and published by the automated workflow; README carries the
maintenance promise.

---

## How the phases relate

```
Phase 1 (Hardening: no-panic, zeroize discipline) -- fixes real bugs -- do first
        |
        +---> Phase 2 (Correctness proof: KATs, proptest, fuzz, Miri)
        |           |
        |           v
        |   Phase 3 (API completion: AAD, reencrypt, ergonomics) -- safe because of 2
        |           |
        |           v
        |   Phase 4 (Ecosystem citizenship: no_std/wasm, benches, SECURITY.md,
        |            cargo-deny, automated publish)
        |           |
        |           v
        |   Phase 5 (The contract: FORMAT.md, vectors, cross-version tests)
        |           |
        |           v
        +----------> Phase 6 (v1.0.0 gate: freeze API + format, audit, publish)
                        |
                        v
                    v1.0.0
```

Phase 1 comes first because panic-on-entropy-failure and key bytes left
in RAM are bugs that exist *today*, regardless of anything else. Phase 2
is the prerequisite for every later phase's confidence: you cannot safely
refactor (Phase 3), promise compatibility (Phase 5), or freeze an API
(Phase 6) without known-answer tests and fuzzing in place. Phase 5's
spec is what makes the crate an ecosystem artifact rather than an
author-only tool. Phase 6 is the gate: the crate does not claim 1.0
stability until the pipeline proves it.

---

## Out of Scope (drawn on purpose, to stay a focused library)

Each of these is valuable *for a different crate*. encryptman stays a
settings-encryption primitive:

- **Password hashing / KDF** -- argon2, bcrypt, scrypt, PBKDF2. Point
  users there (README already does).
- **File / streaming encryption** -- `age`, `rage`, `sequoia`,
  streaming AEAD chunking. encryptman allocates the whole message.
- **Key storage and key management** -- OS keychain (`keyring`), KMS,
  Vault, TPM. encryptman takes a `MasterKey`; where it lives is the
  caller's decision, and the README says so.
- **Password-derived master keys** -- turning a human passphrase into
  the 32-byte key is a KDF problem with its own salt/iterations
  tradeoffs; out of scope, point to argon2.
- **Key exchange, signatures, TLS, PKI** -- different problem space
  entirely (RustCrypto / `rustls`).
- **Cross-language implementations** -- the crate is Rust; the *format*
  is documented for others (Phase 5) but the library stays single-
  language.
- **Secret-management workflows** (rotation policies, vaults, audit
  trails of decryption) -- consumer territory.
- **Encryption of large blobs, streams, or databases** -- README says
  it; the roadmap keeps it true.
- **A CLI or GUI** -- encryptman is a library. A CLI wrapper would be a
  separate crate (and would need key-storage decisions that belong to
  `age`-style tools).
- **Hardware acceleration / exotic primitives** -- the crate stays on
  RustCrypto's audited `aes-gcm`; replacing primitives to chase
  benchmarks is how footguns enter.
- **Performance theater** -- no micro-optimization passes; the bench
  numbers (Phase 4) exist to document, not to race.

---

## Documentation

The `docs/` directory should grow with the project:

| Document | Content | When |
|----------|---------|------|
| `ROADMAP.md` | This document | Now |
| `FORMAT.md` | Ciphertext layout, HKDF construction, compatibility & migration policy | Phase 5 |
| `security.md` | Threat model, nonce math, key-handling invariants, what the crate does and doesn't protect | Phase 4 |
| `perf-baseline.md` | Benchmark results, machine description, overhead vs. raw aes-gcm | Phase 4 |
| `audit.md` | The dated self-audit checklist (key/nonce/panic/zeroize/format) | Phase 6 |
| `SECURITY.md` | Vulnerability reporting, response times, disclosure policy | Phase 4 |

Plus a `CONTRIBUTING.md` at repo root (test/fuzz/bench commands, the
grep gate, PR expectations) -- the missing piece of the maintenance
promise today.

---

## What "not slopware" means for encryptman, concretely

This roadmap is written against the fear of becoming another
forgettable crypto crate. The concrete commitments, in order of
importance:

1. **Proof over claims.** KATs against NIST vectors, property tests,
   fuzzing, and Miri -- not a README that says "secure".
2. **A written contract.** `docs/FORMAT.md` + published test vectors:
   the format is implementable by anyone, so the crate is replaceable
   -- which is exactly why it deserves trust.
3. **Honesty about limits.** The "When NOT to use" section stays; the
   out-of-scope list is enforced; the crate never grows into a
   Swiss-army knife.
4. **Discipline that survives the author.** Pinned CI, `cargo-deny`,
   `SECURITY.md`, MSRV enforcement, semver-checks, automated
   publishing, changelog discipline. A crate is maintained by its
   process, not its enthusiasm.
5. **Ruthless minimalism.** One dead dependency was already found and
   removed in this roadmap (Phase 1). Every future dependency must
   pass the same test.
6. **A real audience served.** The niche exists: `magic-crypt`'s 796K
   downloads buy unauthenticated AES-CBC. encryptman's honest pitch --
   "authenticated, context-separated, zeroizing, versioned settings
   encryption" -- only becomes true *as this roadmap is executed*,
   and the roadmap says so.

---

## Post-1.0 future (only if they stay focused)

- **Additional encodings** if a consumer demands them (e.g.,
  `UrlSafePadded`, `Base32` for manual entry) -- gated behind the
  `Encoding` enum, tested the same way.
- **A sibling CLI crate** (`encryptman-cli`) for shell/settings-file
  workflows, reusing the published format spec -- only if adoption
  justifies it.
- **Integration guides** (Vue/Tauri apps, Electron main-process
  settings, WASM workers) as linked docs, not in-crate features.
- **A formal third-party security audit** -- the `docs/audit.md`
  checklist is the honest pre-1.0 bar; a paid audit becomes
  worthwhile only if downloads and adoption reach a scale where the
  risk justifies the cost. Not promised; not ruled out.

Until then: harden, prove, contract, freeze, publish. That is the whole
roadmap.
