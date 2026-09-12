# Release Checklist

Version is controlled by **git tags** (`vX.Y.Z`). The release workflow
(`.github/workflows/release.yml`) extracts the matching section from
`CHANGELOG.md` and uses it as the GitHub release notes, so **the tag, the
Cargo.toml version, and the CHANGELOG section must all match**.

## Before starting: semver rules (pre-1.0)

- `0.x.0` (minor): may contain **breaking changes** — must be documented
  prominently in CHANGELOG. This is the only place breaking changes are
  allowed.
- `0.x.y` (patch): **never** breaking. Bug fixes, tests, docs, CI only.
- The ciphertext format (version byte `0x01`) is **not** governed by
  crate semver — it is governed by `docs/FORMAT.md` (roadmap Phase 5).
  Until that exists, treat the current format as frozen.

Current release map (from `docs/ROADMAP.md`):

| Version | Content | Breaking? |
|---------|---------|-----------|
| 0.3.0 | Phase 1 hardening + breaking error changes | **Yes** — bundle all breaks here |
| 0.3.x | Phase 2 KATs, proptest, fuzz, Miri, MSRV job | No |
| 0.4.0 | Phase 3 AAD, reencrypt, FromStr, module split | **Yes** — new `CryptoError::InvalidEncoding` variant |
| 0.5.0 | Phase 4 no_std/wasm, benches, cargo-deny, SECURITY.md | Yes if it adds error variants; otherwise No |
| 1.0.0 | Phase 5 + 6 format freeze, audit, API freeze | Yes (the point) |

## Pre-release (do all of this in a branch first)

- [ ] All roadmap work for this version is merged to `main`
- [ ] `cargo test --all-features` passes locally
- [ ] `cargo clippy --all-targets --all-features` passes with zero warnings
- [ ] `cargo fmt --check` passes
- [ ] `cargo doc --no-deps` builds without warnings
- [ ] CI is green on `main` (Quality, Test, Audit jobs)
- [ ] If this release changed the ciphertext format: **STOP** — this is
      not allowed until `docs/FORMAT.md` and a new version byte exist
      (roadmap Phase 5)

## Prepare the release commit

- [ ] In `CHANGELOG.md`, rename `## [Unreleased]` to
      `## [0.X.Y] - YYYY-MM-DD`
- [ ] **Format warning**: the section header must start with exactly
      `## [0.X.Y]` — the release workflow's `awk` matches on
      `^## \[VERSION\]`, so `## [0.3.0] - 2026-08-14` works,
      `## [v0.3.0]` or `## 0.3.0` does **not**
- [ ] Review the section: every change since the last release is listed,
      broken into Added / Changed / Fixed groups (Keep a Changelog)
- [ ] If this is a breaking minor (`0.X.0`): the first Changed entry
      starts with `**BREAKING**:` and explains the migration
- [ ] Bump `version = "0.X.Y"` in `Cargo.toml` (must equal the tag)
- [ ] Confirm `include` in `Cargo.toml` covers `CHANGELOG.md` (it does:
      `["src/**", "README.md", "LICENSE*", "CHANGELOG.md"]`) — the
      changelog ships inside the crate tarball
- [ ] Commit the CHANGELOG + Cargo.toml changes together:
      `git add CHANGELOG.md Cargo.toml && git commit -m "chore: bump version to 0.X.Y"`
- [ ] Push and confirm CI is green on the release commit

## Tag and release

- [ ] `git tag v0.X.Y`
- [ ] `git push origin v0.X.Y`
- [ ] Workflow `release.yml` runs: verify the GitHub release was created
      at `https://github.com/suradet-ps/encryptman/releases`
- [ ] Check the release notes body contains the CHANGELOG section (not
      empty, no stray "Unreleased" text)

## Publish to crates.io (manual until roadmap Phase 4)

- [ ] `cargo publish --dry-run` — verify the tarball contents
      (`--list` on the packaged crate: src/, README, licenses, changelog)
- [ ] `cargo login` (only if the token is not already configured)
- [ ] `cargo publish` — confirm the new version appears on
      `https://crates.io/crates/encryptman`
- [ ] Verify `docs.rs` build succeeds (usually takes ~1 minute after
      publish)

## Post-release

- [ ] Create a new `## [Unreleased]` section at the top of CHANGELOG.md
- [ ] Update the release map table in this file if the plan changed
- [ ] If this was `1.0.0` or later: follow the semver policy — any
      breaking change now requires a `X.0.0` bump and a major-section
      changelog entry

## If something fails

| Symptom | Cause | Fix |
|---------|-------|-----|
| Release created with empty notes | CHANGELOG header doesn't match the tag (`v` prefix, missing `## [`) | Fix header, create a new tag at the fixed commit; delete the broken release via GitHub UI |
| `cargo publish` rejects the version | Version already exists on crates.io | You cannot overwrite a published version — bump to the next `0.x.y` and re-tag |
| CI red on the release commit | Out-of-date tests for the bump | Fix in a new commit; the tag must be moved to the fixed commit (`git tag -f` + force push only if the tag was never fetched by anyone) |
| `cargo publish` fails with auth error | Missing/invalid token | `cargo login`, then retry — no need to re-tag |
