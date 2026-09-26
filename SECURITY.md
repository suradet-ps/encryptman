# Security Policy

## Supported versions

Pre-1.0, only the most recent release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a vulnerability

Use GitHub's private vulnerability disclosure:

<https://github.com/suradet-ps/encryptman/security/advisories/new>

Do not open a public issue for a suspected vulnerability.

Please include the affected version, a minimal reproducer (ciphertext or
code), and what you expected to happen. If the issue involves key or
plaintext handling, describe the threat model you had in mind.

## What to expect

- Acknowledgment within 48 hours.
- An assessment and fix plan within 7 days.
- A coordinated fix released within 90 days where feasible.
- Credit in the GitHub advisory and CHANGELOG, unless you prefer to stay
  anonymous.

## Scope

In scope: the crate's cryptographic behavior (AES-256-GCM usage, HKDF
derivation, nonce generation, ciphertext parsing), panic-freedom on
hostile input, zeroization of key material, and error-path leakage.

Out of scope: where the caller stores the master key (OS keychain, file,
environment), side channels of the host hardware, and applications built
on top of the crate. The threat model is written down in
[`docs/security.md`](docs/security.md).

## Security-relevant invariants

- **No panics on hostile input.** `unwrap`/`expect`/`panic!` are banned
  from library code by a CI grep gate.
- **Authenticate before returning plaintext.** Tampered or truncated
  ciphertexts fail with a generic error; no partial plaintext is ever
  returned.
- **Key material is zeroized on drop.** HKDF output and `reencrypt`
  intermediates are zeroized explicitly.
- **The wire format is versioned.** A format change requires a new
  version byte and a documented migration (roadmap Phase 5).
