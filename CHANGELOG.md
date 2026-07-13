# Changelog

All notable changes to `attest-receipts` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-07-13

First PyPI release built and published from the hardened OIDC pipeline
(Trusted Publishing + PEP 740 attestations). It rolls up every correctness and
security fix landed after 0.1.0.

### Security / correctness

- Continuity check rejects key-substitution: a candidate signature is verified
  against the candidate's own public key, not the trusted key.
- Strict canonical parser gained a recursion depth cap (DoS guard) and rejects
  lone surrogates; unknown key-status is treated fail-closed.
- Revocation view is bounded (default 10,000 records, injectable) and the
  issuer manifest is verified once per classification instead of per record;
  oversized revocation feeds fail closed for revocable receipts.
- Hardened key/artifact manifest handling, bundle import validation, ULID and
  edition schema strictness, and CLI path-escape defenses.

### Added

- Cross-language regression corpus (conformance vectors 19–25) pinning
  Python↔TypeScript parity.

## [0.1.0] — 2026-07-10

### Added

- Initial release: attest v0.1 reference implementation (signer + verifier,
  JCS canonicalization, Ed25519 via PyNaCl, offline verification, CLI).

[0.1.2]: https://github.com/SVM-98/attest/releases/tag/v0.1.2
[0.1.0]: https://github.com/SVM-98/attest/releases/tag/attest-verifier-v0.1.0
