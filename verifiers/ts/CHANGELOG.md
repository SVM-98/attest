# Changelog

All notable changes to `attest-verifier` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-07-13

First npm release from the hardened OIDC pipeline (Trusted Publishing +
provenance). Rolls up the 0.1.1 BOM-rejection fix (never published to npm) and
the revocation-view bound.

### Security / correctness

- Bound the revocation view (`MAX_REVOCATION_RECORDS`, default 10,000, 5th
  `verify` parameter); verify the issuer manifest once per classification;
  fail closed on an oversized revocation view for revocable receipts.
- (from 0.1.1, first time on npm) Reject a leading UTF-8 BOM in the strict
  envelope parser, matching the Python reference.

## [0.1.1] — 2026-07-13

### Fixed

- **Reject a leading UTF-8 BOM in the strict envelope parser** (security /
  cross-implementation parity). The decoder previously used `TextDecoder`
  with the default `ignoreBOM: false`, which silently strips a leading byte
  order mark (`U+FEFF`) before parsing. As a result this verifier **accepted**
  a BOM-prefixed receipt envelope that the Python reference implementation
  (`attest`) **rejects** — two conforming verifiers disagreeing on whether the
  same bytes are valid. The parser now decodes with `ignoreBOM: true`, so the
  BOM survives as `U+FEFF` and is rejected as an unexpected character, matching
  the Python reference and the spec's strict-parser intent.

  This narrows the set of inputs the verifier accepts. Receipts carrying a
  leading BOM were never conformant (the Python reference always rejected
  them), so no legitimate issuer output is affected; the canonical signed bytes
  are unchanged, so this is not a wire-format or protocol change. Surfaced by
  the cross-language regression corpus (conformance vector `21-canon-strict/
  a-bom`).

## [0.1.0] — 2026-07-10

### Added

- Initial release: an independent, from-scratch TypeScript implementation of
  the attest v0.1 verifier — strict JSON parser, JCS-style canonical
  serializer, Ed25519 verification (via `@noble/curves`), key/artifact manifest
  logic, revocation classification, and buyer-binding checks. Verifier-only:
  it reads and validates receipts, never issues, signs, or mutates them.

[0.1.2]: https://github.com/SVM-98/attest/releases/tag/v0.1.2
[0.1.1]: https://github.com/SVM-98/attest/releases/tag/attest-verifier-v0.1.1
[0.1.0]: https://github.com/SVM-98/attest/releases/tag/attest-verifier-v0.1.0
