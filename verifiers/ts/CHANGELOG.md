# Changelog

All notable changes to `attest-verifier` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The TypeScript verifier treats an absent key-entry `valid_to` as open-ended, matching the Python reference; spec §7.1 now clarifies `valid_to` is optional.

### Added

- v0.2 hybrid Ed25519+ML-DSA-65 signature profile (`attest_version: "0.2"`):
  `verify()` accepts a two-signature hybrid envelope (`[Ed25519, ML-DSA-65]`,
  fixed order, shared `kid`), verifying both legs over the same
  `JCS(payload)` bytes with AND semantics — either leg failing invalidates
  the receipt. Composite key binding lives in the key manifest (`pub` +
  new `pub_ml_dsa_65`); a hybrid signer's `manifest_signature` gains
  `sig_ml_dsa_65`, AND-verified, fail-closed both ways. ML-DSA-65
  verification uses `@noble/post-quantum` (verify-only leg, no secret keys
  in this package). v0.1 receipts remain valid and verifiable forever; a
  v0.1-only build MUST reject a v0.2 envelope outright. New public spec:
  [`docs/spec/attest-v0.2.md`](../../docs/spec/attest-v0.2.md). New
  conformance leaf group `26-hybrid` (8 leaves).

- v0.2 Stage 2 verification — transparency and anchoring evidence, verify-only
  as everything in this package is. `verify()` gains a sixth `options` argument
  (`transparency`, `logKeys`, `anchorPolicy`); omit it and behaviour is
  unchanged, offline and log-free. Inclusion evidence is checked against a
  hybrid-signed checkpoint and reported as `transparency` / `corroboration`,
  which never upgrade the `trust` verdict — corroboration is not authenticity.
  Log keys come from the caller's pinned trust store, never from the bundle.
  Anchors: OpenTimestamps (required for post-horizon standing) and RFC 3161
  (classical convenience, no weight past a configured CRQC horizon). New
  modules `src/transparency.ts`, `src/tlog.ts`, `src/anchor.ts`. New conformance
  leaf groups `27-valid-to-absent` and `28-transparency`, bringing the corpus
  this package runs to 66 leaves across 29 groups.

## [0.4.0] — 2026-07-23

### Added

- **v0.2 Stage 3 — issuer-mediated transfer** (`docs/spec/attest-v0.2.md` §17) verify-only
  parity: `src/transfer.ts` builds the same transfer-record verification, holder-authorization
  check, and log-required honoring (consent gate) as the Python reference, over the
  identical closed six-field record profile and `Attest-transfer-authorization-v1`
  domain-separated preimage. `verify()` reports the new reachable `revocation:
  "transferred"` value, capping `ok` the same way `"revoked"` already does, honored for
  every `license.revocability` class once backed by an authenticated
  `holder_authorization` and a logged inclusion proof; unlogged, double-assigned
  (earliest-index-wins), and not-yet-transferable claims resolve to the same warning
  literals as the Python reference (`transfer_record_unlogged`,
  `transfer_double_assignment_conflict`, `transfer_not_yet_transferable`). A separate
  `auditChain` surface walks a whole chain of transfers independent of single-receipt
  `verify()`. A v0.2 receipt with `license.transferable: true` and a null/absent
  `buyer.pubkey` is now a schema error (v0.1 receipts untouched). Closed a
  Python/TypeScript parity divergence in Stage 3 date validation during review. New
  conformance leaf groups `35-transfer` (10 leaves) and `36-transfer-chain` (3 leaves),
  bringing the corpus this package runs to 95 leaves across 36 groups.

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
