# Changelog

All notable changes to `attest-receipts` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The TypeScript verifier treats an absent key-entry `valid_to` as open-ended, matching the Python reference; spec §7.1 now clarifies `valid_to` is optional.

### Added

- v0.2 hybrid Ed25519+ML-DSA-65 signature profile (`attest_version: "0.2"`):
  envelopes carry exactly two signatures, in fixed order `[Ed25519, ML-DSA-65]`,
  both over the same `JCS(payload)` canonical bytes and sharing one `kid`.
  Composite key binding lives in the key manifest (`pub` + new
  `pub_ml_dsa_65`), never in `kid`; a hybrid signer's `manifest_signature`
  itself must carry both a `sig` and a new `sig_ml_dsa_65`, AND-verified,
  fail-closed both ways. Verification is AND semantics: both legs must verify
  or the receipt is rejected. v0.1 receipts remain valid and verifiable
  forever; a v0.1 verifier MUST reject a v0.2 envelope outright (no downgrade
  path). New public spec: [`docs/spec/attest-v0.2.md`](docs/spec/attest-v0.2.md).
  New conformance leaf group `26-hybrid` (8 leaves).

- v0.2 Stage 2 — issuer key transparency and timestamp anchoring, as a
  **corroboration** layer. What it proves is inclusion in a log-signed Merkle
  root: a verifier checks a hybrid-signed checkpoint plus an inclusion proof, and
  anchoring can additionally bound when that checkpoint existed. It can never
  make an unsigned or untrusted artifact look authentic — the `verified` trust
  result stays what it always was, domain control, and inclusion evidence
  surfaces separately as `transparency` / `corroboration` so the two claims
  cannot be confused.

  What it does **not** provide, stated in the spec itself (§10.4, §13) and worth
  repeating here: without witness cosignatures there is no anti-equivocation. An
  unwitnessed log operator can maintain split views indefinitely, and a verifier
  detects equivocation only when it already holds two inconsistent validly-signed
  checkpoints. `corroboration: "witnessed"` — the verdict that closes this — needs
  a witness federation that does not exist yet.

  Substrate is a static C2SP tlog-tiles log; checkpoints carry hybrid Ed25519 +
  ML-DSA-65 signatures on both cores. Two anchor kinds: OpenTimestamps, required
  for any **post-horizon** standing, and RFC 3161, accepted as a classical
  convenience that carries no weight past a configured CRQC horizon. The receipt
  commitment covers the signed-receipt core — `JCS(payload)` and `JCS(signatures)`
  under a domain separator — so it binds the signature bytes, not the payload
  alone. Log keys are pinned in the verifier's own trust store and rotated
  out-of-band; the mandatory gapless rotation chain is a rule about **issuer key
  manifests** above version 1, not about log keys. Sibling patch shipped with it:
  revocation records and artifact manifests carry hybrid signatures too, closing
  the window where they were Ed25519-only and forgeable once a cryptographically
  relevant quantum computer exists. New conformance leaf groups
  `27-valid-to-absent` and `28-transparency`.

- Conformance corpus grown to **66 leaf vectors across 29 groups**, from 43 at
  0.1.2. Both implementations reproduce every one, with none skipped. Note the
  corpus is no longer a v0.1 corpus: the 43 leaves at 0.1.2 are v0.1 conformance,
  and the 23 added since exercise v0.2 behaviour a v0.1-only verifier is required
  to reject.

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
