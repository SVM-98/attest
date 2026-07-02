# OPR v0.1 conformance vectors

This directory holds the OPR v0.1 conformance suite: fixed, language-neutral test cases against which any implementation of [`docs/spec/opr-v0.1.md`](../opr-v0.1.md) can be checked. Each vector is a leaf directory (identified by containing `expected.json`) holding the raw inputs to feed the verification algorithm and the exact `VerificationResult` a conformant verifier must produce.

**Normative conformance requirement**: an implementation is OPR-conformant iff it produces every vector's expected result. There is no partial conformance — any single mismatch is a conformance failure.

## Vector format

Each leaf directory contains:

- `payload.json` — the receipt payload, for readability (not itself fed to `verify()`; it is embedded inside `envelope.json`).
- `envelope.json` — the full envelope (`payload` + `signatures` + optional `delivery`), or `envelope.raw.json` (vector 06 only) for a case whose raw bytes intentionally cannot round-trip through a parsed object.
- `manifests.json` — the trust material: `{"manifests": {...}, "provenance": {...}, "chains": {...}}`, fed straight into the verifier's trust store.
- `expected.json` — the spec-intended `VerificationResult`: `signature`, `schema`, `trust`, `revocation`, `binding`, `ok`, plus `errors`/`errors_contains` and `warnings`/`warnings_contains`.
- optional `disclosure.json` — a buyer-binding disclosure, salt path (`identifier`, `identifier_type`, `salt_b64u`) or challenge path (`nonce_b64u`, `sig_b64u`), for vectors that check §6 step 7.
- optional `revocation.json` — a single issuer-signed revocation record, fed to the verifier as its revocation view, for vectors that check §6 step 6.
- optional `manifest_pristine.json` — only for vector 11: the untampered, self-consistent manifest, alongside the tampered one actually used for verification.

## Vector index

### 1–11: format and crypto

| # | Name | Checks |
| --- | --- | --- |
| 01 | `valid-minimal` | The happy path: a minimal, schema-valid, correctly-signed receipt verifies clean. |
| 02 | `valid-full` | Every optional payload field populated at once (edition, artifacts, refund-window revocability, DRM-bound, jurisdiction flags, escrow end-of-life, supersedes, buyer pubkey) still verifies clean. |
| 03 | `tampered-payload` | A single byte flipped in a signed field, post-signing — signature must fail. |
| 04 | `wrong-key` | Signed by a key whose `kid` domain matches the issuer but is absent from the trusted manifest — rejected at the key-resolution step, not the domain-match step. |
| 05 | `issuer-mismatch` | A genuinely valid signature by a different domain's key over a payload claiming a different `issuer.id` — must never validate (kills cross-issuer impersonation). |
| 06 | `duplicate-key-reject` | A raw envelope with a genuinely duplicated JSON object member — rejected at strict parsing (RFC 8785 forbids duplicate members), before any issuer/key resolution. |
| 07 | `unicode-canon` | (a) NFD-decomposed Unicode in a payload string, plus an integer at the exact I-JSON safe-range boundary, both accepted and signed/verified byte-exact (no silent NFC normalization outside the buyer-commitment path). (b) The same integer field bumped one past the safe boundary — rejected, because canonicalization (required before any signature check) fails first. |
| 08 | `sig-malleability` | A signature's `S` component re-encoded as `S + L` (same scalar mod the curve order) — the pinned Ed25519 ruleset must reject the non-canonical encoding (SUF-CMA). |
| 09 | `commitment` | Buyer-binding commitment recomputation across three identifier shapes: (a) plain ASCII email, (b) non-ASCII/Unicode email, (c) issuer-account identifier with NFD input — normalization must be applied identically at issuance and at verification. |
| 10 | `unknown-field` | An unrecognized top-level payload field is signed and carried through verification successfully, with a non-fatal warning (forward-compatibility). |
| 11 | `manifest-tamper` | A key manifest's `status` flipped from `active` to `compromised` after the manifest itself was signed — the manifest no longer self-verifies, and a receipt genuinely signed while the key was active is now rejected because the trust store's copy says `compromised`. |

### 12–18: lifecycle and policy

| # | Name | Checks |
| --- | --- | --- |
| 12 | `retired-key-ok` | A receipt signed while a key was active still verifies once that key is later marked `retired` in the trust-store manifest — with a warning, not a rejection. |
| 13 | `compromised-key` | A receipt signed by a key now marked `compromised` in an otherwise self-consistent manifest is rejected unconditionally, regardless of `issued_at`. |
| 14 | `rotation-continuity` | A two-manifest chain (v1 → v2) where v2 is signed by v1's own active key, introducing a new active key and retiring the old one — the standard rotation handoff. A receipt signed by the new key resolves against the current manifest and keeps full (TLS-derived) trust. |
| 14b | `rotation-discontinuous` | Same v1 root, but the candidate v2 is signed by a key never listed in v1 at all — the chain is discontinuous, so trust is forced down to `unverified_rotation` even though the receipt's own signature verifies cleanly against the current manifest. |
| 15 | `revoked-policy` | A `revocability: "policy"` receipt plus an authenticated, matching revocation record is honored as-is: `revocation: "revoked"`, `ok: false`. |
| 16 | `revocation-against-none-ignored` | The irrevocability guarantee: a `revocability: "none"` receipt plus an authenticated, matching revocation record ignores the record (`invalid_revocation_ignored`) and stays `ok: true` — a revocation feed can never override an irrevocable license. |
| 17 | `binding-proven` | Both buyer-binding proof paths: (a) salt disclosure recomputing the commitment, (b) pubkey challenge-response — a signed transcript proving key possession without revealing an identifier. |
| 18 | `drm-bound` | `license.drm == "drm-bound"` verifies green but always carries a mandatory warning — a receipt never claims to remove DRM. |

## Regeneration

The vectors are generated deterministically by [`tools/gen_vectors.py`](../../../tools/gen_vectors.py): every keypair, salt, timestamp, and ULID randomness source is a fixed constant (no wall-clock reads, no CSPRNG). Running

```sh
.venv/bin/python tools/gen_vectors.py
```

twice must produce byte-identical output — `git diff --exit-code docs/spec/vectors` after a second run is the determinism gate. `tests/test_vectors.py` replays every vector against the reference implementation and asserts the produced `VerificationResult` matches `expected.json` exactly.
