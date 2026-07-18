# attest v0.2 — Normative Specification Delta: Hybrid Signature Profile, Transparency, and Anchoring

- **Status**: Normative, v0.2 (Stage 1 AND Stage 2 — see §1 Scope; Stage 2b witness federation remains forthcoming, §15)
- **Date**: 2026-07-18
- **Grounding**: this document is grounded in the reference implementation in `src/attest/` (`verify.py`, `pq.py`, `manifests.py`, `tlog.py`, `anchor.py`, `transparency.py`, `bundle.py`, `cli.py`, `revocation.py`) and the conformance vectors in [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) and [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/). It introduces no design decision not already present in the shipped implementation and its conformance corpus (repo rule: spec-follows-implementation).
- **Companion artifacts**: [`docs/spec/attest-v0.1.md`](attest-v0.1.md) (the base specification this document extends — read together, never in isolation); conformance vectors — [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/), [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/), and [`docs/spec/vectors/README.md`](vectors/README.md) (per-group vector index).

This document uses the same conformance language as v0.1 §1 (RFC 2119/RFC 8174 key words, non-normative notes carry no conformance weight).

## 1. Status and scope

attest v0.2 is **additive**: every v0.1 receipt, key manifest, and revocation record remains valid and verifiable forever, under the v0.1 rules, with no expiry. This document does not revise, deprecate, or restrict anything in v0.1 — it defines a second, parallel signature profile selected by the payload's own `attest_version` field.

**No downgrade path.** `attest_version` is INSIDE the signed payload (v0.1 §5.1), so a receipt's version is itself signed and cannot be stripped or rewritten without invalidating the signature. A v0.1 verifier supports only `attest_version: "0.1"` (v0.1 §11 step 1) and MUST reject any `"0.2"` envelope outright, exactly as it would reject any other unsupported version string — there is no compatibility shim and none is planned. Conversely, a v0.2 verifier supports both `"0.1"` and `"0.2"` and dispatches on that field alone, never on `signatures[].alg` (v0.1 §4.1's dispatch prohibition extends unchanged to v0.2).

**This document specifies Stage 1 (§2–§6, the hybrid Ed25519+ML-DSA-65 signature profile) and Stage 2 (§7–§16, transparency logging, hybrid checkpoints, anchoring, and the `transparency`/`corroboration`/`manifest_freshness` result components).** Stage 2 is additive over Stage 1 exactly as Stage 1 is additive over v0.1: it introduces new, purely informational result components (§10) and never changes `signature`, `schema`, `revocation`, `binding`, or the `ok` predicate for any receipt. A verifier that implements only Stage 1 remains fully conforming for everything Stage 1 specifies; it simply never populates the Stage 2 fields (they default to their zero-behavior-change stub values, §10).

Stage 2 does **not** deliver full anti-equivocation. §15 states this as a normative limitation: detecting two inconsistent signed checkpoints for the same log (`equivocation_detected`, §10.3) is a hard verdict this stage does implement, but *ruling out* equivocation in the general case requires an independent witness quorum, which this stage defines the wire format for (`corroboration: "witnessed"`, C2SP tlog-cosignature compatible) but does not deliver — that is Stage 2b, a federation/ops effort, not a format change. A conforming Stage 2 implementation MUST NOT report `corroboration: "witnessed"` before Stage 2b witness federation exists.

Issuer-mediated transfer records (a new record type giving real meaning to the reserved `license.transferable` field) remain **forthcoming** in a later v0.2 revision of this document and are unaffected by anything in §7–§16.

## 2. The hybrid signature profile (`ed25519+ml-dsa-65`)

### 2.1 Rationale

**Non-normative note:** the classical leg (Ed25519, mature, constant-time reference implementations) covers today's relative immaturity of production PQ signature implementations; the post-quantum leg (ML-DSA-65, FIPS 204) covers a future cryptographically-relevant quantum computer (CRQC). Forging a v0.2 receipt requires breaking **both** primitives — an attacker who breaks only Ed25519 (e.g. via a CRQC) or only ML-DSA-65 (e.g. via a classical cryptanalytic advance) still cannot forge a signature. ML-DSA-65 is NIST security category 3, chosen because it matches the pairing used by `draft-ietf-lamps-pq-composite-sigs` (MLDSA65-Ed25519), maximizing future interoperability with that emerging composite-signature standard.

### 2.2 Envelope structure

A v0.2 hybrid envelope has the same three-member shape as a v0.1 envelope (`payload`, `signatures`, optional `delivery`; v0.1 §4). The only differences are inside `payload.attest_version` and `signatures`:

- `payload.attest_version` MUST equal the literal string `"0.2"`.
- `signatures` MUST be a JSON array containing **exactly two** entries, in this **fixed order**:

```json
{
  "payload": { "attest_version": "0.2", "...": "..." },
  "signatures": [
    { "kid": "store.example.com/keys/2025-01#ed25519-1", "alg": "Ed25519", "sig": "<base64url, 64 bytes decoded>" },
    { "kid": "store.example.com/keys/2025-01#ed25519-1", "alg": "ML-DSA-65", "sig": "<base64url, 3309 bytes decoded>" }
  ]
}
```

- Entry 0 MUST have `alg == "Ed25519"`; entry 1 MUST have `alg == "ML-DSA-65"`. A verifier MUST reject any other order, count, or `alg` value.
- Both entries MUST carry the **same `kid`** — the hybrid pair is one signer, not two independently-resolved keys. The `kid` format is unchanged from v0.1 (`<issuer-domain>/keys/<label>#<name>`, v0.1 §7.1): `kid` is an operator-chosen string, never a hash, and it does not itself encode which algorithms are bound to it.
- Both signatures MUST be computed over the **same** `JCS(payload)` canonical bytes (v0.1 §9) — there is one signature input, signed twice with two different keys.

### 2.3 Composite key binding lives in the manifest, not the kid

Because `kid` carries no algorithm information, the binding between a hybrid signer's Ed25519 and ML-DSA-65 public keys is established entirely by the **key manifest** (v0.1 §7.1): a single key-entry object carries both public keys.

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `pub` | string, base64url, 32 decoded bytes | REQUIRED (unchanged from v0.1) | Ed25519 public key. |
| `pub_ml_dsa_65` | string, base64url, 1952 decoded bytes | REQUIRED for a hybrid signer's key entry; absent for an Ed25519-only entry | ML-DSA-65 public key. Its presence is what makes a key entry "hybrid": a verifier MUST NOT accept a v0.2 hybrid signature against an entry lacking `pub_ml_dsa_65` (§3, step 6). |

Mix-and-match across signers is structurally prevented: both legs of a hybrid signature resolve through the identical signed manifest key-entry (same `kid`, same lookup), so there is no way to pair one signer's Ed25519 key with a different signer's ML-DSA-65 key without also forging the manifest itself.

**Manifest signature must itself be hybrid for a hybrid signer.** A manifest's own `manifest_signature` (v0.1 §7.1) is extended with an optional second member:

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `manifest_signature.sig_ml_dsa_65` | string, base64url, 3309 decoded bytes | REQUIRED iff the manifest was signed by a key whose own entry carries `pub_ml_dsa_65` (i.e. the signer is hybrid); MUST be absent otherwise | ML-DSA-65 signature over the same `JCS(manifest)` (with `manifest_signature` removed) that the Ed25519 leg signs. |

This is **AND-verified, fail-closed in both directions**: a hybrid signer's manifest signature that is missing its `sig_ml_dsa_65` leg MUST be treated as invalid (a downgrade attempt — stripping the PQ leg to fall back to a break-one-primitive forgery), and an Ed25519-only signer's manifest signature that carries a stray `sig_ml_dsa_65` MUST likewise be treated as invalid (a manifest cannot claim hybrid protection for a key that never had a PQ public key). **Rationale:** without this rule, a future CRQC could forge a manifest *rotation* using only the broken classical primitive and thereby bypass the hybrid protection on every receipt the rotation vouches for — the manifest chain is exactly as strong as its weakest verified leg, so the manifest signature's strength MUST match the strength implied by the keys it lists.

### 2.4 Sizes and measured cost

**Measured 2026-07-17** (ML-DSA-65 / FIPS 204, NIST category 3), base64url-unpadded on the wire:

| Quantity | Raw bytes | b64u (no padding) |
| --- | --- | --- |
| Public key (`pub_ml_dsa_65`) | 1952 | 2603 |
| Secret key (not on the wire) | 4032 | — |
| Signature (`sig`, `sig_ml_dsa_65`) | 3309 | 4412 |

A hybrid receipt and its manifest total roughly 13–14 KB (about 6 KB for the envelope plus 8 KB for the manifest, b64u overhead included) — larger than a v0.1 receipt (a few hundred bytes) but still an acceptable size for a signed receipt document, not a constrained protocol frame.

## 3. Verification algorithm — v0.2 hybrid path

A v0.2-capable verifier executes v0.1 §11's algorithm with the hybrid path substituted for §11 steps 1 and 4 whenever `payload.attest_version == "0.2"`; steps 0 (preconditions), 2 (issuer binding), 3 (key checks), 5 (schema), 6 (revocation), and 7 (binding) are unchanged from v0.1 and are not restated here. Every step below fails closed: any rejection sets `signature: "invalid"` and short-circuits (v0.1 §11's short-circuit rule applies unchanged — `revocation` and `binding` take their stub values `"unknown"`/`"not_checked"`, and `schema` takes `"not_checked"`, whenever a step upstream of schema validation rejects). This is **AND semantics**: both legs must independently verify, or the receipt is invalid.

The reference implementation (`src/attest/verify.py`) executes these checks in exactly this order:

1. **Signature count.** `signatures` MUST have length exactly 2. Otherwise: `hybrid envelope requires exactly two signatures`.
2. **Signature-block structure.** Both entries MUST be objects. Otherwise: `malformed signature block`.
3. **Alg and order.** Entry 0's `alg` MUST equal `"Ed25519"` and entry 1's `alg` MUST equal `"ML-DSA-65"`. Otherwise: `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order`.
4. **Shared kid.** Both entries' `kid` values MUST be identical. Otherwise: `hybrid envelope signatures must share a single kid`.
5. **Kid type.** The shared `kid` MUST be a string. Otherwise: `malformed signature block: 'kid' must be a string`.
6. **Signature type.** Both entries' `sig` values MUST be strings. Otherwise: `malformed signature block: 'sig' must be a string`.
7. **Issuer binding** (shared with v0.1 §11 step 2, unchanged): resolve the manifest for `payload.issuer.id`; the shared `kid`'s DNS-domain prefix and the manifest's own `issuer` field MUST both equal `payload.issuer.id`.
8. **Key checks** (shared with v0.1 §11 step 3, unchanged): the key entry MUST be present in the resolved manifest, MUST NOT be `status == "compromised"` (unconditional, v0.1 §7.3), and `payload.issued_at` MUST fall within the key's `[valid_from, valid_to]` window; a `"retired"` key still verifies, with a warning.
9. **Hybrid key-entry requirement.** The resolved key entry MUST carry `pub_ml_dsa_65`. Otherwise: `key entry for kid {kid!r} has no ML-DSA-65 public key`.
10. **Ed25519 leg.** `Ed25519.verify(JCS(payload), sig_0, pub)` under the v0.1 §10 pinned ruleset, over the same canonical bytes computed once for both legs. Otherwise: `signature verification failed`.
11. **ML-DSA-65 leg.** `ML-DSA-65.verify(JCS(payload), sig_1, pub_ml_dsa_65)`. Otherwise: `ML-DSA-65 signature verification failed`.

Only if both legs (steps 10 and 11) verify does the algorithm continue to v0.1 §11 steps 5–7 (schema, revocation, binding) unchanged.

### 3.1 Error-literal table (verbatim)

A conforming implementation SHOULD surface these exact strings (or a superset containing them, e.g. via `errors_contains` in the conformance harness) so that cross-implementation conformance testing can match on literal text:

| Literal (verbatim) | Emitted when |
| --- | --- |
| `hybrid envelope requires exactly two signatures` | `signatures` length ≠ 2. |
| `malformed signature block` | either signature entry is not an object. |
| `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order` | entry 0/1 `alg` is not exactly `["Ed25519", "ML-DSA-65"]` in that order (includes a duplicated `alg`). |
| `hybrid envelope signatures must share a single kid` | the two entries' `kid` values differ. |
| `malformed signature block: 'kid' must be a string` | the shared `kid` is not a string. |
| `malformed signature block: 'sig' must be a string` | either signature entry's `sig` is not a string. |
| `key entry for kid {kid!r} has no ML-DSA-65 public key` | the resolved manifest key entry lacks `pub_ml_dsa_65`. |
| `signature verification failed` | the Ed25519 leg fails to verify (unchanged literal from v0.1). |
| `ML-DSA-65 signature verification failed` | the ML-DSA-65 leg fails to verify. |

Result vocabulary (`signature`, `schema`, `revocation`, `binding`, `trust`) and the `ok` predicate are unchanged from v0.1 §11.1 — v0.2 introduces no new result values, only new ways to arrive at `signature: "invalid"`.

## 4. Manifest continuity and trust

Rotation continuity (v0.1 §7.3) is unchanged in mechanism — a manifest at `manifest_version` N+1 is auto-trusted only if signed by a key `active` in the version-N manifest already trusted — but for a **hybrid signer**, that continuity check is enforced through the hybrid manifest signature (§2.3): a candidate rotation manifest whose signer key is hybrid but whose `manifest_signature` has been **downgraded** to an Ed25519-only signature (missing `sig_ml_dsa_65`) fails the AND-verified manifest-signature check and is therefore treated as **not validly signed by that key** for continuity purposes — the chain is discontinuous at that point, and the verifier MUST report `trust: "unverified_rotation"` (v0.1 §11.1) exactly as it would for any other discontinuous rotation, even though the receipt's own hybrid signature (§3) may independently verify cleanly against the manifest in use.

The **single-manifest, un-rotated receipt path** — a bare envelope plus a directly-trusted manifest, with no rotation chain in play — is unaffected by this: it continues to follow the existing v0.1 TOFU model (v0.1 §7.4) unchanged. `trust` is `verified` if the manifest was obtained over TLS from the issuer's own domain, `unauthenticated_tofu` otherwise; the hybrid manifest-signature requirement (§2.3) governs whether the manifest itself is accepted as self-consistent, not whether the verifier's *provenance* for that manifest is upgraded.

## 5. Worked example (vector `26-hybrid/a-valid-hybrid`)

Trimmed payload (`attest_version: "0.2"`, otherwise an ordinary `revocability: "none"` receipt):

```json
{
  "attest_version": "0.2",
  "issuer": { "id": "store.example.com", "display_name": "Example Games Store" },
  "issued_at": "2025-07-02T13:50:00Z",
  "receipt_id": "01JZ5PDHT0000G40R40M30E209",
  "license": { "grant": "perpetual", "revocability": "none", "drm": "drm-free", "...": "..." },
  "work": { "title": "Example Game", "publisher": "Example Publisher srl", "...": "..." }
}
```

Envelope — the two-entry hybrid `signatures` array, both entries sharing one `kid` (sizes are illustrative — see §2.4 for the exact byte counts; a full ML-DSA-65 signature is thousands of base64url characters):

```json
{
  "payload": { "attest_version": "0.2", "...": "..." },
  "signatures": [
    { "alg": "Ed25519",   "kid": "store.example.com/keys/2025-01#ed25519-1", "sig": "_srp5DTeCSCG...LsifBQ" },
    { "alg": "ML-DSA-65", "kid": "store.example.com/keys/2025-01#ed25519-1", "sig": "JIuyB18NYaoD...GAh0i" }
  ]
}
```

Key manifest — one key entry carrying both public keys, and a manifest signature carrying both legs:

```json
{
  "issuer": "store.example.com",
  "manifest_version": 1,
  "keys": [
    {
      "kid": "store.example.com/keys/2025-01#ed25519-1",
      "pub": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
      "pub_ml_dsa_65": "LQ5NxHed2F9hW-FOSlutPO5NE3XAARBF5HkSLNPmaHbOL_QrOQ...5nwRmal-cfm5TeRwhXxlyrQtEsFBwGiAdsDsRZKKjNF",
      "status": "active",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_to": null
    }
  ],
  "manifest_signature": {
    "kid": "store.example.com/keys/2025-01#ed25519-1",
    "sig": "frfQdQJAQbNuZC7bB24_pI_OJvkEIa--F4f5-QLeEYLsFSG5TP8XcQosgSUxebwNf3ZKgh73TDoRGrsKByhcAg",
    "sig_ml_dsa_65": "OGGEM4MjqPb1FeUrVH1AG0lQi_ewMS_Jijhs8gyDz01U4EjeKSTZgrc2Ufcd5JNKa5ktNdGHMTSy8Xg5d7WWNm93yV...jqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAggSFh0i"
  }
}
```

Against this manifest, both signature legs of the envelope above verify (§3 steps 10–11), yielding `signature: "valid"`, `schema: "valid"`, `trust: "verified"`, `ok: true` — the same layered `VerificationResult` shape v0.1 §11.1 defines, unchanged.

## 6. Conformance

The conformance leaf group [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) adds 8 leaves (a–h) to the existing 43 v0.1/cross-implementation leaves, for 51 total. Each leaf is checked against all three conformance runners (Python reference, TypeScript verifier, and the web verifier where applicable) from the same shared golden files, exactly as the v0.1 corpus is (v0.1 §15).

| Leaf | Checks |
| --- | --- |
| `a-valid-hybrid` | The happy path worked in §5: both legs verify, `ok: true`. |
| `b-ed25519-leg-tampered` | Entry 0's signature bytes flipped post-signing → `signature verification failed`, `signature: "invalid"`. |
| `c-mldsa-leg-tampered` | Entry 1's signature bytes flipped post-signing → `ML-DSA-65 signature verification failed`, `signature: "invalid"`. |
| `d-mldsa-leg-missing` | The ML-DSA-65 entry stripped, leaving only the Ed25519 leg → `hybrid envelope requires exactly two signatures`, `signature: "invalid"` (a stripped PQ leg is not a valid v0.1-shaped fallback; it is rejected outright). |
| `e-duplicate-ed25519-alg` | Both entries carry `alg: "Ed25519"` → `hybrid envelope requires algs Ed25519 and ML-DSA-65 in order`, `signature: "invalid"`. |
| `f-kid-mismatch-between-legs` | The two entries carry different `kid` values → `hybrid envelope signatures must share a single kid`, `signature: "invalid"`. |
| `g-key-entry-not-hybrid` | The resolved manifest key entry has no `pub_ml_dsa_65` → `key entry for kid {kid!r} has no ML-DSA-65 public key`, `signature: "invalid"`. |
| `h-manifest-downgraded-continuity` | A rotation candidate manifest signed by a hybrid key but with its `manifest_signature` downgraded to Ed25519-only (§4) → the receipt's own hybrid signature still verifies (`signature: "valid"`, `ok: true`), but `trust: "unverified_rotation"`, because the manifest signature itself failed the hybrid AND-check and the rotation chain is therefore discontinuous. |

### 6.1 Vector determinism and cross-implementation parity

**Non-normative note:** the 26-hybrid vectors are generated deterministically by [`tools/gen_vectors.py`](../../tools/gen_vectors.py), the same generator and the same determinism gate as the v0.1 corpus (v0.1 §15 / [`docs/spec/vectors/README.md`](vectors/README.md) "Regeneration"). ML-DSA-65 keys and signatures are produced with the dev-only oracle `dilithium-py` (`ML_DSA_65.key_derive(seed)` from a committed fixed seed, `sign(sk, m, deterministic=True)` per the FIPS 204 deterministic variant) — reproducible byte-for-byte, never used at verification runtime in either production package. At runtime, `pqcrypto` (Python, PQClean-derived) and `@noble/post-quantum` (TypeScript) independently verify the same vectors, so cross-implementation parity is exercised by the corpus itself rather than by a separate parity harness.

## 7. Stage 2 architecture and substrate

### 7.1 The corroboration thesis

**Non-normative note:** a transparency log proves *existence* and, with a witness quorum, *append-only history* — never *domain control*. attest key manifests are self-signed (v0.1 §7.1) and a log is an open-ingestion host, so "this manifest is in the log" says nothing by itself about who controls issuer X's domain. Stage 2 therefore introduces the log as a **corroboration layer**, orthogonal to `trust`, never a replacement for it (§10). `trust: "verified"` continues to require an independent domain-control root (a TLS fetch from the issuer's own domain, v0.1 §7.4, unchanged); a log-corroborated manifest with no such root stays `unauthenticated_tofu`.

### 7.2 Log substrate: a documented C2SP tlog-tiles subset

A conforming Stage 2 log is a static, mirrorable file set following the shape of [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) (RFC 6962 Merkle tree, SHA-256 leaf/interior hashing, §7.1's tiles carry leaf hashes, a signed-note checkpoint attests to the tree root) — with one documented, honest subset of the full C2SP profile, matching the reference layout (`src/attest/cli.py`, module-level `attest log` on-disk layout comment):

- **`entries.jsonl` is the SOLE source of truth.** One JSON entry object per line, append-only. Every other on-disk artifact is derived from it: tiles, the RFC 6962 tree root, and the unsigned checkpoint candidate are recomputable from `entries.jsonl` alone by re-running RFC 6962 `MTH` (v0.1's Merkle build, `tlog.build_tree`) over the re-encoded entries. The signed checkpoint's note body is likewise recomputable, but producing its signatures requires the ceremony-side private keys.
- **Level-0 (leaf-hash) tiles only.** A full C2SP tlog-tiles deployment materializes interior-level cache tiles as a read-amplification optimization for very large logs. A conforming Stage 2 log MAY materialize only level-0 tiles (leaf hashes, `_TILE_FULL_WIDTH = 256` leaves per full tile) and MUST always recompute the tree root from the entries list directly rather than trusting a cached interior tile — this is a documented, intentional subset, not full C2SP tlog-tiles.
- **Partial-tile naming is flattened.** A not-yet-full tile at the growing right edge of the log is named `<index>.p.<width>` — a flattened stand-in for C2SP's nested `<index>.p/<width>` directory form. The nested form exists in the C2SP spec purely to keep tile URLs short at huge scale; this document's flattened form is equivalent content addressed differently, and is what a conforming implementation MUST produce and accept.

A conforming implementation MUST fully rebuild its tile cache from `entries.jsonl` on every append (never patch a tile incrementally). The tile cache carries no authority: signing and proof generation MUST recompute from `entries.jsonl` and MUST NOT consult tiles.

### 7.3 Log key custody: the offline-signer split

Log signing keys are held offline (HSM/ceremony), never by the CI or serving process that appends entries (design doc "Log key custody: offline/HSM ceremony, never CI"). A conforming Stage 2 log implementation MUST split the append and sign responsibilities into two separately-administered steps:

1. **`log append` (CI-side).** Validates and appends one new entry to `entries.jsonl`, rebuilds the level-0 tile cache, recomputes the tree root, and writes an **UNSIGNED** checkpoint candidate (origin, decimal tree size, base64 root — the same three header lines a signed checkpoint's note body carries, §9.1 — with no signature lines at all; this is genuinely unsigned, not a signed note with an empty signature list, which the checkpoint grammar rejects outright, §9.1). This step holds no signing key material of any kind.
2. **`log sign-checkpoint` (ceremony-side).** The ONLY step that may hold the log's Ed25519/ML-DSA-65 secret keys. It MUST independently recompute the tree root from `entries.jsonl` (never trust the candidate's claimed root) and refuse to sign unless that recomputation matches the candidate exactly; if a checkpoint was previously signed for this log, it MUST additionally verify the new tree is a valid RFC 6962 consistency-proof extension of the prior signed tree (v0.1's `tlog.verify_consistency`) before signing a successor. Both checks are against the log's own authoritative on-disk state, never against which flags were passed on the command line.

This split is what makes the log's signing key operationally independent of the (comparatively higher-exposure) ingestion path — an attacker who compromises the CI-side append step obtains no signing capability at all, only the ability to propose entries a separately-administered signer may refuse.

Pinned log keys (§9.2 `LogKey`) ship baked into the verifier's own trust store, distributed and rotated out-of-band from any bundle. A conforming verifier MUST NOT take log keys from a bundle: bundle-embedded key material is untrusted and is never a trust root.

## 8. Log entry schemas

Every entry admitted to the log is a CLOSED, versioned, JCS-canonicalized object (`tlog.encode_entry`): unknown members are rejected outright (no silent extension of a schema in production use — schema extension is a registry-governed change, out of this document's scope), and the canonical bytes produced are exactly what gets RFC 6962 leaf-hashed: `tlog.leaf_hash(entry_bytes) = SHA-256(0x00 || entry_bytes)`. Exactly two entry types are defined:

| Type | Members (exactly these, no more, no fewer) | Semantics |
| --- | --- | --- |
| `key-manifest` | `type` (`"key-manifest"`), `issuer` (lowercase DNS name, same shape as the receipt schema's `issuer.id`), `manifest_version` (int, `1 <= manifest_version <= 2**53 - 1`), `manifest_sha256` (64 lowercase-hex chars) | `manifest_sha256 = SHA-256(JCS(manifest))` — the hash of the manifest as it re-canonicalizes, not of any particular served byte stream (v0.2 §5's `manifest_sha256` domain, unchanged for Stage 2). |
| `receipt` | `type` (`"receipt"`), `issuer` (lowercase DNS name), `core_sha256` (64 lowercase-hex chars) | `core_sha256` is the **signed-receipt-core hash** defined in §12 — never a hash of `payload` alone. `issuer` here is a NON-AUTHENTICATED hint only, a convenience for log browsing/filtering; a conforming verifier MUST NOT read it as attribution — the receipt's own signature is what binds it to an issuer. |

An entry whose `type` is not one of these two, or whose member set is not exactly the required set, MUST be rejected by the log (never admitted) and, if encountered as evidence during verification, MUST resolve to `transparency: "not_checked"` (§10.2) rather than being partially trusted.

## 9. Checkpoints: the hybrid C2SP signed-note profile

### 9.1 An explicit carve-out: signed bytes are C2SP signed-note TEXT, not JCS

Every other signed artifact in this protocol (v0.1 payloads, v0.2 §2 envelopes, key manifests, artifact manifests, revocation records) is signed over `JCS(...)` canonical bytes. **Checkpoints are the one explicit exception**, by design, for Stage 2b witness compatibility: a checkpoint's signed bytes are the [C2SP signed-note](https://c2sp.org/signed-note) TEXT format — three ASCII header lines (`origin`, decimal `tree_size`, standard-base64 32-byte `root`), each newline-terminated, WITHOUT the blank line that separates the header from the signature lines that follow it (`tlog.Checkpoint.note_bytes` — "the three header lines... through their final newline, excluding the blank line"). This carve-out exists so a Stage 2 checkpoint is byte-for-byte a C2SP tlog-checkpoint note, interoperable with the wider C2SP witness ecosystem once Stage 2b federates independent witnesses (§15) — a JCS-wrapped checkpoint would not be.

A checkpoint's full serialized text is: the three header lines, a blank line, then one or more C2SP signature lines of the form `— <name> <base64(key-hash || signature)>` (an em dash U+2014, one space, key name, one space, standard base64 with padding). The whole text MUST end with a trailing newline. A conforming implementation MUST reject a checkpoint text that has any other shape (missing header line, missing blank-line separator, non-decimal tree size, a root that does not decode to exactly 32 bytes, zero signature lines, a malformed signature line) — see the literal-error table in §9.4.

### 9.2 Hybrid signature, mandatory

A checkpoint carries a **key-id** — a 4-byte prefix `SHA-256(name || "\n" || signature-type || pub)[:4]` (C2SP's key-hash convention) — and BOTH of the following signature legs, keyed by the same log key `name`:

- An **Ed25519** signature over `note_bytes`, using C2SP's assigned signature-type byte `0x01`.
- An **ML-DSA-65** signature over the same `note_bytes`, using signature-type `0xff` (C2SP's own extension mechanism — "signature types without an identifier byte assigned by this specification") followed by the identifier string `attest-ml-dsa-65`. This document REGISTERS INTENT for this type but it is NOT YET IN THE C2SP REGISTRY — a future single-byte assignment cannot collide with it, since it is namespaced under `0xff`. (Byte `0x06` was considered and rejected: the C2SP registry assigns `0x06` to a *timestamped ML-DSA-44 cosignature*, a different algorithm and a different note-signature shape than the plain ML-DSA-65 leg this document defines.)

Standing requires **BOTH** legs to independently verify against a pinned `LogKey`'s matching public key (fail-closed AND — mirrors `manifests.py`'s hybrid `manifest_signature` discipline, v0.2 §2.3). An Ed25519-only checkpoint — even one whose Ed25519 signature is genuinely valid — MUST NOT confer any `transparency`/`corroboration` standing (conformance vector 28c). A conforming verifier scans every signature line whose `name` matches the pinned key's `name`; a line whose key-hash prefix doesn't match either expected leg's prefix simply does not count toward that leg and scanning continues — a signed-note convention, not a fatal condition, since multiple parties (eventually including Stage 2b witnesses) may sign lines with different names in the same note.

### 9.3 Origin and key-name grammar: printable ASCII on both cores

Checkpoint `origin` and `LogKey.name` are each constrained to **non-empty printable ASCII**: `origin` to the range `0x20`–`0x7e` inclusive; `name` to `0x21`–`0x7e` inclusive and additionally forbidden from containing `+` (avoids ambiguity with C2SP's `+`-delimited note-signer conventions). This is a deliberate protocol decision, not an oversight: a `\p{}`-class Unicode grammar would drift between the Python and TypeScript runtimes' bundled Unicode Character Database versions, making acceptance version-dependent across the two conformance cores. Restricting to ASCII makes the grammar identical, forever, regardless of either runtime's Unicode table.

For the same reason, diagnostic rendering of untrusted origin/name/tree-size/signature-line values follows **Python `ascii()` per-character escape semantics on both cores**: printable ASCII passes through unchanged, and every other code point renders as `\xNN` (one byte, `< 0x100`), `\uNNNN` (BMP), or `\UNNNNNNNN` (astral). The reference implementations are `tlog.py`'s `_trunc_repr` (Python, calling `ascii()` directly) and `verifiers/ts/src/messages.ts`'s `pyStage2StringRepr` (TypeScript). The TypeScript `pyRepr` used by some checkpoint diagnostics has a known, non-normative quote-style deviation from Python `repr` for apostrophes and backslashes; it affects diagnostic text only, never parsing, acceptance, or verdicts.

### 9.4 Checkpoint error literals (verbatim)

| Literal (verbatim, `{...}` interpolated) | Emitted when |
| --- | --- |
| `checkpoint text must end with a newline` | checkpoint text is missing its trailing `\n`. |
| `checkpoint header must be followed by a blank line` | the line immediately after the 3 header lines is not empty. |
| `tree size must be ASCII decimal digits: {trunc}` | the tree-size header line is not pure ASCII decimal. |
| `tree size must not contain leading zeros: {trunc}` | the tree-size header line has a leading `0` with more than one digit. |
| `root must decode to 32 bytes, got {n}` | the base64-decoded root header is not exactly 32 bytes. |
| `malformed checkpoint signature line: {trunc}` | a signature line does not match `— <name> <base64>`. |
| `checkpoint origin {origin!r} != expected_origin {expected!r}` | the checkpoint's own origin disagrees with the caller's pinned expectation. |
| `checkpoint origin {origin!r} != log_key.origin {origin!r}` | the checkpoint's own origin disagrees with the pinned `LogKey`'s origin. |
| `checkpoint has no valid Ed25519+ML-DSA-65 signature pair for name {name!r}` | after scanning every signature line, at least one hybrid leg never verified. |

`{trunc}` denotes the `ascii()`-rendered, length-bounded value described in §9.3 (never the raw untrusted text). These literals are Python-side (`tlog.py`); `verifiers/ts/src/tlog.ts` renders the equivalent message with `pyRepr`/`truncRepr` for parity, matching the same substrings a conformance harness checks against.

## 10. Result contract: `transparency`, `corroboration`, `manifest_freshness`

Stage 2 adds three new, purely informational `VerificationResult` components (v0.1 §11.1's table gains three rows; none of the five original rows, nor `ok`, gain a new possible value). **The log NEVER upgrades `trust`, and these three components never affect `signature`, `schema`, `revocation`, `binding`, or `ok`** — this is Stage 2's central correctness property, not an incidental one (design doc: the log is a corroboration layer, not an authenticity layer). Their defaults (`not_checked` / `none` / `not_checked`) are the exact values every pre-Stage-2 caller already implicitly gets, so Stage 1 behavior is unchanged for any caller that never supplies transparency evidence.

### 10.1 Vocabulary

| Component | Allowed values |
| --- | --- |
| `transparency` | `not_checked` \| `logged` \| `anchored_before:<T>` \| `equivocation_detected` |
| `corroboration` | `none` \| `logged` \| `witnessed` |
| `manifest_freshness` | `not_checked` \| `verified_as_of:<N>` |

`anchored_before:<T>` concatenates the fixed prefix with `T`, an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) rendered from the anchor's pinned Bitcoin block-header time (§11). `verified_as_of:<N>` concatenates the fixed prefix with `N`, the checkpoint's own `tree_size` at the moment the claim was evaluated — a size, not a wall-clock time, since a manifest's freshness is bounded by log inclusion order, not by anchor time.

`corroboration: "witnessed"` requires a quorum of independent witness cosignatures on the checkpoint. **It is defined here but UNREACHABLE in Stage 2**: no witness-cosignature input exists anywhere on the evidence schema this stage implements (§10.2), and a conforming Stage 2 verifier MUST NOT emit it — only `"none"` and `"logged"` are reachable outcomes until Stage 2b stands up witness federation (§15). This is deliberate format-freezing, not an oversight: the checkpoint/verification wire contract is already C2SP tlog-cosignature-compatible so that Stage 2b is pure operations, no format change.

### 10.2 Evidence input and decision order

A verifier evaluates at most one untrusted **evidence bundle** per claim (`attest.transparency.evaluate_transparency`), shaped:

```json
{
  "entry": { "...": "the log entry the caller claims corroborates this artifact" },
  "leaf_index": 0,
  "tree_size": 1,
  "inclusion_proof": ["<64-hex-char>", "..."],
  "checkpoint": "<C2SP signed-note text, §9>",
  "prior_checkpoint": "<optional, C2SP signed-note text>",
  "consistency_proof": ["<64-hex-char>", "..."],
  "anchors": { "...": "optional anchor evidence, §11" }
}
```

`evidence` is entirely untrusted (it arrives from wherever the bundle was fetched — a log mirror, an anchor service, or an adversary) and evaluation NEVER raises because of anything in it; every failure degrades to `(transparency: "not_checked", corroboration: "none")` plus a warning naming the condition, except equivocation, which is its own hard verdict (§10.3). `log_keys`, `expected_origin`, `policy`, and `expected_entry` are the TRUSTED, verifier-config side of the call — computed by the caller from its OWN trusted artifacts (never read off the evidence itself, §12) — and a malformed one of these raises, since that signals a caller/configuration bug, not adversarial input.

A conforming implementation MUST evaluate the claim in this order:

1. **Entry validity and match.** `entry` MUST re-encode under the closed schema (§8) and MUST deep-equal the `expected_entry` the caller independently computed from the artifact actually being corroborated (never trust the evidence's own hash claims).
2. **Checkpoint verification.** Try every pinned `LogKey` sharing `expected_origin` (log keys may rotate) until one verifies the checkpoint per §9.2's hybrid AND rule; a checkpoint that verifies under none of them yields no standing.
3. **Inclusion.** The evidence's declared `tree_size` MUST equal the verified checkpoint's own `tree_size`, and the entry's leaf hash MUST verify (RFC 6962 §2.1.1) against the checkpoint's root at the declared `leaf_index`.
4. **Optional prior-checkpoint consistency.** If `prior_checkpoint` is present, it MUST itself verify under a pinned key, and its tree MUST be RFC 6962-consistent (§2.1.2) with the current checkpoint's tree. A validly-signed prior whose consistency check FAILS is proof the log signed two incompatible histories for the same origin — `transparency: "equivocation_detected"` (§10.3), a hard verdict that short-circuits every later step. A prior that does not itself verify, or that verifies with no consistency proof supplied, is fail-safe (not equivocation) and degrades to `not_checked`.
5. **Base standing.** `(transparency: "logged", corroboration: "logged")`.
6. **Optional anchor upgrade.** If `anchors` evidence is present, verify it (§11) against the same checkpoint; a PQ-surviving proof upgrades `transparency` to `anchored_before:<T>`.
7. **CRQC horizon gate.** If the verifier's policy declares a `crqc_horizon` and the anchor verdict (or its absence) does not pass it (§11.3), the WHOLE result caps back down to `(transparency: "not_checked", corroboration: "none")` — a checkpoint signature alone does not survive a declared post-quantum cutoff; only a PQ-surviving anchor dated strictly before the horizon does.

### 10.3 Equivocation

`transparency: "equivocation_detected"` is a HARD verdict (step 4 above): two validly hybrid-signed checkpoints for the same pinned origin that are not RFC 6962-consistent is conclusive proof the log signed two incompatible histories. This is the one Stage 2 verdict that is not "fail-safe degrade to not_checked" — it is a positive, actionable signal that MUST be surfaced, never silently absorbed into `not_checked`.

Detecting equivocation this way requires the verifier to already be in possession of BOTH checkpoints (typically because it, or a source it trusts, saw the log branch at two different points). Stage 2 provides no independent mechanism for DISCOVERING that a log has equivocated when the verifier has only ever seen one branch — that is exactly what an independent witness quorum (`corroboration: "witnessed"`, Stage 2b) is for (§15): anchors bound *time*, not *branching*, so a keyed log with no witnesses can in principle maintain parallel self-consistent branches forever without ever producing the two-checkpoint evidence this section relies on.

### 10.4 Freshness and the rotation-chain rule

A `key-manifest` claim that reaches `logged` or better additionally sets `manifest_freshness: verified_as_of:<tree_size>` — this proves the manifest existed, unmodified, as of that point in the log's history, and MUST NOT by itself be read as a claim about the key's CURRENT status: a later manifest version may have since marked the same key compromised.

If the claimed manifest's own `manifest_version` is greater than 1, `corroboration` is only honored (left at `logged`) when the verifier's OWN trust store independently holds a validated, gapless rotation chain from version 1 through that manifest (`_rotation_chain_verified` — deliberately STRICTER than the `trust: "unverified_rotation"` continuity check of v0.1 §7.3/v0.2 §4, which tolerates an absent chain as "nothing to validate"). Absent that chain, `corroboration` is forced back down to `none` with the warning `corroboration_requires_rotation_chain` (conformance vector 28h) — the log merely saying "this manifest existed" is not proof of a legitimate rotation history, only of publication; a verifier that has not independently validated every intermediate version cannot corroborate that the presented manifest is the legitimate head of its issuer's key history.

The transparency/corroboration verdict for a receipt is resolved BEFORE that receipt's own pass/fail verdict is known, and independently of it (`verify.py`'s `_evaluate_transparency_claim` runs unconditionally, early). This is deliberate: it is what lets conformance vector 28i demonstrate that a receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still honestly reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — corroboration can never rescue an otherwise-invalid receipt, because it was never given the chance to.

## 11. Anchoring: `AnchorPolicy`, OTS, RFC 3161, and the CRQC horizon

### 11.1 OpenTimestamps is the required post-quantum leg

An anchor proves a checkpoint existed no later than a fixed point in time, external to the log operator's own signing key. Two anchor kinds are defined:

- **`ots` (OpenTimestamps, REQUIRED for any post-horizon standing).** A hash-only Bitcoin block-header commitment: starting from `SHA-256(checkpoint.note_bytes)`, an op-chain of `sha256`/`append`/`prepend` operations is replayed and MUST land on the `header_merkle_root` of a Bitcoin block header **pinned, by header hash, in the verifier's own `AnchorPolicy.pinned_headers`** — never fetched live, never trusted from the untrusted evidence's own claimed header time. This is hash-based, not signature-based, and therefore PQ-surviving: no future cryptanalytic or quantum advance against a classical signature scheme un-anchors it.
- **`rfc3161` (OPTIONAL, classical convenience only).** An RFC 3161 timestamp token (a CMS/X.509 RSA/ECDSA signature) is accepted as OPAQUE classical corroboration — parsed only far enough to note its presence, never validated as a certificate chain — and carries the fixed warning `rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight`. An `rfc3161` proof alone sets `anchored: true` but NEVER sets `pq_surviving` and NEVER sets `anchored_before`: its own signature is exactly the kind of classical primitive a CRQC breaks, so it carries zero post-horizon evidentiary weight (conformance vector 28k).

`AnchorVerdict.anchored_before` is the MINIMUM pinned header time across every verified `ots` proof in the bundle (never a single timestamping authority's self-asserted `genTime`). `anchored_before:<T>` states that the checkpoint `note_bytes` existed at or before time `T`: it is an upper bound on the earliest provable existence time, not a lower bound. It appears only when at least one `ots` proof verifies. `AnchorPolicy` evaluates every verified, PQ-surviving `ots` proof with these min-over-proofs semantics; its two fields (`pinned_headers` and optional `crqc_horizon`) express no quorum requirement.

### 11.2 `AnchorPolicy`

```
AnchorPolicy {
  pinned_headers: { <64-hex header_hash>: PinnedHeader { header_hash, merkle_root, time } },
  crqc_horizon: <unix-seconds int> | null
}
```

`pinned_headers` is the verifier's own trust store of Bitcoin block headers — shipped with the verifier (or its trust-store update mechanism), never taken from a bundle; a proof naming a `header_hash` absent from this map contributes nothing. `crqc_horizon` is `null` by default ("no cutoff yet configured" — every PQ-anchored checkpoint passes unconditionally); once a verifier operator sets it, §10.2 step 7 gates every standing that would otherwise rest on it.

### 11.3 `passes_horizon`

A verdict passes the horizon iff `policy.crqc_horizon is None`, OR the verdict is PQ-surviving (`pq_surviving == true`) AND its `anchored_before` is strictly less than `crqc_horizon`. An `rfc3161`-only verdict (`pq_surviving == false`) never passes a configured horizon, regardless of how early its claimed time is — consistent with §11.1: a classical timestamp is exactly the kind of evidence a CRQC horizon exists to stop trusting.

## 12. The signed-receipt-core commitment

A `receipt` log entry (§8) commits to the **signed-receipt-core**, not to `payload` alone:

```
receipt_core_hash = SHA-256("attest-receipt-core-v1" || 0x00 || JCS(payload) || 0x00 || JCS(signatures))
```

rendered as 64 lowercase hex characters (`tlog.receipt_core_hash`). `signatures` is the envelope's `signatures` array, canonicalized as a JSON array exactly as the rest of this document canonicalizes any array-valued member; `delivery` is deliberately excluded from this hash entirely — deleting a receipt's `delivery` member (v0.1 §4.2, already unsigned) never invalidates its log entry. This is the ONLY receipt-entry hash domain; a conforming implementation MUST NOT define or accept any other.

**Committing to the signature bytes, not just the payload, is deliberate and load-bearing, not redundant.** Post-CRQC, an attacker who has derived an issuer's Ed25519 private key from its public key (the exact scenario Stage 1's hybrid profile defends against for FUTURE receipts) can sign an arbitrary backdated payload at will. A hash over `payload` alone would let a precommitted log entry describe a payload that was never actually signed until long after it was logged: the attacker signs it only after the fact, past the horizon, and the old entry still "matches" the forged receipt byte-for-byte. Domain-separating and hashing the signature bytes too means a log entry can only ever describe a signature that ALREADY EXISTED at logging time — this is what makes `anchored_before:<T>` a genuine existence-of-signature proof rather than a mere existence-of-payload proof, and it is what conformance vector 28l pins: an unsigned payload-only precommit (a hash computed over `payload` alone, without domain separation or the signature bytes) is NOT accepted as receipt existence proof — it fails entry matching exactly like any other mismatched claim (`transparency_entry_mismatch`).

This is also the honest boundary of what Stage 2 protects for pre-existing receipt stock (§15): the guarantee holds only for a receipt whose signed-receipt-core was ACTUALLY logged and PQ-anchored before the horizon — never for "the stock" unqualified.

## 13. Sibling hardening: hybrid AND-rule extended to revocation and artifact manifests

**Normative note on scope:** this section documents a hardening fix folded into the Stage 2 wave, not new Stage 2 machinery — it closes a gap in code that shipped with v0.2 Stage 1.

v0.2 Stage 1, as originally shipped, left revocation records' own authentication Ed25519-only even for a hybrid-keyed issuer. Post-CRQC, an attacker who has broken only Ed25519 could forge a `policy`/`refund_window` revocation record against an otherwise-hybrid-protected manifest key, driving `revocation: "revoked"` (`ok: false`) purely through the classical leg — defeating the "breaking only Ed25519 is insufficient" guarantee (v0.2 §2.1) specifically for revocation, even though it held everywhere else.

**Fix, normative for every Stage-2-and-later implementation.** The Stage 2 sibling patch extends artifact manifests and revocation records to the hybrid AND-rule: if the signing key's own manifest entry carries `pub_ml_dsa_65` (i.e. the signer is hybrid), the side-document's signature block MUST also carry a valid `sig_ml_dsa_65` leg over the same signed bytes, or the document is treated as invalid and ignored — a downgraded, Ed25519-only signature against a hybrid key's authority is never honored, regardless of how early or late it is presented. An Ed25519-only signer's side-document carrying a stray `sig_ml_dsa_65` leg likewise fails closed (a document cannot claim hybrid protection for a key that never had a PQ public key). This is symmetric, fail-closed AND-verification in both directions, exactly mirroring §2.3's manifest-signature rule.

Conformance vector 28m pins the mechanism this closes: an Ed25519-only-signed revocation record against a HYBRID issuer key is unconditionally rejected and ignored (`revocation: "unknown"`, `ok: true`) — the record simply never counts, regardless of any transparency/anchor evidence presented alongside it (§10 confirms transparency evidence cannot rescue OR condemn a revocation verdict either way).

## 14. Bundle transparency evidence: the `proofs/` member

An offline `.attest` bundle (v0.1 §14.1) MAY carry transparency/corroboration evidence for its receipts, one JSON evidence bundle (§10.2's shape) per receipt, as a `proofs/` member.

**A conforming bundle contains `proofs/` members only in the shape `proofs/<ULID>.json`**, where `<ULID>` is exactly the 26-character Crockford base32 ULID the receipt schema already pins `receipt_id` to (first character in `0`–`7`, matching the schema's own timestamp-prefix constraint). A conforming importer MUST reject any other shape under `proofs/` — a nested path, a nested member, a nonexistent-`.json` suffix, or a filename that is not itself a syntactically valid ULID — BEFORE deriving any filesystem path from it: the member name is attacker-supplied bundle content, and letting an unvalidated shape reach a filesystem join is exactly the traversal hazard the ULID-only grammar exists to close.

`proofs/<ULID>.json`'s contents are exactly the untrusted §10.2 evidence shape and MUST be treated with the same untrusted-evidence discipline as evidence obtained any other way — importing it into a bundle confers no additional trust. A bundle's `README.html` (v0.1 §14.1) MUST document, in plain language, that a `proofs/` entry is corroboration, not authenticity: the receipt's own signature is what makes it authentic; a proof only shows the receipt (or manifest) was independently observable in the log at a point in time and, absent independent witnesses, does not by itself rule out the log operator equivocating.

## 15. Limitations (normative)

This section states Stage 2's bound, honestly and normatively — not as a caveat to be read past, but as part of the conformance surface. A conforming implementation and its documentation MUST NOT claim more than this section allows.

1. **No anti-equivocation without witnesses.** Stage 2 can DETECT equivocation when a verifier already holds two inconsistent, validly-signed checkpoints for the same origin (§10.3) — but it defines no mechanism for a verifier that has seen only one branch to discover that the log has a second, inconsistent branch. A keyed log with no independent witness quorum can, in principle, maintain parallel self-consistent branches indefinitely. Full anti-equivocation is a Stage 2b guarantee (independent witness federation, `corroboration: "witnessed"`, §10.1) and is NOT delivered by this document.
2. **Un-logged stock is unprotected.** Every guarantee in §10–§13 applies only to an artifact that was ACTUALLY logged (and, for post-horizon standing, ALSO PQ-anchored, §10.2 step 7). A receipt or key manifest that was never submitted to a log gets no existence-before-T guarantee from this document at all, no matter how old it is or how strong its original signature was. "Protect the existing stock" is true ONLY for the subset of stock that has been logged and anchored — a **bulk-logging path** for pre-existing receipts is therefore RECOMMENDED for any issuer that wants this guarantee to cover its historical stock, and a conforming implementation MUST NOT claim to protect "the stock" unqualified; the claim MUST always be scoped to "logged-and-anchored receipts."
3. **`corroboration` is not `authenticity`.** `corroboration: "logged"` (or, once reachable, `"witnessed"`) says an artifact was independently observable at a point in the log's history. It says nothing about who is entitled to have written that artifact — that is exactly what the receipt's own signature (`signature`) and the issuer's domain-control root (`trust`) already establish, unchanged by anything in this document. A consumer MUST NOT treat `corroboration` as a substitute for either.
4. **The log never upgrades `trust`.** Stated already in §7.1 and §10, restated here because it is the single most important non-goal: no value of `transparency` or `corroboration`, however strong, changes `trust` from `unauthenticated_tofu` to `verified`. `verified` requires the v0.1 §7.4 domain-control root; nothing else suffices, ever.
5. **Artifact-manifest/revocation equivocation beyond §13's hybrid-signature patch is out of scope.** §13 closes the specific hybrid-downgrade gap in revocation authentication. It does not extend transparency-log coverage, inclusion proofs, or anti-equivocation guarantees to artifact manifests or revocation records themselves — those side-documents are not currently loggable entry types (§8 defines exactly two: `key-manifest` and `receipt`).

## 16. Conformance: group 28 (transparency/corroboration)

The conformance leaf group [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/) adds 14 leaves (28a–28n) to the 52 pre-Stage-2 leaves (the 43 v0.1 leaves, the 8 `26-hybrid` leaves, and the single `27-valid-to-absent` leaf), for **66 total** — the conformance floor this document and its implementations MUST meet. Every group-28 leaf's `expected.json` additionally carries `transparency`, `corroboration`, and `manifest_freshness` — the only group where these three fields appear; every other leaf's absence of them means the verifier saw no transparency evidence at all (zero-behavior-change default, §10). Each leaf runs against every conformance runner (Python reference, TypeScript verifier) from the same shared golden files, per the discipline of v0.1 §15 and [`docs/spec/vectors/README.md`](vectors/README.md).

| Leaf | Checks |
| --- | --- |
| `28a` | Genuinely logged receipt (hybrid checkpoint, valid inclusion proof), TOFU/bundle provenance → `transparency: "logged"`, `corroboration: "logged"`, `trust: "unauthenticated_tofu"` UNCHANGED — logging never upgrades trust (§7.1, §15 item 4). |
| `28b` | Valid hybrid checkpoint, but for a root that does not actually contain the entry → inclusion proof fails, `transparency: "not_checked"`. |
| `28c` | Checkpoint with only the Ed25519 leg, no ML-DSA-65 line → NO standing at all, even though the Ed25519 signature is genuinely valid (§9.2). |
| `28d` | Genuinely hybrid-signed checkpoint by the pinned key material, but a different `origin` than pinned → no candidate `LogKey` verifies (§10.2 step 2). |
| `28e` | A verifying prior (smaller) checkpoint plus a genuine RFC 6962 consistency proof against the current checkpoint → still just `"logged"` — consistency rules out equivocation only between those two supplied checkpoints; it does not itself upgrade standing. |
| `28f` | A validly hybrid-signed prior checkpoint claiming the SAME tree size as the current checkpoint but a DIFFERENT root → `transparency: "equivocation_detected"` (§10.3, hard verdict). |
| `28g` | The evidence's `entry` disagrees with the entry `verify()` independently computes from the actual receipt → `transparency_entry_mismatch`, regardless of an otherwise-valid checkpoint/proof. |
| `28h` | A self-consistent `manifest_version: 2` key-manifest claim, but the verifier's trust store holds no rotation chain for the issuer → `corroboration_requires_rotation_chain`, `corroboration` downgraded to `"none"`, while `transparency: "logged"` and `manifest_freshness: "verified_as_of:1"` are unaffected (§10.4). |
| `28i` | A receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still honestly reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — corroboration never rescues an otherwise-invalid receipt (§10.4). |
| `28j` | A PQ-surviving `ots` proof replaying to a pinned Bitcoin block header → `transparency` upgrades to `anchored_before:2023-11-14T22:13:20Z` (header time `1700000000`). |
| `28k` | An `rfc3161`-only anchor proof → opaque classical corroboration only, `transparency` stays `"logged"`, never `anchored_before:<T>`; the verbatim RFC 3161 warning literal is asserted (§11.1). **Documented adaptation**: this vector's committed policy has `crqc_horizon=None`, so it does not consult `anchor.passes_horizon` here. With a configured horizon, the evaluator does call `anchor.passes_horizon`; an `rfc3161`-only verdict never becomes `pq_surviving` and is capped. |
| `28l` | The evidence entry's `core_sha256` is hashed over `payload` alone — no domain separation, no signature commitment — exactly the "pre-sign, log now, sign later" attack §12's domain separation defeats; same observable outcome as 28g (`transparency_entry_mismatch`), different attacker narrative. |
| `28m` | **Documented adaptation** from "post-horizon Ed-only revocation": `verify()`'s revocation classification has no `crqc_horizon`-shaped input at all — the horizon cap and revocation classification are separate subsystems, so a literal "post-horizon revocation" cannot be expressed through any `verify()` call. Adapted to the mechanism that would have to exist for that framing to hold: an Ed25519-only-signed revocation record against a HYBRID issuer key is unconditionally rejected/ignored (§13's AND rule, fail-closed) — `revocation: "unknown"`, `ok: true`. |
| `28n` | An evidence `entry` whose `type` the log's closed schema (§8) doesn't recognize → the claim is unresolvable before any checkpoint/proof is even consulted (`transparency_claim_unresolvable`); the receipt itself verifies untouched. |

### 16.1 Vector determinism

**Non-normative note:** group-28 vectors are generated deterministically by [`tools/gen_vectors.py`](../../tools/gen_vectors.py)'s `gen_28_transparency`, the same generator and determinism gate as every other group. Checkpoint/log fixtures use fixed keys and seeds; the `ots`/`rfc3161` anchor fixtures are frozen and committed (a committed OTS proof plus a pinned test Bitcoin header; synthetic opaque bytes for the `rfc3161` token) — no network access occurs in any conformance test, ever.

## References

- [`docs/spec/attest-v0.1.md`](attest-v0.1.md) — the base specification; every section referenced above (§1, §4, §7.1, §7.2, §7.3, §7.4, §9, §10, §11, §11.1, §14.1, §15) is unchanged by this document except where explicitly stated.
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- `draft-ietf-lamps-pq-composite-sigs` — the composite-signature parameter pairing (MLDSA65-Ed25519) this profile's parameter choice tracks for future interoperability.
- RFC 6962 — Certificate Transparency (the Merkle Tree Hash / inclusion / consistency proof construction §7–§10 build on).
- [C2SP tlog-tiles](https://c2sp.org/tlog-tiles), [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint), [C2SP signed-note](https://c2sp.org/signed-note) — the substrate profiles §7.2 and §9 specify a documented subset of / hybrid extension to.
- [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) — normative conformance vectors for §2–§6 of this document.
- [`docs/spec/vectors/28-transparency/`](vectors/28-transparency/) — normative conformance vectors for §7–§16 of this document.
