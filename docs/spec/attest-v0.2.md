# attest v0.2 — Normative Specification Delta: Hybrid Signature Profile

- **Status**: Normative, v0.2 (Stage 1 only — see §1 Scope)
- **Date**: 2026-07-17
- **Grounding**: this document is grounded in the reference implementation in `src/attest/` (`verify.py`, `pq.py`, `manifests.py`) and the conformance vectors in [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/). It introduces no design decision not already present in one of those two sources.
- **Companion artifacts**: [`docs/spec/attest-v0.1.md`](attest-v0.1.md) (the base specification this document extends — read together, never in isolation); conformance vectors — [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/).

This document uses the same conformance language as v0.1 §1 (RFC 2119/RFC 8174 key words, non-normative notes carry no conformance weight).

## 1. Status and scope

attest v0.2 is **additive**: every v0.1 receipt, key manifest, and revocation record remains valid and verifiable forever, under the v0.1 rules, with no expiry. This document does not revise, deprecate, or restrict anything in v0.1 — it defines a second, parallel signature profile selected by the payload's own `attest_version` field.

**No downgrade path.** `attest_version` is INSIDE the signed payload (v0.1 §5.1), so a receipt's version is itself signed and cannot be stripped or rewritten without invalidating the signature. A v0.1 verifier supports only `attest_version: "0.1"` (v0.1 §11 step 1) and MUST reject any `"0.2"` envelope outright, exactly as it would reject any other unsupported version string — there is no compatibility shim and none is planned. Conversely, a v0.2 verifier supports both `"0.1"` and `"0.2"` and dispatches on that field alone, never on `signatures[].alg` (v0.1 §4.1's dispatch prohibition extends unchanged to v0.2).

**This document specifies Stage 1 only: the hybrid Ed25519+ML-DSA-65 signature profile.** The v0.2 design additionally scopes two later stages — (a) issuer key transparency and cross-anchoring of key manifests (a Merkle log of manifests, periodically timestamped on independent external anchors, protecting the existing v0.1 receipt stock against a future forgery), and (b) issuer-mediated transfer records (a new record type giving real meaning to the reserved `license.transferable` field). Neither is specified here; both are **forthcoming** in later v0.2 revisions of this document, and neither changes anything stated below. A conforming Stage 1 implementation MUST NOT be understood to implement, or to be blocked on, either later stage.

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

## References

- [`docs/spec/attest-v0.1.md`](attest-v0.1.md) — the base specification; every section referenced above (§1, §4, §7.1, §7.3, §7.4, §9, §10, §11, §11.1, §15) is unchanged by this document except where explicitly stated.
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- `draft-ietf-lamps-pq-composite-sigs` — the composite-signature parameter pairing (MLDSA65-Ed25519) this profile's parameter choice tracks for future interoperability.
- [`docs/spec/vectors/26-hybrid/`](vectors/26-hybrid/) — normative conformance vectors for this document.
