# attest v0.1 conformance vectors

This directory holds the attest v0.1 conformance suite: fixed, language-neutral test cases against which any implementation of [`docs/spec/attest-v0.1.md`](../attest-v0.1.md) can be checked. Each vector is a leaf directory (identified by containing `expected.json`) holding the raw inputs to feed the verification algorithm and the exact `VerificationResult` a conformant verifier must produce.

**Normative conformance requirement**: an implementation is attest-conformant iff it produces every vector's expected result. There is no partial conformance — any single mismatch is a conformance failure.

## Vector format

Each leaf directory contains:

- `payload.json` — the receipt payload, for readability (not itself fed to `verify()`; it is embedded inside `envelope.json`).
- `envelope.json` — the full envelope (`payload` + `signatures` + optional `delivery`), or `envelope.raw.json` (vector 06 only) for a case whose raw bytes intentionally cannot round-trip through a parsed object.
- `manifests.json` — the trust material: `{"manifests": {...}, "provenance": {...}, "chains": {...}}`, fed straight into the verifier's trust store.
- `expected.json` — the spec-intended `VerificationResult`: `signature`, `schema`, `trust`, `revocation`, `binding`, `ok`, plus `errors`/`errors_contains` and `warnings`/`warnings_contains`.
- optional `disclosure.json` — a buyer-binding disclosure, salt path (`identifier`, `identifier_type`, `salt_b64u`) or challenge path (`nonce_b64u`, `sig_b64u`), for vectors that check §6 step 7.
- optional `revocation.json` — a single issuer-signed revocation record, fed to the verifier as its revocation view, for vectors that check §6 step 6.
- optional `manifest_pristine.json` — only for vector 11: the untampered, self-consistent manifest, alongside the tampered one actually used for verification.
- optional `canonical.json` — the exact canonical serialization bytes of the leaf's payload. A conforming implementation MUST reproduce these bytes exactly when canonicalizing the parsed payload. Present on vectors 21f/21g (supplementary-plane encodings) and 24.
- optional `transparency.json` / `log-keys.json` / `anchor-policy.json` — group 28 only: the untrusted transparency/corroboration evidence bundle, the verifier's pinned transparency-log signing identities, and its pinned Bitcoin block headers + CRQC horizon, fed to the verifier as `transparency`/`log_keys`/`anchor_policy`. Only group 28's `expected.json` carries the corresponding `transparency`/`corroboration`/`manifest_freshness` result fields.

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

### 19–25: cross-implementation review parity

| # | Name | Checks |
| --- | --- | --- |
| 19a | `rotation-substituted-key/a-substituted-candidate-key` | A candidate v2 manifest that is itself self-consistent (signed by a substituted key never present in the trusted v1 root) — the discontinuous chain is unmasked against the root, forcing `trust: "unverified_rotation"` even though the receipt's own signature verifies. |
| 19b | `rotation-substituted-key/b-chain-tail-not-manifest-used` | A genuinely continuous v1→v2 chain exists, but the receipt is verified against v1 (the manifest actually in trust), not the chain's tail — trust downgrades the same way, pinning that continuity is judged against the manifest in use, not any reachable chain. |
| 20a | `sig-canonicity/a-s-equals-l` | Signature `S` set to exactly `L` (the curve order) — the smallest non-canonical scalar boundary case beyond vector 08's `S + L` — rejected. |
| 20b | `sig-canonicity/b-small-order-pubkey` | Signer pubkey (`A`) is a small-order point — rejected (zip215:false / libsodium-equivalent ruleset). |
| 20c | `sig-canonicity/c-small-order-r` | Signature's `R` component is a small-order point, `S` otherwise genuine — rejected. |
| 21a | `canon-strict/a-bom` | A UTF-8 byte-order mark prepended to the raw envelope bytes — rejected at strict parsing. |
| 21b | `canon-strict/b-depth-255` | Whole-text nesting depth exactly 255 — accepted (unknown-field tolerance, vector 10). |
| 21c | `canon-strict/c-depth-256` | Whole-text nesting depth exactly 256, the boundary — still accepted. |
| 21d | `canon-strict/d-depth-257` | Whole-text nesting depth 257, one past the boundary — rejected at strict parsing (maximum nesting depth exceeded). |
| 21e | `canon-strict/e-lone-surrogate` | A lone UTF-16 surrogate injected via `\uXXXX` escape — rejected at strict parsing (a payload carrying one can never be signed in the first place). |
| 21f | `canon-strict/f-supplementary-raw` | A supplementary-plane character (outside the BMP) encoded as raw UTF-8 bytes — verifies clean; carries `canonical.json` for the payload's exact canonical bytes. |
| 21g | `canon-strict/g-supplementary-escaped` | The same payload and signature as 21f, but the envelope bytes use `𝄞`-style surrogate-pair escaping instead of raw UTF-8 — verifies clean with the identical result, proving canonicalization is transport-escaping-independent; carries the same `canonical.json`. |
| 22a | `b64u-decoder-parity/a-padding-accepted` | A signature's base64url encoding with explicit `=` padding added — accepted (both reference decoders are deliberately permissive). |
| 22b | `b64u-decoder-parity/b-standard-alphabet-accepted` | The same signature re-encoded with the standard `+/` alphabet instead of urlsafe `-_` — accepted. |
| 22c | `b64u-decoder-parity/c-trailing-bits-accepted` | The same signature with non-zero discarded trailing bits in its final base64 character — accepted. |
| 23a | `revocation-refund-window/a-inside-window` | A `revocability: "refund_window"` receipt with an authenticated revocation record whose `revoked_at` falls inside the window — effective: `revocation: "revoked"`, `ok: false`. |
| 23b | `revocation-refund-window/b-after-window` | The same receipt with an authenticated revocation record whose `revoked_at` falls after the window closes — ignored: `revocation: "invalid_revocation_ignored"`, a warning is emitted, `ok` stays `true`. |
| 24 | `canonical-roundtrip` | A plain valid receipt that additionally commits its payload's exact canonical bytes via `canonical.json` — a Python→TS→Python round-trip must reproduce them byte-for-byte. |
| 25a | `schema-parity/a-edition-nonstring` | `work.edition` set to a non-string (an int) before signing, so the signature genuinely covers the invalid payload — signature valid, `schema: "invalid"` (pins schema drift where an implementation's runtime type accepts non-strings). |
| 25b | `schema-parity/b-ulid-first-char` | `receipt_id`'s first character set to `'8'`, past the ULID timestamp-prefix range the pinned regex allows (`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`) — signature valid, `schema: "invalid"`. |

### 26: hybrid Ed25519+ML-DSA-65 signatures (attest v0.2)

Checked against [`docs/spec/attest-v0.2.md`](../attest-v0.2.md), the additive delta specification for the `attest_version: "0.2"` hybrid signature profile.

| Leaf | Name | Checks |
| --- | --- | --- |
| 26a | `a-valid-hybrid` | The happy path: both the Ed25519 and ML-DSA-65 legs verify against a single hybrid key-manifest entry — `ok: true`. |
| 26b | `b-ed25519-leg-tampered` | The Ed25519 leg's signature bytes flipped post-signing — `signature: "invalid"`. |
| 26c | `c-mldsa-leg-tampered` | The ML-DSA-65 leg's signature bytes flipped post-signing — `signature: "invalid"`. |
| 26d | `d-mldsa-leg-missing` | The ML-DSA-65 signature entry stripped, leaving one signature — rejected outright (`signatures` must have length exactly 2), never treated as a v0.1-shaped fallback. |
| 26e | `e-duplicate-ed25519-alg` | Both signature entries carry `alg: "Ed25519"` instead of the fixed `[Ed25519, ML-DSA-65]` order — rejected. |
| 26f | `f-kid-mismatch-between-legs` | The two signature entries carry different `kid` values — rejected (the hybrid pair must be one signer). |
| 26g | `g-key-entry-not-hybrid` | The resolved manifest key entry has no `pub_ml_dsa_65` — rejected, nothing to verify the PQ leg against. |
| 26h | `h-manifest-downgraded-continuity` | A rotation candidate manifest signed by a hybrid key but whose `manifest_signature` was downgraded to Ed25519-only — the receipt's own signature still verifies, but the manifest fails its own hybrid AND-check, so the rotation chain is discontinuous: `trust: "unverified_rotation"`. |

### 27: `valid_to` omitted (attest v0.2)

| Leaf | Name | Checks |
| --- | --- | --- |
| 27 | `valid-to-absent` | A key manifest entry with the `valid_to` field omitted entirely (not `null`) still self-verifies and resolves an open-ended key — the JSON-shape divergence (absent vs. explicit `null`) must not affect verification. |

### 28: transparency/corroboration layer (attest v0.2, design doc "transparency/corroboration layer")

The cross-core corpus for `verify()`'s Stage 2 `transparency`/`corroboration`/`manifest_freshness` result components, exercising `tlog`/`anchor`/`transparency` end to end. Every leaf's `expected.json` additionally carries `transparency`, `corroboration`, and `manifest_freshness` — the ONLY group where these three appear; every other leaf's absence of these files/fields means `verify()` saw `transparency=None`/`log_keys=None`/`anchor_policy=None` (zero behavior change, Task-8-and-earlier defaults). New per-leaf input files (loaded when present, absent everywhere else): `transparency.json` (the untrusted evidence bundle), `log-keys.json` (the verifier's pinned transparency-log signing identities), `anchor-policy.json` (pinned Bitcoin block headers + optional CRQC horizon).

| Leaf | Name | Checks |
| --- | --- | --- |
| 28a | `a-logged-trust-unchanged` | A genuinely logged receipt (hybrid-signed checkpoint, valid inclusion proof) with TOFU/bundle provenance — `transparency: "logged"` and `corroboration: "logged"` MUST leave `trust: "unauthenticated_tofu"` unchanged; log evidence never upgrades trust. |
| 28b | `b-wrong-root` | A validly hybrid-signed checkpoint, but for a Merkle root that does not actually contain this entry — inclusion proof fails, `transparency: "not_checked"`. |
| 28c | `c-ed-only-checkpoint` | A checkpoint carrying only the Ed25519 signature line, no ML-DSA-65 leg — checkpoint auth is hybrid, MANDATORY (design doc), so a genuine Ed25519-only signature grants no standing at all. |
| 28d | `d-origin-mismatch-log-key` | A genuinely hybrid-signed checkpoint by the pinned log key material, but claiming a different `origin` than the one pinned in `log-keys.json` — no candidate verifies. |
| 28e | `e-consistency-ok` | A two-leaf tree with a verifying prior checkpoint (smaller tree) and a genuine consistency proof against the current checkpoint — still just `"logged"` (consistency rules out equivocation, it does not upgrade standing on its own). |
| 28f | `f-equivocation-detected` | A validly hybrid-signed prior checkpoint claiming the SAME tree size as the current checkpoint but a DIFFERENT root — proof the log signed two incompatible histories: `transparency: "equivocation_detected"` (a hard verdict, not fail-safe degradation). |
| 28g | `g-entry-hash-mismatch` | The evidence's `entry` disagrees with the hash `verify()` independently computes from the actual receipt — `transparency_entry_mismatch`, regardless of an otherwise-valid checkpoint/proof. |
| 28h | `h-rotation-chain-omitted` | A self-consistent `manifest_version: 2` issuer manifest, logged as a key-manifest claim, but the trust store holds no rotation chain for the issuer at all — `corroboration` is downgraded to `"none"` with `corroboration_requires_rotation_chain`, even though `transparency` (`"logged"`) and `manifest_freshness` (`"verified_as_of:1"`) are unaffected. |
| 28i | `i-compromised-key-fail-closed` | A receipt rejected outright for a compromised signing key (`signature: "invalid"`, `ok: false`) still reports `transparency: "logged"`/`corroboration: "logged"` for its own genuinely-logged evidence — proving corroboration can never rescue an otherwise-invalid receipt (design fix 6; transparency is resolved before the pass/fail verdict). |
| 28j | `j-ots-anchor` | A PQ-surviving `ots` proof replaying from `SHA-256(checkpoint.note_bytes)` to a pinned Bitcoin block header — `transparency` upgrades to `anchored_before:2023-11-14T22:13:20Z` (header time `1700000000`, `transparency.py`'s own documented KAT). |
| 28k | `k-rfc3161-only` | An `rfc3161`-only anchor proof — opaque classical corroboration only, never sets `pq_surviving`, so `transparency` stays `"logged"` (no PQ/post-horizon standing); the verbatim RFC 3161 warning is asserted. **Adapted**: no leaf here sets `anchor-policy.json`'s `crqc_horizon` — an rfc3161-only proof never reaches `anchor.passes_horizon` regardless of horizon configuration, so a horizon value would add configuration, not test coverage. |
| 28l | `l-payload-only-precommit` | The evidence entry's `core_sha256` is hashed over the payload ALONE (no domain separation, no signature commitment) — exactly the "pre-sign, log now, sign later" attack `receipt_core_hash`'s domain separation defeats. Same observable outcome as 28g (`transparency_entry_mismatch`), different attacker narrative: this is specifically the hash an attacker could compute before the receipt was ever signed. |
| 28m | `m-hybrid-revocation-and-rule` | **Adapted** from the original "post-horizon ed-only revocation" framing: `verify.py`'s revocation classification has no `crqc_horizon`-shaped parameter at all (revocation and the transparency/anchor horizon cap are separate subsystems), so that framing cannot be expressed through any `verify()` input. Pins the mechanism that would have to exist for it to hold instead: an Ed25519-only-signed revocation record against a HYBRID (`pub_ml_dsa_65`-carrying) issuer key is unconditionally rejected/ignored (the Task 6/8 sibling-hybrid AND rule, fail-closed) — `revocation: "unknown"`, the record ignored with a warning, `ok: true`. |
| 28n | `n-unknown-entry-type` | An evidence `entry` whose `type` the log's closed schema doesn't recognize — the claim is unresolvable before any checkpoint/proof is even consulted (`transparency_claim_unresolvable`); the receipt itself verifies untouched (`ok: true`). |

## Regeneration

The vectors are generated deterministically by [`tools/gen_vectors.py`](../../../tools/gen_vectors.py): every keypair, salt, timestamp, and ULID randomness source is a fixed constant (no wall-clock reads, no CSPRNG). Running

```sh
.venv/bin/python tools/gen_vectors.py
```

twice must produce byte-identical output — `git diff --exit-code docs/spec/vectors` after a second run is the determinism gate. `tests/test_vectors.py` replays every vector against the reference implementation and asserts the produced `VerificationResult` matches `expected.json` exactly.
