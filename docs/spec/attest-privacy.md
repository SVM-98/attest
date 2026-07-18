# attest — Privacy Considerations

- **Status**: Living document, v0.1 (initial publication)
- **Date**: 2026-07-18
- **Grounding**: the fields, documents, and data flows analyzed here are grounded in `attest-v0.1.md`, `attest-v0.2.md`, and the normative JSON Schema at [`schema/attest-receipt.schema.json`](schema/attest-receipt.schema.json); this companion document declares the classification vocabulary and the analytical lens used to analyze them.

## 1. Status and scope

This is a living normative companion to [`attest-v0.1.md`](attest-v0.1.md) and [`attest-v0.2.md`](attest-v0.2.md), and the sibling of [`attest-threat-model.md`](attest-threat-model.md). Where the threat model asks what an adversary can forge, suppress, or substitute, this document asks a narrower question about the same artifacts: what personal data each one carries, and what each party that handles one is thereby able to learn. It covers the shipped protocol as those two specifications currently define it — the v0.1 baseline (envelope, payload registry, buyer commitment and binding, key and artifact manifests, revocation records, the two export bundle formats), the v0.2 Stage 1 hybrid signature profile, and the v0.2 Stage 2 transparency layer (log entries, checkpoints, evidence bundles, and the bundle `proofs/` member).

This is a technical analysis of the protocol's data flows, not legal advice. It states what the specified formats do and do not record and what that means for the parties handling them; it does not assess any deployment's obligations, and no statement here should be read as advising that a given deployment complies with, or fails to comply with, any legal regime.

**Update rule.** Because this document's classifications and observer analyses cite specific fields and mechanisms in the normative specifications as evidence, a specification change that adds, removes, or alters a field or a mechanism invalidates any classification or analysis that cited it. Every future normative change to the attest specifications MUST update this document (and `attest-threat-model.md`) in the same change cycle — a threat-model or privacy-model gap introduced by a spec change and left undocumented is itself a defect in that change, not a follow-up. This is the same obligation stated in `attest-threat-model.md` §1, and the two documents state it identically on purpose: neither is a snapshot that may drift behind the specifications it describes.

**Non-normative note:** except for this document's own maintenance obligation in the update rule above, this document analyzes and cross-references the normative text; it does not itself impose requirements beyond what `attest-v0.1.md` and `attest-v0.2.md` already state. Where a classification's rationale uses RFC 2119 keywords, it is restating a requirement that is normative in one of those two documents, not inventing a new one.

### Analytical backbone

The analysis in §3 uses the threat vocabulary of **RFC 6973 (Privacy Considerations for Internet Protocols)**, which catalogues privacy threats in two groups: combined security-privacy threats (surveillance, stored data compromise, intrusion, misattribution) and privacy-specific threats (correlation, identification, secondary use, disclosure, exclusion). Four of those carry the weight here and every observer subsection in §3 is analyzed against the same four:

- **Surveillance** — what the observer can watch, over time, without any party choosing to tell it anything.
- **Correlation** — what the observer can join together: two receipts to one buyer, one buyer to one purchase history, one artifact to another.
- **Identification** — what it takes for the observer to move from a pseudonymous handle to a named natural person.
- **Disclosure** — what the observer is simply handed, by the format, when an artifact reaches it.

The remaining RFC 6973 threats are not absent from the protocol; they are analyzed elsewhere or fall outside it. Stored data compromise is the threat model's territory (`attest-threat-model.md` TM-15, TM-35), as is misattribution (TM-05, TM-06). Buyer-secret custody (TM-44) and implementation supply-chain compromise (TM-59) are separate scope boundaries. Secondary use and exclusion are properties of a deploying issuer's own data handling rather than of the wire formats these specifications define, and intrusion has no protocol surface here at all, since attest defines no messaging to a buyer.

### Conformance language

This document reuses, without redefining, the conformance language established in `attest-v0.1.md` §1: the key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** carry the RFC 2119 meaning, as clarified by RFC 8174, when and only when they appear in all capitals. Passages introduced with **Non-normative note:** carry no conformance weight. Classifications and mechanism citations are descriptive of the referenced specifications; the update rule above is this document's own normative obligation.

### Actor names

Actor names are the canonical ones fixed in `attest-threat-model.md` §2 and are used here verbatim and unqualified: `issuer`, `buyer`, `verifier`, `log operator`, `mirror operator`, `network attacker`, `coercive third party`, `supply chain`. Where §3 analyzes a party that is not an actor in its own right — the holder of an exported bundle, the recipient of a per-receipt disclosure — that party is described in terms of the canonical actor it is playing.

### Changelog

| Date | Change |
| --- | --- |
| 2026-07-18 | Initial publication: §1 status and scope, §2 data inventory, §3 what each observer learns. |

## 2. Data inventory

This section inventories, artifact by artifact, every field of every document the two specifications define as travelling between parties, and classifies each one. It is drawn from the field registries in `attest-v0.1.md` §4, §5, §7.1, §7.2, §12, §13, and §14, and the additions in `attest-v0.2.md` §2.2, §2.3, §8, §9, §10.2, §13, and §14; the payload tables in §2.1–§2.6 are additionally checked field-for-field against the normative schema at [`schema/attest-receipt.schema.json`](schema/attest-receipt.schema.json).

What is outside the inventory, and why: the verifier-side trusted configuration — the `TrustStore` (v0.1 §7.4), the pinned `LogKey` set (v0.2 §7.3, §9.2), and the `AnchorPolicy` with its pinned Bitcoin headers (v0.2 §11.2) — is not an artifact any party transmits to another, and its content is issuer public key material, log public key material, and public blockchain headers. It carries no buyer-derived value and is not classified below. `VerificationResult` (v0.1 §11.1, v0.2 §10.1) is a locally computed output over artifacts the verifying party already holds, and is treated in §3 rather than here.

Every field carries exactly one of three classifications:

- **`not personal`** — the value is fixed by the specification, drawn from a closed vocabulary, matched against a fixed pattern, or is a hash of a public non-personal document. It carries no information about a natural person on its own. A `not personal` field may still be an *attribute of* a person's purchase, and may still serve as a correlation handle in combination with others; §3 analyzes what that combination yields.
- **`pseudonymous`** — the value stands for, or is derived from, a person or a single person's purchase, but reveals no identity on its own. Re-identification requires information held elsewhere: a salt, an `issuer`'s own customer records, or a second artifact to join against.
- **`potentially personal, user-controlled`** — the value is free-form and chosen by the deploying `issuer`, copied from `buyer`-supplied input, or — for the artifacts an `issuer` does not produce — chosen by whichever party assembles them. The format constrains its type, length, or pattern, never its content, and no verification step inspects what a string means.

**The classification describes what a field MAY carry across every conforming deployment, not what a well-behaved `issuer` typically puts there.** That is why every open string field below is `potentially personal, user-controlled` even when its conventional content is a product name or a platform token: nothing in the schema, the canonicalization profile, or the verification algorithm stops an `issuer` from placing an identity in one, and a receipt that does carry one verifies exactly as cleanly as one that does not.

**Two structural facts govern the whole inventory.** First, `payload` is immutable once signed (v0.1 §6.3) and is the sole signature input (v0.1 §9), so there is no redaction mechanism: a field cannot be removed from a receipt without destroying the signature that gives the receipt its value. The one defined field removal in the protocol — stripping `delivery.salt` on export (v0.1 §4.2, §14.1) — works only because `delivery` sits outside the signed object. Within a receipt, sharing is all-or-nothing; the only sharing granularity the protocol offers is per-receipt (v0.1 §13). Second, no object anywhere in the payload sets `additionalProperties: false` (v0.1 §5, confirmed in the schema, whose root sets `additionalProperties: true` and whose nested objects set it nowhere), so any of these tables describes the *specified* field set, never an exhaustive bound on what a conforming receipt may contain.

### 2.1 Receipt payload — top level (v0.1 §5.1)

| Field | Classification | Notes |
| --- | --- | --- |
| `attest_version` | not personal | Schema enum `["0.1", "0.2"]`; selects the payload shape and signature profile. v0.2 adds no payload member of its own — the entire hybrid delta lives in `signatures` (v0.2 §2.2) and in the key manifest (v0.2 §2.3), so this table and §2.2–§2.6 are complete for both versions. |
| `receipt_id` | pseudonymous | A per-purchase handle, not derived from the `buyer`, but stable across every copy of the receipt, every revocation record naming it (v0.1 §12), and every `proofs/<ULID>.json` member (v0.2 §14). It is a ULID — v0.1 §9.1 fixes the encoding (Crockford base32, 26 characters) and v0.1's References cite the ULID specification as the format for this field — whose leading characters encode a 48-bit millisecond timestamp — v0.2 §14 names this directly as "the schema's own timestamp-prefix constraint" when pinning the first character to `0`–`7`. Issuance time is therefore recoverable from the identifier alone, at finer resolution than `issued_at`, which the payload states only to the second. |
| `issued_at` | not personal | UTC `YYYY-MM-DDTHH:MM:SSZ`, second resolution. A timestamp carries nothing about a person on its own; in a receipt it is the time that `buyer` bought, and it anchors key-validity checks (v0.1 §11 step 3) and `refund_window` revocation (v0.1 §12.2). |
| `supersedes` | pseudonymous | ULID or `null`; same class and same timestamp property as `receipt_id`. Where non-null it joins two receipts as one lineage, which is a correlation the format asserts rather than one an observer has to infer. It is an unverified pointer: nothing requires the named receipt to exist or to have been issued to the same `buyer` (TM-08). Issuers SHOULD offer re-issue via `supersedes` after a disclosure (v0.1 §8.1), so a non-null value may itself indicate that the superseded receipt's binding secrecy was burned. |
| `issuer` | — | Object; see §2.2. |
| `buyer` | — | Object; see §2.3. |
| `work` | — | Object; see §2.4. |
| `license` | — | Object; see §2.5. |
| `survivability` | — | Object; see §2.6. |
| any unrecognized member | potentially personal, user-controlled | Permitted and signed (v0.1 §11.2). An unrecognized **top-level** member MUST be surfaced as a warning; a member nested inside `issuer`, `buyer`, `work`, `license`, or `survivability` is signed and accepted with no mandated warning at all, because the schema sets `additionalProperties: false` nowhere (TM-21). Nothing prevents such a member from carrying a plaintext identity. |

### 2.2 `payload.issuer` (v0.1 §5.2)

| Field | Classification | Notes |
| --- | --- | --- |
| `issuer.id` | potentially personal, user-controlled | A lowercase DNS domain of at least two labels, which the `issuer` controls and publishes under. About the `issuer`, never the `buyer` — but where the `issuer` is a sole trader operating under their own name, the domain is personal data about that trader. It is public by design: it roots key discovery (v0.1 §7) and issuer binding (v0.1 §11 step 2). |
| `issuer.display_name` | potentially personal, user-controlled | Free-form non-empty string, human-readable, carrying no cryptographic weight. Same consideration as `issuer.id`: a sole trader's own name is personal data about that trader. |

### 2.3 `payload.buyer` (v0.1 §5.3)

The schema lists exactly three properties for this object — `commitment`, `identifier_type`, and `pubkey` — of which the first two are required. There is no plaintext identity member among them. As everywhere else in the payload, that is the specified set and not a closed one: `buyer` sets `additionalProperties: false` no more than any other object does, so an additional signed member here is accepted with no mandated warning (§2.1, §2.16).

| Field | Classification | Notes |
| --- | --- | --- |
| `buyer.commitment` | pseudonymous | `scrypt(P, salt, N=32768, r=8, p=1, dkLen=32)` over a domain-separated, normalized identifier (v0.1 §8.1), base64url, 32 decoded bytes. Not reversible without the salt, and the per-receipt salt means two receipts committing to the *same* identifier carry unrelated commitment values. scrypt **raises** the cost of dictionary recovery; it does not eliminate it — an attacker holding the salt can still enumerate candidates drawn from a guessable population, which is exactly the low-entropy case v0.1 §8.1 names as its reason for choosing scrypt (TM-18). The parameters are fixed by the specification version and MUST NOT be tuned per-issuer, so an `issuer` facing a higher-risk identifier population cannot raise them. |
| `buyer.identifier_type` | not personal | Enum, exactly `issuer-account` or `email`. The value itself names no one, but it discloses which population the commitment covers: `issuer-account` is a store-scoped identifier whose disclosure links nothing globally and is RECOMMENDED; `email` is a globally-scoped identifier that, once recovered, links the `buyer` across issuers (v0.1 §8.1, TM-18). |
| `buyer.pubkey` | pseudonymous | Ed25519 public key (base64url, 32 decoded bytes) or `null`; `null` is the default for client-less flows, so the field is frequently absent in practice. Keys SHOULD be per-receipt (v0.1 §8.2). A `verifier` MUST NOT treat `pubkey` equality across two receipts as proof of `buyer` identity — but that rule bounds what a `verifier` may *conclude*, not what the format *permits*: an implementation that reuses one key across a buyer's receipts makes this field a stable cross-receipt correlator visible to anyone holding two of them, and no mechanism detects or prevents that. |

### 2.4 `payload.work` (v0.1 §5.4)

| Field | Classification | Notes |
| --- | --- | --- |
| `work.title` | potentially personal, user-controlled | Non-empty string. Conventionally a product name, which is not personal data — but the title of a commissioned or personalized work can name the `buyer`, and the format neither prevents nor detects that. What was bought is, in combination with the rest of the receipt, the most revealing attribute the document carries; §3 analyzes that. |
| `work.publisher` | potentially personal, user-controlled | Non-empty string naming the publisher of record — the delegated-issuer path's anchor. A self-publishing author's own name is personal data about that author. It is a signed but unattested string: v0.1 defines no publisher authorization semantics (TM-06). |
| `work.edition` | potentially personal, user-controlled | Optional free-form string; conventionally an edition name, content otherwise unconstrained. |
| `work.identifiers` | potentially personal, user-controlled | Object, at least one property, string-valued (schema: `minProperties: 1`, `additionalProperties: {"type": "string"}`). **Both the keys and the values are unconstrained beyond being strings.** The conventional content is an issuer-scoped product identifier such as `{"issuer_sku": "EXG-001"}`, which is not personal; nothing stops an `issuer` keying an order number or a customer identifier here, and such a value is a plaintext handle into that issuer's own records, signed permanently into the payload. This is the widest open surface in the specified field set. Identifiers being issuer-scoped also means two issuers naming the same work carry no cross-issuer relationship any `verifier` can check (TM-17). |
| `work.artifact_series` | potentially personal, user-controlled | Optional issuer-scoped series identifier, conditionally required by v0.1 §6.1. Conventionally a product-level constant shared by every buyer of that series; the schema constrains only type and non-emptiness. |
| `work.artifacts` | — | Optional array; per-item fields below. |

Each `work.artifacts[]` item:

| Field | Classification | Notes |
| --- | --- | --- |
| `role` | potentially personal, user-controlled | Non-empty string, conventionally a short technical token such as `installer`. |
| `platform` | potentially personal, user-controlled | Non-empty string, conventionally a token such as `windows-x86_64`. |
| `filename` | potentially personal, user-controlled | Non-empty string. See the per-buyer-build note below. |
| `size_bytes` | pseudonymous | Integer, `0 ≤ n ≤ 2^53 − 1`; a property of a file. An `issuer` can pad a per-buyer artifact to a unique size within this range, making the value a stable correlator for that buyer's copy without carrying plaintext. See the per-buyer-build note below. |
| `sha256` | pseudonymous | Lowercase-hex SHA-256 of the artifact. A shared release hash is not personal, but a per-buyer artifact hash is a stable correlator for that buyer's copy without carrying plaintext. See the per-buyer-build note below. |

**Per-buyer builds.** These rows describe files, not people — with an exception that the format permits and no `verifier` can detect. Where an `issuer` serves watermarked or otherwise personalized artifacts, the `filename`, `size_bytes`, and `sha256` of a buyer's own copy can be unique to that buyer and are signed into the payload. A `filename` can carry plaintext; a unique size or hash functions as a stable correlator joining the receipt to the buyer's downloaded file and to another document quoting that value. The `size_bytes` and `sha256` classifications cover that correlation case, not only the common shared-release case. Separately, artifact hashes identify content **authorized** under the issuer's mirror policy and MUST NOT be construed as a license to source matching-hash files from unauthorized hosts (v0.1 §5.4).

### 2.5 `payload.license` (v0.1 §5.5)

| Field | Classification | Notes |
| --- | --- | --- |
| `grant` | not personal | Enum `perpetual` \| `subscription`. |
| `revocability` | not personal | Enum `none` \| `refund_window` \| `policy`; governs revocation-record effectiveness (v0.1 §12.2). |
| `revocation_window_days` | not personal | Integer `1 ≤ n ≤ 3650`, REQUIRED iff `revocability == "refund_window"`. A term of the sale, not an attribute of the `buyer`. |
| `transferable` | not personal | Boolean; reserved, and MUST NOT be read as authorization to resell or transfer (v0.1 §2). |
| `drm` | not personal | Enum `drm-free` \| `drm-bound`; `drm-bound` MUST emit a warning (v0.1 §11.2). |
| `terms_uri` | potentially personal, user-controlled | String. `format: "uri"` is **annotation-only** in v0.1 (§9): a conforming validator is not required to assert even URI well-formedness, and the reference implementation does not. Content is therefore entirely at the issuer's discretion — including a per-buyer URL carrying an order or account identifier in its path or query, signed into every copy of the receipt. Integrity of the document it points at rests on `legal_text_sha256`, never on URI syntax. Fetching it is also an observable network event, to the host serving it and to anyone on the path. |
| `legal_text_sha256` | pseudonymous | Lowercase-hex SHA-256 hash-binding the license text into the signed payload. A standard public text yields a shared hash, but an `issuer` can bind a per-sale text that is personal; its hash then correlates every copy of that sale's receipt and legal document without carrying the text. The text itself travels in the export bundle (§2.14). |
| `jurisdiction_flags` | potentially personal, user-controlled | Optional object; the schema constrains *values* to booleans but leaves the **key vocabulary open**. The one defined key, `eu_usedsoft_asserted`, is an assertion by the `issuer` that the sale met the *UsedSoft* C‑128/11 conditions. It is an assertion about the sale's conditions and carries no claim about where the `buyer` is located or resident; it MUST NOT be read as one. |

### 2.6 `payload.survivability` (v0.1 §5.6)

| Field | Classification | Notes |
| --- | --- | --- |
| `redownload_right` | not personal | Boolean; a term of the sale. |
| `mirror_policy_uri` | potentially personal, user-controlled | Optional string; same annotation-only `format: "uri"` status and the same content and fetch-observability considerations as `terms_uri`. |
| `mirror_policy_sha256` | pseudonymous | Optional lowercase-hex SHA-256 hash-binding the mirror policy text, so the `issuer` cannot silently rewrite obligations post-issuance. An `issuer` can bind a per-sale policy document; its hash then correlates copies of that document and receipt without carrying the document text. |
| `end_of_life` | potentially personal, user-controlled | Non-empty string over an open versioned vocabulary; v0.1 seeds `artifacts-remain-redownloadable`, `escrow`, `none`, and unknown values are valid-with-warning rather than a schema error (v0.1 §11.2). Conventionally a vocabulary token; content unconstrained. |
| `eol_commitment_uri` | potentially personal, user-controlled | Optional string or `null`; same considerations as `terms_uri`. |
| `eol_commitment_sha256` | pseudonymous | Optional lowercase-hex SHA-256 or `null`, hash-binding an end-of-life commitment document. An `issuer` can bind a per-sale commitment document; its hash then correlates copies of that document and receipt without carrying the document text. |

### 2.7 Envelope members outside the payload (v0.1 §4; v0.2 §2.2)

An envelope has exactly three top-level members: `payload`, `signatures`, and an OPTIONAL `delivery`.

| Field | Classification | Notes |
| --- | --- | --- |
| `signatures[].kid` | potentially personal, user-controlled | `<issuer-domain>/keys/<label>#<name>`, whose domain prefix MUST equal `issuer.id` and therefore inherits that field's classification; the label is operator-chosen free text. About the `issuer`, never the `buyer`. Because issuers SHOULD use one signing key per period (v0.1 §7.3), the `kid` narrows a receipt's issuance to that key's period and groups every receipt signed within it — a coarse correlation handle that is a deliberate blast-radius control, not an oversight. |
| `signatures[].alg` | not personal | The literal `"Ed25519"` for v0.1. A v0.2 envelope carries exactly two entries in fixed order, `"Ed25519"` then `"ML-DSA-65"`, sharing one `kid` (v0.2 §2.2). MUST NOT be used to select a verification primitive. |
| `signatures[].sig` | not personal | Opaque signature bytes over `JCS(payload)`: base64url, 64 decoded bytes for Ed25519, 3309 for ML-DSA-65. The value is stable within a given envelope and carries no plaintext beyond the signed payload. |
| `delivery.salt` | not personal | Base64url of the 16 raw bytes used as the buyer-commitment salt (v0.1 §4.2, §8.1) — random bytes that describe nobody. What matters is what holding them enables: with the receipt's own `commitment` and `identifier_type`, an attacker can mount an offline dictionary attack against the identifier (TM-18), and a disclosed `(identifier, salt)` pair is a replayable bearer proof that also hands over the identifier itself (v0.1 §8.1, TM-19). An envelope carrying this member is a **private artifact** and implementations MUST strip it before treating the envelope as shareable. It is unsigned, so it can be removed — and stripped in transit (TM-12) — without invalidating anything. |
| `delivery.issuer_manifest` | — | Optional embedded key-manifest snapshot; see §2.8 for its field classifications. A manifest that arrived this way is unauthenticated TOFU and MUST be reported as `trust: "unauthenticated_tofu"` (v0.1 §7.4). |

### 2.8 Key manifests (v0.1 §7.1; v0.2 §2.3)

A key manifest is a public document, published by an `issuer` at a well-known URL. Its defined fields contain no buyer-derived value.

| Field | Classification | Notes |
| --- | --- | --- |
| `issuer` | potentially personal, user-controlled | DNS domain; MUST equal the domain prefix of every listed `kid`. Same consideration as `issuer.id` (§2.2). |
| `manifest_version` | not personal | Monotonically increasing integer per issuer; rotation continuity keys off `N → N+1` (v0.1 §7.3). |
| `issued_at` | not personal | UTC timestamp of manifest publication. |
| `keys` | — | REQUIRED array of key-entry objects; each entry is classified below. |
| `keys[].kid` | potentially personal, user-controlled | Same as `signatures[].kid` (§2.7). |
| `keys[].pub` | not personal | Ed25519 public key, base64url, 32 decoded bytes; published by design. |
| `keys[].pub_ml_dsa_65` | not personal | ML-DSA-65 public key, base64url, 1952 decoded bytes; REQUIRED for a hybrid signer's entry, absent otherwise (v0.2 §2.3). Its presence discloses that this signer is hybrid — an operational fact about the `issuer`, not about anyone else. |
| `keys[].valid_from` | not personal | UTC timestamp bounding the key's window. |
| `keys[].valid_to` | not personal | UTC timestamp or `null`/absent for open-ended. |
| `keys[].status` | not personal | Enum `active` \| `retired` \| `compromised`. Publishing `compromised` is an operational disclosure about the `issuer` with retroactive, fail-closed effect on every signature that key ever made (v0.1 §7.3). |
| `manifest_signature.kid` | potentially personal, user-controlled | Same operator-chosen `kid` form and issuer consideration as `signatures[].kid` (§2.7). |
| `manifest_signature.sig` | not personal | Opaque Ed25519 signature over `JCS(manifest)` with this member removed; stable within the signed manifest and carries no plaintext. |
| `manifest_signature.sig_ml_dsa_65` | not personal | Opaque ML-DSA-65 leg over the same signed bytes, REQUIRED iff the signing key entry carries `pub_ml_dsa_65`, absent otherwise; AND-verified fail-closed in both directions (v0.2 §2.3). |

### 2.9 Artifact manifests (v0.1 §7.2; v0.2 §13)

An artifact manifest is series-level product state, shared by every buyer of that series. Its defined fields carry no buyer-derived value.

| Field | Classification | Notes |
| --- | --- | --- |
| `issuer` | potentially personal, user-controlled | DNS domain; MUST equal the resolving key manifest's `issuer`. Same consideration as §2.2. |
| `series` | potentially personal, user-controlled | Free-form string matching `work.artifact_series`; same consideration as that field (§2.4). |
| `version` | not personal | Integer. |
| `released_at` | not personal | UTC timestamp, checked against the signer key's window. |
| `artifacts[]` | potentially personal, user-controlled | The v0.1 §5.4 artifact shape (`role`, `platform`, `filename`, `size_bytes`, `sha256`); classified as in §2.4. The per-buyer-build case is a misuse here rather than a deployment choice, since a manifest describes the current artifact set for a whole series. |
| `manifest_signature.kid` | potentially personal, user-controlled | Same operator-chosen `kid` form and issuer consideration as `signatures[].kid` (§2.7). |
| `manifest_signature.sig` | not personal | Opaque Ed25519 signature over `JCS(manifest)` with this member removed; stable within the signed manifest and carries no plaintext. |
| `manifest_signature.sig_ml_dsa_65` | not personal | Optional opaque ML-DSA-65 leg over the same signed bytes; where present, it is AND-verified under the v0.2 §13 rule. |

### 2.10 Revocation records (v0.1 §12; v0.2 §13)

A revocation record has no dedicated buyer identifier, commitment, or salt member. Its defined buyer-related reference is the receipt identifier it names.

| Field | Classification | Notes |
| --- | --- | --- |
| `receipt_id` | pseudonymous | ULID of the receipt the record refers to; inherits §2.1's classification and its timestamp property. This is the record's only link to a purchase, and it is a link a party must already hold the receipt (or the identifier) to resolve. |
| `status` | not personal | Only the literal `"revoked"` carries revocation meaning in v0.1. |
| `revoked_at` | not personal | The record's own signed ISO-8601 UTC time — what window checks are evaluated against, never the verifier's clock (v0.1 §12.1). |
| `signature.kid` | potentially personal, user-controlled | Same operator-chosen `kid` form and issuer consideration as `signatures[].kid` (§2.7). |
| `signature.sig` | not personal | Opaque Ed25519 signature over `JCS(record)` with this member removed; stable within the signed record and carries no plaintext. |
| `signature.sig_ml_dsa_65` | not personal | Optional opaque ML-DSA-65 leg over the same signed bytes; where present, it is AND-verified under the v0.2 §13 rule. |

**On the freshness anchor.** `T` in `not_revoked_as_of:<T>` is the maximum `revoked_at` across **all authenticated records** the `verifier` consulted, regardless of which `receipt_id` they target (v0.1 §12.3). It therefore describes how current the verifier's feed is, not one receipt's history, and reporting it discloses nothing about the receipt being verified. Neither specification defines how a revocation view is obtained; v0.1 §11 takes it as an already-supplied input. Whether checking revocation discloses to an `issuer` which receipt is being verified is consequently a property of a deployment's fetch pattern — a whole-feed fetch discloses nothing about a particular receipt, a per-receipt query discloses exactly which one — and it is a property no conformance requirement constrains.

### 2.11 Log entries (v0.2 §8)

Log entries are **content-free by construction** in a precise sense: their closed schemas exclude receipt payload and buyer content. They retain a non-authenticated `issuer` hint, which is potentially personal about the `issuer`, and opaque hashes that commit to artifacts. Exactly two versioned types are defined, each with exactly the required member set and no more; unknown members are rejected outright rather than silently tolerated; and every member is a domain name, a version integer, or a lowercase-hex hash. That closure leaves nowhere for attacker-chosen payload content to live (TM-51). No payload field or plaintext fragment of one is ever admitted to a log.

`key-manifest` entry — exactly these four members:

| Field | Classification | Notes |
| --- | --- | --- |
| `type` | not personal | The literal `"key-manifest"`. |
| `issuer` | potentially personal, user-controlled | Lowercase DNS name, same shape as `issuer.id`; same consideration as §2.2. |
| `manifest_version` | not personal | Integer, `1 ≤ n ≤ 2^53 − 1`. |
| `manifest_sha256` | not personal | `SHA-256(JCS(manifest))` — the hash of a public issuer document, in 64 lowercase-hex characters. |

`receipt` entry — exactly these three members:

| Field | Classification | Notes |
| --- | --- | --- |
| `type` | not personal | The literal `"receipt"`. |
| `issuer` | potentially personal, user-controlled | Lowercase DNS name, and normatively a **NON-AUTHENTICATED hint** for log browsing and filtering: a conforming `verifier` MUST NOT read it as attribution, because the receipt's own signature is what binds it to an issuer. Two consequences follow for this document. It is the only member of a `receipt` entry that is not a hash, so an entry stream discloses per-issuer activity in submission order; and because neither specification defines submitter authentication (TM-51's tracked gap), anyone may submit an entry naming any issuer, so what it discloses is unverifiable in either direction. |
| `core_sha256` | pseudonymous | The signed-receipt-core hash, `SHA-256("attest-receipt-core-v1" \|\| 0x00 \|\| JCS(payload) \|\| 0x00 \|\| JCS(signatures))`, in 64 lowercase-hex characters (v0.2 §12). This is the ONLY receipt-entry hash domain; a conforming implementation MUST NOT define or accept another. It stands for one receipt without revealing any part of it: the preimage includes a 32-byte commitment, a ULID with 80 bits of randomness, and the signature bytes themselves, so recovering a payload from the hash is not a guessing problem an adversary can mount. What it does permit is **confirmation**: any party that already holds a candidate receipt can recompute this hash and learn whether that exact receipt is in the log. `delivery` is excluded from the hash entirely, so stripping the salt never invalidates a receipt's log entry. |

### 2.12 Checkpoints (v0.2 §9)

A checkpoint is an aggregate statement about the whole tree. It contains no per-receipt and no per-buyer value of any kind.

| Field | Classification | Notes |
| --- | --- | --- |
| `origin` | potentially personal, user-controlled | First header line; non-empty printable ASCII (`0x20`–`0x7e`), naming the log and pinned in the verifier's own configuration. The character constraint permits a person's name, email address, or other identifier. |
| `tree_size` | not personal | Second header line, ASCII decimal without leading zeros. It discloses the log's total entry count at that point — aggregate volume across every issuer using the log, attributable to no one. |
| `root` | not personal | Third header line, standard-base64 32-byte RFC 6962 Merkle tree hash over the leaf hashes. |
| signature `name` | potentially personal, user-controlled | The `name` in `— <name> <base64(key-hash \|\| signature)>`; non-empty printable ASCII (`0x21`–`0x7e`, no `+`) naming the log key. The character constraint permits a person's name, email address, or other identifier. |
| signature key-hash and signature legs | not personal | The base64 `key-hash \|\| signature` value; both Ed25519 and ML-DSA-65 legs are REQUIRED and AND-verified against a pinned `LogKey` (v0.2 §9.2). |

### 2.13 Transparency evidence and the bundle `proofs/` member (v0.2 §10.2, §14)

An evidence bundle is entirely untrusted input, evaluated at most one per claim, and MAY travel inside an export bundle as a `proofs/` member.

| Field | Classification | Notes |
| --- | --- | --- |
| member name `proofs/<ULID>.json` | pseudonymous | A conforming bundle contains `proofs/` members **only** in this shape, where `<ULID>` is exactly the receipt's own `receipt_id` (v0.2 §14; the ULID-only grammar exists to close a path-traversal hazard, TM-45). The member name therefore discloses a `receipt_id`, and with it that identifier's embedded issuance time, to anyone listing the archive — before any file is opened. |
| `entry` | see §2.11 | The claimed log entry, in one of the two closed shapes; it MUST deep-equal the entry the `verifier` independently computed from the artifact being corroborated. |
| `leaf_index` | not personal | The entry's position in the tree. It discloses where in the log's append order this artifact sits — coarse ordering relative to every other entry, and thus a bound on issuance order. |
| `tree_size` | not personal | MUST equal the verified checkpoint's own; see §2.12. |
| `inclusion_proof` / `consistency_proof` | not personal | Lists of 64-hex-character sibling hashes forming an RFC 6962 path through the tree — leaf hashes of *other* entries and interior hashes over subtrees of them. Since every entry is itself content-free (§2.11), a proof discloses nothing about any other issuer's or buyer's artifacts beyond the fact that entries exist. |
| `checkpoint` / `prior_checkpoint` | potentially personal, user-controlled | C2SP signed-note text carried whole, so it inherits the classification of its parts: `tree_size` and `root` are not personal, but the `origin` header line and the signature `name` are free printable ASCII that may carry a person's name, email address, or other identifier (§2.12). |
| `anchors` (`ots`) | not personal | A hash-only op-chain of `sha256`/`append`/`prepend` operations starting from `SHA-256(checkpoint.note_bytes)` and terminating on a Bitcoin header pinned in the verifier's own `AnchorPolicy` (v0.2 §11.1). Hashes and public blockchain data throughout. |
| `anchors` (`rfc3161`) | potentially personal, user-controlled | An RFC 3161 token accepted as **OPAQUE** evidence — "parsed only far enough to note its presence, never validated as a certificate chain" (v0.2 §11.1). Its content is consequently unconstrained and uninspected by any conforming implementation: whatever bytes an assembler places there travel in the bundle unexamined. It sets `anchored: true` while contributing nothing to `transparency`. |

### 2.14 Shareable bundle `<name>.attest` (v0.1 §14.1)

| Member | Classification | Notes |
| --- | --- | --- |
| `receipts/*.attest.json` | see §2.1–§2.7 | Full envelopes with `delivery.salt` stripped from every one. **The salts are the only thing removed**: every other field of every receipt is present in full, as signed. "Shareable-safe" is a statement about binding secrets, not about purchase history (TM-16). Member naming beyond the `.attest.json` suffix is unconstrained by the specification. |
| `manifests/<issuer>.json` | see §2.8, §2.9 | Key and artifact manifests; the member name itself discloses which issuers the holder has bought from, before any file is opened. |
| `legal/<sha256>.txt` | potentially personal, user-controlled | The license texts, mirror policies, and end-of-life commitment documents referenced by every included receipt, each verified against its hash binding at export time. Conventionally an issuer's standard public terms; because `terms_uri` is per-receipt, an `issuer` may hash-bind a document specific to one sale, and that document's content is unconstrained. The member name is the document's own hash. |
| `proofs/<ULID>.json` | see §2.13 | OPTIONAL. Reserved in v0.1 §14.1, given its shape and contents by v0.2 §14. |
| `README.html` | potentially personal, user-controlled | Generated and human-readable. The specifications fix what it MUST explain — what the bundle is, how to verify it if the issuing store no longer exists, which file MUST NOT be shared (v0.1 §14.1), and that a `proofs/` entry is corroboration rather than authenticity (v0.2 §14) — never what else it may render. In practice it renders the bundle's own contents for a human, which is the whole receipt set in readable form. |

### 2.15 Private bundle `<name>.private.attest` (v0.1 §14.2)

This file MUST be named and documented as private, and a conforming CLI implementation MUST warn whenever it is accessed. The split reduces accidental sharing; it does not protect the file against theft, detect that theft, or revoke what the file exposes (TM-15).

| Member | Classification | Notes |
| --- | --- | --- |
| `salts.json` | pseudonymous | A `receipt_id → salt` map. Individually each salt is 16 random bytes (§2.7); as a file it is an index enumerating every receipt the holder has and the salt for each, so it converts a per-receipt exposure into a whole-library one. Holding it alongside the receipts enables commitment recomputation, and offline dictionary recovery of the identifier, for every receipt at once (TM-18, TM-15). |
| `keys/` | pseudonymous | Per-receipt `buyer` binding keypairs, where used (v0.1 §8.2). These are the private halves of the `buyer.pubkey` values in §2.3; a holder can answer any fresh binding challenge as that buyer, for every affected receipt (TM-35). v0.1 defines no binding-key revocation or rotation path. |

### 2.16 No dedicated fields by default

Open strings — especially the unconstrained keys and values of `work.identifiers` — URI strings, referenced legal documents, `README.html`, and additional signed payload members can carry identities, email addresses, IP addresses, device identifiers, payment data, or special-category data. No payload object sets `additionalProperties: false`, so a conforming receipt can carry such content even though no defined member is dedicated to it. The list below identifies only the absence of a dedicated specified member; it never guarantees that the data is absent from an artifact:

- **No dedicated plaintext buyer-identity member.** The specified `buyer` properties are `commitment`, `identifier_type`, and `pubkey`; none is a name, an account name, or a customer number.
- **No dedicated email-address member.** `email` appears as an `identifier_type` value naming which population an opaque commitment was computed over; no defined member is dedicated to the address itself.
- **No dedicated payment-data member.** Price, currency, total, payment method, card, account, and transaction reference are not defined receipt members. v0.1 §2 places payment processing out of scope outright: a receipt records the outcome of a purchase, not the purchase transaction, and MUST NOT be construed as a payment instrument.
- **No dedicated device-identifier member.** Hardware identifier, installation identifier, and machine fingerprint are not defined members of the artifacts inventoried above.
- **No dedicated IP-address member.** attest defines document formats, canonicalization, and verification, and no delivery transport at all (v0.1 §2, TM-13); a deployment's chosen channel may expose addresses outside the formats, while the formats define no address member.
- **No dedicated postal or billing-address, date-of-birth, age, residence-jurisdiction, or special-category member.** `jurisdiction_flags` is a defined assertion about a sale's conditions, never a defined assertion about where the `buyer` is (§2.5).
- **No dedicated behavioural or usage-data member.** attest is content-free with respect to hosted or indexed works: a conforming implementation MUST NOT host or index the works a receipt refers to (v0.1 §2). The specified artifacts define no member for an opening, playing, reading, or download event.

For its defined buyer-binding fields, the payload carries the buyer commitment described in §2.3: **scrypt over a store-scoped identifier by default, salted per receipt.** `issuer-account` — an identifier meaningful only within one store, whose disclosure links nothing globally — is the RECOMMENDED `identifier_type`, and the 16-raw-byte salt is generated fresh for every receipt, so the same identifier commits to an unrelated value in each one (v0.1 §8.1).

**The bound on this list.** It describes the field set the specifications define, not a constraint conforming implementations enforce. A deploying `issuer` can place any of the above in an additional signed member and the receipt will verify cleanly — with a warning if that member is top-level, and with no mandated warning at all if it is nested inside `issuer`, `buyer`, `work`, `license`, or `survivability` (v0.1 §11.2, TM-21). The same holds without any extension at all for the open fields in §2.4–§2.6 and for the referenced documents and `README.html`; no `verifier` can detect the meaning an `issuer` placed there.

## 3. What each observer learns

Each subsection below takes one party, assumes it behaves exactly as the specifications permit, and asks what it learns. The four RFC 6973 lenses fixed in §1 are applied in the same order throughout: surveillance, correlation, identification, disclosure. Where an exposure has a matching entry in `attest-threat-model.md`, it is cross-referenced by ID rather than re-analyzed.

Two properties recur and are stated once here. First, the analysis is about what a party is *able* to learn from the artifacts and mechanisms these specifications define — not about what a party's own systems, logs, or business records already contain for other reasons. Second, no `verifier` verdict, warning, or result component discloses anything to anyone by itself: the layered `VerificationResult` (v0.1 §11.1, v0.2 §10.1) is computed locally and its values are derived from artifacts the verifying party already holds.

### 3.1 `issuer`

**attest does not hide the `buyer` from the `issuer`, and does not try to.** The `issuer` computes `buyer.commitment` from an identifier it already holds, generates the 16-byte salt itself (v0.1 §8.1), and chooses the content of every free-form field in the payload. The commitment protects the buyer's identity against third parties; against the party that constructed it, it protects nothing and was never meant to.

- **Surveillance.** The `issuer` observes issuance, which it performs. Beyond that, the protocol hands it two signals it would not otherwise have, both weaker than they first appear. `trust: "verified"` requires the trust store's provenance for that issuer to be a TLS fetch from the issuer's own domain (v0.1 §7.4, §11.1), so a party reaching that verdict fetched the key manifest at some point — but that fetch populates or refreshes a trust store rather than occurring per verification (v0.1 §7.4 requires offline verification to work from a local store), and the manifest is one document shared by every receipt the issuer ever signed. What the issuer learns is that some party is holding or checking its receipts at all, from that network location; never which receipt. Revocation is the sharper case: if a deployment resolves it by per-receipt query, that query discloses exactly which receipt, while a whole-feed fetch discloses nothing about any one (§2.10). Neither pattern is specified, so which one a deployment exposes is a deployment decision, not a protocol property.
- **Correlation.** Total, within its own scope. The `issuer` can recompute any commitment it ever issued from the identifier and salt it holds, so it can recognize its own receipts and join them to its own customer records; per-receipt salts do not impede a party that knows the salts. `supersedes` lineage, `work.identifiers`, and any per-buyer `filename`/`sha256` add nothing it does not already have. What the per-receipt salt *does* bound is what happens after the issuer's records leave the issuer: a leaked salt exposes one receipt, not a library (TM-18).
- **Identification.** Not a threshold the `issuer` has to cross. It holds the plaintext identifier by construction.
- **Disclosure.** The `issuer` chooses what the artifact discloses to everyone downstream. Data minimization in attest is therefore an issuance-time decision, exercised through three levers the format provides: preferring `identifier_type: "issuer-account"` over `email` (v0.1 §5.3), keeping open string fields — especially `work.identifiers` (§2.4) — free of order and customer identifiers, and adding no unrecognized members. The format supplies the levers; it cannot pull them, and no `verifier` can tell whether they were pulled.

Whether the `issuer` retains the salt after delivering it is undefined: v0.1 §8.1 requires it to be generated per receipt and delivered, and neither specification requires or forbids retention afterwards (TM-12 assumes an issuer that *can* still re-deliver; §7 of the threat model records the case where neither party retains it as an unrecoverable custody boundary).

### 3.2 An offline `verifier`

Offline verification MUST work from a local trust store with no issuer endpoint reachable, reporting `revocation: "unknown"` honestly rather than failing closed (v0.1 §7.4, §11.2). This is the protocol's strongest privacy posture and it is normatively required to work, which matters beyond privacy: it is the same property that makes evidence survive a `coercive third party` compelling an `issuer` (TM-57).

- **Surveillance.** None, in the offline case, in either direction: verification emits no network traffic, so no third party observes that a receipt was checked and the `issuer` does not learn it either. This holds only while the verifier's trust store, revocation view, and any transparency evidence are already local — which the `proofs/` bundle member exists to make possible for the Stage 2 path too (v0.2 §14). A verifier that fetches instead trades exactly that property for freshness, as §3.1 and §3.4 describe.
- **Correlation.** Bounded by what it is given. A `verifier` handed one envelope learns that one purchase; a `verifier` handed a bundle learns the whole library in it (§3.5). Nothing in the verification algorithm accumulates state across invocations, and `buyer.pubkey` equality across two receipts MUST NOT be treated as proof of buyer identity (v0.1 §8.2) — a rule that constrains the verdict a conforming verifier may reach, not what a curious operator can notice (§2.3).
- **Identification.** For the canonical buyer-binding fields, a `verifier` running the algorithm in v0.1 §11 without a disclosure sees no plaintext buyer identifier: `binding` stays `not_checked`, and `binding` is not a component of `ok` (v0.1 §11.1). Verification and identification through those fields are therefore separate by default. This does not constrain direct identification through `work.identifiers`, other open strings, referenced legal documents, `README.html`, or additional payload members; a supplied receipt can carry such content and still verify fully green.
- **Disclosure.** Everything in the artifacts supplied: the full signed payload of every receipt, the issuer's public key material, and the referenced legal texts where a bundle carries them. That is the design — a receipt is evidence, and evidence that cannot be read is not evidence — but it means the granularity of what a verifier learns is the artifact, never the field. There is no selective disclosure of parts of a receipt (§2, structural facts); the only granularity control is sharing one receipt rather than a library (v0.1 §13).

### 3.3 `log operator`

A Stage 2 log sees only what §2.11 inventories: closed entries containing a non-authenticated `issuer` hint plus manifest or receipt-core hashes, never receipt payload or buyer content. **Content-free** here excludes receipt payload and buyer content; it does not mean an entry has no potentially personal data, because `issuer` is potentially personal about the `issuer`. Exactly two entry types are defined, each closed to exactly its required members, with every member a domain name, a version integer, or a lowercase-hex hash. An entry whose type or member set does not match is rejected outright rather than partially trusted (v0.2 §8).

- **Surveillance.** The `log operator` observes submissions as they arrive, so it sees the append-order and arrival timing of entries, and — via each `receipt` entry's `issuer` member — the claimed issuer of each. That yields per-issuer submission volume and timing over the life of the log. Two caveats bound what it is worth. The `issuer` member is a NON-AUTHENTICATED hint that a conforming `verifier` MUST NOT read as attribution (v0.2 §8), and neither specification defines submitter authentication, quotas, or rate limits (TM-51's tracked gap), so any party may submit an entry naming any issuer and the resulting volume figures are unverifiable in both directions. Submission is also not necessarily performed by the `issuer`: nothing in the protocol says who submits, and bulk-logging historical stock is RECOMMENDED rather than specified (v0.2 §15 item 2).
- **Correlation.** Across entries, only what a stream of hashes and issuer hints supports: how many entries claim a given issuer, and in what order. `core_sha256` is a per-receipt value, so the log operator can count distinct receipts claimed for an issuer. The core hash has buyer fields in its opaque preimage, but the entry exposes no separately addressable buyer field; it supplies no way to group entries by buyer or join two entries to one purchaser.
- **Identification.** Buyer identification is not reachable from the log's closed entry contents alone. Recovering a payload from `core_sha256` would mean inverting SHA-256 over a preimage that includes a 32-byte scrypt commitment, an 80-bit-random ULID, and the signature bytes themselves — not a guessing problem. The `issuer` hint can itself identify an `issuer`, as its classification in §2.11 records. What the hash does permit is confirmation in the other direction: a party that **already holds** a candidate receipt can recompute the hash and learn whether that exact receipt is logged. That is a check on a receipt one already has, never a route from the log to a receipt one does not.
- **Disclosure.** The log discloses that an artifact with a given hash existed at a point in the log's history, and nothing about who was entitled to write it — `corroboration` says an artifact was independently observable, never who was entitled to write it, and the log NEVER upgrades `trust` (v0.2 §15 items 3 and 4, TM-26). Checkpoints disclose aggregate tree size and a Merkle root, neither attributable to anyone, plus whatever the `log operator` itself chose to put in the `origin` line and the signature `name` — free printable ASCII that may carry an identifier, and a property of the operator rather than of any `buyer` or `issuer` (§2.12).

### 3.4 `mirror operator`

A `mirror operator` republishes the log's static, mirrorable file set — `entries.jsonl`, tiles, checkpoints (v0.2 §7.2). It therefore learns from the files exactly what §3.3 describes and no more: it holds the same closed entries, which exclude receipt payload and buyer content while retaining non-authenticated `issuer` hints. Everything a mirror serves is untrusted evidence, exactly like the log's own primary host or an adversary (v0.2 §10.2, TM-27) — a trust property, and it does not change what the mirror sees.

- **Surveillance.** Request-side surveillance accrues to whichever party serves the static files — the log's primary host or a mirror alike. That party observes who fetches which files, and when. How much that discloses depends on the granularity the file set offers, and the substrate is coarse rather than per-entry: `entries.jsonl` is one whole-log file whose retrieval narrows nothing, and a level-0 tile covers up to 256 leaves (v0.2 §7.2), so a tile request narrows the requester's interest to a window of that size rather than to one entry. That is a real signal — a requester repeatedly fetching one window, from one network location, is distinguishable from one fetching the whole log — but it is not the per-receipt disclosure a naive reading would assume. Neither specification defines a private-retrieval mechanism, a batching rule, or cover traffic, so what remains is unaddressed rather than bounded.
- **Correlation.** Over time, a mirror can link repeated requests from one requester into a profile of which regions of the log that requester keeps returning to. The protocol offers one effective countermeasure and names it for a different reason: a `.attest` bundle MAY carry each receipt's evidence as a `proofs/<ULID>.json` member so that verification stays offline (v0.2 §14, TM-58), and a verifier that uses it makes no request to any mirror at all. That is the difference between §3.2's zero-traffic posture and this one.
- **Identification.** The mirrored entry set contains no direct buyer content, but its `issuer` hints can identify an `issuer` (§3.3, §2.11). What a mirror sees of a requester's own network identity comes from the transport it chose to serve over, which attest does not define (v0.1 §2, TM-13).
- **Disclosure.** Identical to §3.3, since the file set is identical. A mirror can also simply withhold evidence, which is an availability question rather than a privacy one (TM-27), and cannot fabricate any, since standing requires a checkpoint verifying under a `LogKey` pinned out-of-band in the verifier's own trust store (v0.2 §10.2).

### 3.5 Any holder of a shareable `.attest` bundle

This covers the intended recipient of a bundle a `buyer` shared, a later recipient it was forwarded to (TM-16), and a `network attacker` that stole it (TM-14) — the format treats all three identically, because a bundle carries no access control of any kind.

- **Surveillance.** None from the bundle itself, which is a static archive. The `legal/`, `terms_uri`, `mirror_policy_uri`, and `eol_commitment_uri` paths are the exception worth naming: a holder that follows a URI rather than reading the hash-bound copy in `legal/` announces itself to whoever hosts it, and where an `issuer` used a per-buyer URI (§2.5) that fetch is attributable to one sale.
- **Correlation.** This is the bundle's central privacy property and it is a negative one: **the shareable bundle discloses the full content of every receipt it contains.** Stripping `delivery.salt` from every envelope is the only redaction the format performs (v0.1 §14.1); issuer, work, edition, timestamps, license terms, and artifact rows are all present exactly as signed. The `manifests/<issuer>.json` member names disclose which issuers the holder bought from before any file is opened, and `proofs/<ULID>.json` member names disclose receipt identifiers and, through the ULID timestamp prefix, issuance times (§2.13). One bundle is therefore a purchase history, and a purchase history over books, films, games, or music can carry inferences well beyond the transactions themselves. The threat model states the same bound from the other direction: the two-file split protects binding secrets, not purchase-history privacy (TM-16 residual). The protocol's answer is granularity rather than redaction — `attest disclose` exists so that sharing one receipt never means forwarding a library (v0.1 §13) — and that answer only helps a `buyer` who uses it.
- **Identification.** From the canonical buyer-binding fields alone, a shareable bundle does not enable identifier recovery: no salt is present, so a commitment cannot be tested against a candidate identifier even by dictionary attack. That bound does not apply to open and additional fields or to the documents the bundle carries. The holder gains `receipt_id` values and any direct identifier the `issuer` wrote into `work.identifiers`, another open string, an additional payload member, a referenced legal document, or `README.html`; a per-buyer URI in `terms_uri` likewise supplies a plaintext handle into the issuer's records without any attack.
- **Disclosure.** Possession proves nothing about the holder: with no salt in the file, `binding` stays `not_checked` or `not_proven` absent a disclosed `(identifier, salt)` or a fresh challenge-response against `buyer.pubkey` (TM-14). But `binding` is not a component of `ok` (v0.1 §11.1), so a relying party that never requests a binding proof gains nothing from that separation, and `buyer.pubkey` is OPTIONAL and `null` by default for client-less flows (v0.1 §5.3).

### 3.6 A `verifier` that received a per-receipt disclosure

`attest disclose <receipt_id>` MUST emit exactly one receipt plus its manifests **plus its salt** (v0.1 §13). The recipient is therefore in a materially different position from §3.5's bundle holder, for that one receipt, before any binding proof is even attempted.

- **Surveillance.** None from the artifact. As in §3.5, following a URI rather than reading the hash-bound copy is the exception.
- **Correlation.** Per-receipt salts confine only commitment-path exposure: a salt disclosed here is useless for recomputing another receipt's commitment (v0.1 §8.1, TM-19). That does not confine correlation across the rest of the receipt set. A reused `buyer.pubkey`, `supersedes` lineage, customer or order identifiers in `work.identifiers` or other open/additional fields, per-buyer artifact values, and per-sale legal documents can still join receipts; a recipient that accumulates disclosures also extends the commitment-path set by one each time.
- **Identification.** This is where the exposure concentrates. Holding the salt alongside the receipt's `commitment` and `identifier_type`, the recipient can mount an offline dictionary attack against the identifier without any further cooperation: scrypt at the specification's fixed parameters **raises** the cost of that attack, it does not eliminate it, and the parameters MUST NOT be tuned upward per-issuer (v0.1 §8.1, TM-18). Against `identifier_type: "email"` — the guest-checkout case, drawn from exactly the guessable population v0.1 §8.1 names as its reason for choosing scrypt — a successful recovery yields not just this purchase but a globally-scoped identifier that links the `buyer` across issuers. This exposure exists whether or not a binding proof is ever requested, because `disclose` emits the salt regardless.
- **Disclosure.** If the `buyer` then proves binding by the commitment path, they hand over the identifier itself, and doing so is a **replayable bearer proof**: the recipient can re-present the same `(identifier, salt)` pair to claim buyer status for that receipt afterwards, and the disclosure permanently burns that receipt's binding secrecy toward that verifier (v0.1 §8.1, TM-19). The non-replayable alternative exists and is RECOMMENDED wherever a client app can hold a key — a challenge-response over a fresh nonce of at least 16 bytes, bound to `receipt_id`, which proves possession without handing over anything reusable (v0.1 §8.2). Two limits keep this from being a general answer. `buyer.pubkey` is `null` by default for client-less flows (v0.1 §5.3), so the replayable path is the common one rather than the exceptional one. And the protections v0.1 §8.1 attaches to a disclosed identifier are obligations on the recipient — a `verifier` MUST treat it as personal data not to be retained beyond the verification, and issuers SHOULD offer re-issue via `supersedes` afterwards — neither of which the `buyer` can enforce or verify once the identifier has left their hands.
