# attest — Threat Model

- **Status**: Living document, v0.1 (initial publication)
- **Date**: 2026-07-18
- **Grounding**: the protocol mechanisms analyzed here are grounded in `attest-v0.1.md` and `attest-v0.2.md` (v0.1 §2; v0.2 §1); this companion document declares the attacker assumptions and analytical vocabulary used to analyze those mechanisms.

## 1. Status and scope

This is a living normative companion to [`attest-v0.1.md`](attest-v0.1.md) and [`attest-v0.2.md`](attest-v0.2.md). It covers the shipped protocol as those two documents currently define it: the v0.1 baseline (envelope, canonicalization, Ed25519 signing, key/artifact manifests, buyer commitment and binding, revocation, export bundles), the v0.2 Stage 1 hybrid signature profile (`ed25519+ml-dsa-65`), and the v0.2 Stage 2 transparency and anchoring layer (log substrate, checkpoints, corroboration, anchoring, the CRQC horizon).

**Update rule.** Because this document's entries cite specific mechanisms in the normative specifications as evidence for a verdict, a specification change that adds, removes, or alters a mechanism invalidates any entry that cited it. Every future normative change to the attest specifications MUST update this document (and `attest-privacy.md`) in the same change cycle — a threat-model or privacy-model gap introduced by a spec change and left undocumented is itself a defect in that change, not a follow-up.

**Non-normative note:** except for this document's own maintenance obligation in the update rule and its catalog-vocabulary obligation in §2, this document analyzes and cross-references the normative text; it does not itself impose requirements beyond what `attest-v0.1.md` and `attest-v0.2.md` already state. Where an entry's rationale uses RFC 2119 keywords, it is restating or combining requirements that are normative in one of those two documents, not inventing new ones.

### Verdict vocabulary

Every attack-catalog entry (§4 onward) resolves to exactly one of two verdicts:

- **Mitigated** — the attack is prevented, detected, or bounded by one or more mechanisms already defined in `attest-v0.1.md` or `attest-v0.2.md`. The entry cites the exact section(s) that implement the mitigation.
- **Out of scope** — the attack is not addressed by the current specifications. The entry states the rationale: either the attack targets a layer attest deliberately does not define (e.g. payment processing, DRM — v0.1 §2), or it targets an actor's operational security that is not governed by v0.1 or v0.2; operational controls those specifications do govern, such as offline log-key custody, remain in scope (v0.2 §7.3).

A **Mitigated** verdict MAY still carry a residual-risk line. That line is not a hedge: it names the specific slice of the attack that no cited mechanism closes, so a mitigation already granted is never silently overstated as absolute. A residual risk with no proposed mitigation is left as an explicit, tracked gap (§6 onward), not smoothed over by the verdict.

### Conformance language

This document reuses, without redefining, the conformance language established in `attest-v0.1.md` §1: the key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** carry the RFC 2119 meaning, as clarified by RFC 8174, when and only when they appear in all capitals. Passages introduced with **Non-normative note:** carry no conformance weight. Verdicts and mechanism citations are descriptive of the referenced specifications; the update rule above and the catalog-vocabulary rule in §2 are this document's own normative obligations.

### Changelog

| Date | Change |
| --- | --- |
| 2026-07-18 | Initial publication: §1 status and scope, §2 system model, §3 attacker model. |
| 2026-07-18 | Attack catalog (§4, Groups A–I), traceability matrix (§5), forward-looking requirements (§6), consolidated out-of-scope register (§7). |

## 2. System model

### Actors

The following actor names are canonical for this document and every attack-catalog entry that follows (§4 onward) MUST use them verbatim, unqualified.

| Actor | Description |
| --- | --- |
| `issuer` | The domain-identified entity that signs receipts, key manifests, and artifact manifests (v0.1 §3, §7.1, §7.2); may act on behalf of a named `work.publisher` via the delegated-issuer path. |
| `buyer` | The holder of exported receipts and, where a client app exists, of an optional binding keypair (v0.1 §3, §8.2). |
| `verifier` | Any software that runs the verification algorithm against a receipt envelope — the v0.1 §11 algorithm, extended by the v0.2 §3 hybrid path and v0.2 §10 transparency/anchoring evaluation. |
| `log operator` | The operator of a Stage 2 transparency log, split into a CI-side append role and a separately-administered, offline ceremony-side signing role (v0.2 §7.2, §7.3). |
| `mirror operator` | An independent party republishing a Stage 2 log's static, mirrorable file set — entries, tiles, checkpoints (v0.2 §7.2). Anything it serves is untrusted evidence, exactly like the log's own primary host or an adversary (v0.2 §10.2). |
| `network attacker` | A party controlling the network path between any two other actors, with no key material of its own; modeled with Dolev-Yao capabilities (§3). |
| `coercive third party` | A government, court, or other party able to compel action from `issuer`, `log operator`, or `buyer` through legal process rather than technical compromise. |
| `supply chain` | The dependency, build, and release pipeline producing the reference implementation and its published packages; a compromise here does not require breaking any cryptographic primitive attest defines. |

### Assets

| Asset | Description | Primary spec grounding |
| --- | --- | --- |
| Issuer signing keys (both hybrid legs) | The Ed25519 key and, for a hybrid signer, the paired ML-DSA-65 key bound to the same `kid` (v0.1 §7.1; v0.2 §2.2, §2.3). | v0.1 §7.1; v0.2 §2.2 |
| Manifest continuity chain | The `manifest_version` N → N+1 rotation-trust chain that lets a verifier auto-trust a new key manifest without re-bootstrapping trust (v0.1 §7.3; v0.2 §4 for the hybrid AND-rule extension). | v0.1 §7.3; v0.2 §4 |
| Buyer commitment salts | The per-receipt, 16-raw-byte salts that randomize `buyer.commitment` and confine disclosure damage to one receipt; scrypt raises, rather than eliminates, dictionary-recovery cost (v0.1 §8.1). | v0.1 §8.1 |
| Optional buyer binding key (`buyer.pubkey`) | The buyer-held Ed25519 keypair used for the non-replayable challenge-response binding path; `null` by default for client-less flows (v0.1 §5.3, §8.2). | v0.1 §8.2 |
| Log signing key (offline custody) | The log's Ed25519/ML-DSA-65 checkpoint-signing key pair, held exclusively by the ceremony-side signing step and never by the CI-side append step (v0.2 §7.3). | v0.2 §7.3 |
| Checkpoint stream | The sequence of signed C2SP signed-note checkpoints attesting to successive tree roots of a Stage 2 log (v0.2 §9). | v0.2 §9 |
| `AnchorPolicy` | Trusted verifier-side configuration containing `pinned_headers`, the verifier's own Bitcoin-header trust store, and an optional `crqc_horizon` that controls post-horizon standing (v0.2 §11.2, §11.3). | v0.2 §11.2; v0.2 §11.3 |
| Revocation feed | The set of issuer-signed revocation records for issued receipts (v0.1 §12). | v0.1 §12 |
| Export bundles (shareable `.attest` / `.private.attest`) | The two-file export split: a shareable bundle with salts stripped, and a private bundle carrying salts and buyer keys (v0.1 §14.1, §14.2). | v0.1 §14 |

### Trust anchors

| Trust anchor | Spec ref | Description |
| --- | --- | --- |
| TOFU domain-control root | v0.1 §7.4 | A key manifest fetched over TLS directly from the issuer's own domain is v0.1's root of trust (`trust: "verified"`); a manifest that arrived by any other path is unauthenticated TOFU (`trust: "unauthenticated_tofu"`) and MUST NOT be silently upgraded. |
| Out-of-band pinned log keys | v0.2 §7.3 | A Stage 2 verifier's `LogKey` trust store ships baked into the verifier and is distributed and rotated out-of-band from any bundle; a conforming verifier MUST NOT take log keys from a bundle. |
| Offline log-key custody | v0.2 §7.3 | The log's signing keys are held exclusively by a separately-administered, offline ceremony-side step, never by the CI-side append process — the append path being compromised confers no signing capability. |

## 3. Attacker model

### Capability classes

- **Dolev-Yao network attacker.** Full control of the network between any two actors — read, drop, delay, reorder, replay, and inject arbitrary messages — but no ability to forge a signature without the corresponding private key and no ability to break the cryptographic primitives themselves. This is the default adversary against which every transport-independent, signature-based claim in `attest-v0.1.md` and `attest-v0.2.md` is evaluated.
- **CRQC attacker (cryptographically relevant quantum computer).** An attacker who, at some future point, gains a quantum computer capable of breaking classical signature schemes, including Ed25519 and the RSA/ECDSA-based RFC 3161 timestamping path; the hash-only OpenTimestamps leg is PQ-surviving (v0.2 §2.1; v0.2 §11.1). Horizon semantics are defined normatively in v0.2 §11.3 (`passes_horizon`): a verdict passes a configured `crqc_horizon` only if it is PQ-surviving and its `anchored_before` time is strictly earlier than that horizon. **Harvest-now-forge-later is explicitly in scope**: an attacker who records classical-signed material today and later gains a CRQC to forge or retroactively fabricate it is the scenario the hybrid signature profile bounds for future v0.2 receipts (v0.2 §2.1). For historical receipts, the signed-receipt-core commitment proves that the signature already existed before the horizon only when that receipt was actually logged and PQ-anchored before it (v0.2 §12; v0.2 §15 item 2).
- **Key-compromise scenarios.** Modeled per compromised key class, since attest's blast-radius containment differs by class:
  - *Single hybrid leg* — either the Ed25519 or the ML-DSA-65 half of a hybrid signer's key pair is compromised alone, while the other leg remains secure (v0.2 §2.2, §2.3).
  - *Both hybrid legs* — the full signer identity behind a `kid` is compromised. Before a resolving key manifest marks the key `compromised`, an attacker holding both private keys can forge receipts that verify while the key remains `active`; once a resolving manifest marks it `compromised`, every past signature by that key is retrospectively invalidated, regardless of `issued_at` (v0.2 §2.1; v0.1 §7.3).
  - *Log key* — the Stage 2 log's checkpoint-signing key is compromised, threatening the integrity of the checkpoint stream (v0.2 §7.3).
  - *Buyer key* — a buyer's optional `buyer.pubkey` binding key is compromised, threatening the strong binding path while leaving the base commitment (v0.1 §8.1) unaffected (v0.1 §8.2).
- **Malicious or equivocating log operator.** A `log operator` that deviates from honest operation: refusing to append entries, serving inconsistent views of the log to different parties, or presenting two signed checkpoints that disagree about the tree at the same size. attest's transparency layer treats the log as a corroboration source, never a replacement for domain-control trust (v0.2 §7.1); equivocation is a hard verdict only when the verifier already possesses both inconsistent, validly-signed checkpoints (v0.2 §10.3). Stage 2 supplies no mechanism to discover a hidden second branch; general split-view discovery requires the forthcoming witness federation (v0.2 §15 item 1).
- **Malicious issuer.** Bounded, by design: attest proves what an issuer signed, not that the issuer is honest. An issuer that signs a fraudulent receipt, misrepresents `work` or `license` terms, or issues receipts it has no authority to issue produces artifacts that verify cleanly — reputation and legal recourse against the issuer are client and marketplace concerns outside this protocol's cryptographic scope.
- **Coercive third party.** A `coercive third party` compelling `issuer`, `log operator`, or `buyer` through legal process — a subpoena, court order, or equivalent compulsion — rather than technical compromise. This class is capability-distinct from key compromise: the compelled actor retains valid key material and may be forced to use it (e.g. an issuer compelled to sign a backdated revocation, or a log operator compelled to withhold entries), which the mechanisms bounding pure key theft do not by themselves address.

## 4. Attack catalog

Entries are grouped by the lifecycle stage at which the attack is mounted: issuance (Group A), delivery (Group B), storage and sharing (Group C), verification (Group D), rotation and key compromise (Group E), revocation, refund, and end-of-life (Group F), the transparency log (Group G), anchoring (Group H), and coercion and supply chain (Group I). Every entry uses the format fixed in §1 — actor and precondition, impact, exactly one verdict from the §1 vocabulary with the specification sections that carry it, and a residual-risk line — and every entry names actors using the §2 canonical names verbatim.

An entry's verdict describes only what `attest-v0.1.md` and `attest-v0.2.md` currently implement. Where a mechanism bounds one slice of an attack and leaves another open, the open slice is named in the residual-risk line rather than absorbed into the verdict; where the residual is a gap with no mechanism behind it, the line says so in those words.

### Group A — Issuance

#### TM-01 — Receipt forgery without key compromise

- **Actor / precondition:** `network attacker` holds a genuine receipt and the published manifest but no `issuer` private key material.
- **Impact:** A fabricated receipt would verify as issuer-signed evidence of a license grant that was never made.
- **Verdict:** Mitigated — v0.1 §10, v0.1 §11, v0.2 §3.  Forgery requires a valid signature over `JCS(payload)` under the pinned RFC 8032 ruleset (non-canonical `S`, small-order and non-canonical `A`/`R` all rejected); for a v0.2 receipt both the Ed25519 and the ML-DSA-65 leg must independently verify against the same manifest key entry, so breaking one primitive is insufficient.
- **Residual risk:** The guarantee is exactly as strong as the manifest that resolves the key. A `verifier` that obtained that manifest by any path other than a TLS fetch from the issuer's own domain is in TOFU (v0.1 §7.4) and can be handed an attacker's self-signed manifest instead — TM-11.

#### TM-02 — Cross-issuer impersonation

- **Actor / precondition:** `issuer` controls valid key material for one domain and signs a payload that names a different issuer identity.
- **Impact:** One domain's signing key would vouch for receipts attributed to another domain.
- **Verdict:** Mitigated — v0.1 §11, v0.2 §3.  The signing key is resolved **only** from the trust store's manifest for `payload.issuer.id`, and both the `kid`'s DNS-domain prefix and the resolving manifest's own `issuer` field MUST equal it; the hybrid path applies the identical binding to the single shared `kid`.
- **Residual risk:** None identified. The check is unconditional, precedes any signature computation, and is pinned by conformance (v0.1 §15, vector 5).

#### TM-03 — Post-CRQC forgery against Ed25519-only receipt stock

- **Actor / precondition:** `network attacker` has CRQC capability to derive Ed25519 private keys from published public keys; the target receipts are v0.1 and classical-only.
- **Impact:** Arbitrary v0.1 receipts, including backdated ones, that verify cleanly — retroactively fabricated purchase history that is cryptographically indistinguishable from genuine stock.
- **Verdict:** Mitigated — v0.2 §2, v0.2 §10, v0.2 §11.3, v0.2 §12.  For a receipt whose signed-receipt-core was actually logged and PQ-anchored, the hash-only OpenTimestamps leg (PQ-surviving, unlike the classical RFC 3161 leg) proves the signature bytes existed at or before a Bitcoin header time pinned in the verifier's own policy, and a configured `crqc_horizon` refuses standing to anything not PQ-surviving and not dated strictly earlier; receipts issued under the v0.2 hybrid profile require both legs and are unaffected.
- **Residual risk:** v0.2 §15 item 2 scopes this honestly: un-logged stock gets no existence-before-`T` guarantee at all, however old and however strongly originally signed, and bulk-logging historical stock is RECOMMENDED rather than required. Further, the horizon gates `transparency` and `corroboration` only (v0.2 §10, v0.2 §11.3) — it can never make an Ed25519-only forgery report `signature: "invalid"`, so post-CRQC discrimination between genuine and forged legacy receipts rests entirely on the presence of anchored-before-horizon evidence, which is precisely what un-logged stock lacks.

#### TM-04 — Payload precommitment ("log now, sign later")

- **Actor / precondition:** `network attacker` can submit Stage 2 log entries before the horizon and later has CRQC capability to derive an `issuer` Ed25519 key.
- **Impact:** An entry logged and anchored early would appear to prove that a receipt in fact signed much later already existed before the horizon, laundering a post-horizon forgery into pre-horizon standing.
- **Verdict:** Mitigated — v0.2 §12, v0.2 §8, v0.2 §10.2.  The only accepted receipt-entry hash domain is the signed-receipt-core, `SHA-256("attest-receipt-core-v1" || 0x00 || JCS(payload) || 0x00 || JCS(signatures))`, which commits to the signature bytes themselves, so a log entry can only ever describe a signature that already existed at logging time; evidence whose `entry` does not deep-equal the entry the verifier independently computed from the artifact fails entry matching before any checkpoint is consulted (v0.2 §16, leaf 28l).
- **Residual risk:** The commitment binds the signature bytes, not the signer's honesty: an `issuer` that signs and logs a false receipt before the horizon obtains entirely genuine anchored standing for it (TM-05).

#### TM-05 — Issuer signs false or misleading receipt content

- **Actor / precondition:** `issuer` in control of its own signing key and domain, asserting a purchase, license term, or work identity that does not correspond to reality.
- **Impact:** A cleanly verifying receipt whose content is untrue.
- **Verdict:** Out of scope — v0.1 §2, v0.1 §6.1. attest proves what an issuer signed, not that the issuer is honest. The specification's own framing of a receipt is strictly evidentiary — evidence of a license grant and its terms, signed by the issuer identified in it, determining nothing about the seller's regulatory compliance, and even the strongest conditional v0.1 defines is "evidence, not a compliance determination" — so the truth of `work`, `license`, and `survivability` assertions is a reputational, contractual, and legal question the protocol deliberately does not adjudicate.
- **Residual risk:** A dishonest issuer's receipts are cryptographically indistinguishable from an honest one's, and Stage 2 logging corroborates their existence without vouching for their content (v0.2 §15 item 3). The only protocol-level consequence available — the fail-closed `compromised` status — is the issuer's own to publish (v0.1 §7.3).

#### TM-06 — Delegated-issuer misattribution of a publisher

- **Actor / precondition:** `issuer` on the delegated-issuer path signs a receipt that names a publisher which never authorized it.
- **Impact:** A named publisher of record appears to stand behind a license grant it never made.
- **Verdict:** Out of scope — v0.1 §5.4, v0.1 §4.1.  `work.publisher` is a signed but unattested string: v0.1 defines no publisher authorization or counter-signature semantics, and the multi-entry `signatures` array reserved for a future publisher counter-signature is explicitly rejected today (exactly one entry for v0.1; exactly two ordered hybrid legs for v0.2, v0.2 §2.2).
- **Residual risk:** A `verifier` cannot distinguish an authorized delegated issuer from an unauthorized one from the receipt alone; the only binding attestation in the document is the signing issuer's own.

#### TM-07 — Backdated `issued_at`

- **Actor / precondition:** `issuer` controls the signing key at signing time, including both hybrid legs where applicable.
- **Impact:** A receipt that claims to predate its real creation — manufacturing priority, landing inside a favourable window, or placing a forgery before a compromise marking.
- **Verdict:** Mitigated — v0.1 §11, v0.1 §7.3, v0.2 §11.1, v0.2 §12.  `issued_at` MUST fall inside the signed key entry's `[valid_from, valid_to]` window in the resolving manifest, so backdating cannot reach behind that key's own signed `valid_from`, and the per-period signing-key discipline narrows that window; for a logged and anchored receipt, `anchored_before:<T>` bounds the time by which the signature demonstrably already existed.
- **Residual risk:** v0.1 §7.3 states the limit plainly: because `issued_at` lives inside the signed payload and is controlled by whoever holds the key, a backdated forgery is undetectable without an external trusted timestamp — and `anchored_before:<T>` is an upper bound on existence, never a lower bound (v0.2 §11.1). Neither document defines a result component asserting that an artifact was *not* in the log before some time, so an `issued_at` earlier than reality but still inside the key window remains undetectable, and an issuer that also controls its manifest controls `valid_from`.

#### TM-08 — Bogus `supersedes` lineage read as implicit revocation

- **Actor / precondition:** `issuer` or `network attacker` presents a later receipt whose supersedes field names the target receipt identifier.
- **Impact:** An earlier receipt is treated as retired without the buyer's consent and without a revocation record of the class its license actually permits.
- **Verdict:** Mitigated — v0.1 §5.1, v0.1 §6.2, v0.1 §12.  `supersedes` is normatively informational lineage: a superseding re-issue does not invalidate the superseded receipt absent buyer consent, and a `verifier` MUST treat it as lineage metadata only, never as an implicit revocation. The only mechanism that can change a receipt's revocation state is an authenticated revocation record classified against the license's own signed `revocability`.
- **Residual risk:** `supersedes` is an unverified pointer: nothing requires the named `receipt_id` to exist, to be verifiable, or to have been issued to the same `buyer`, so it can carry a misleading lineage claim that a human reader may over-interpret even though no conforming verifier acts on it.

### Group B — Delivery

#### TM-09 — In-transit tampering with a receipt

- **Actor / precondition:** `network attacker` controls the path between `issuer` and `buyer`, or between `buyer` and `verifier`.
- **Impact:** Altered license terms, work identity, artifact hashes, or timestamps inside an otherwise genuine receipt.
- **Verdict:** Mitigated — v0.1 §9, v0.1 §10, v0.1 §11, v0.2 §3.  `payload` is the sole signed object and every byte of it is inside `JCS(payload)`; any change breaks the Ed25519 leg — and, for a v0.2 receipt, the ML-DSA-65 leg over the same canonical bytes — yielding `signature: "invalid"` (v0.1 §15, vector 3).
- **Residual risk:** Only `payload` is signature-covered. `delivery` is unsigned by construction (v0.1 §4.2); TM-11 and TM-12 state what tampering there can and cannot achieve.

#### TM-10 — Hybrid downgrade of a v0.2 receipt in transit

- **Actor / precondition:** `network attacker` has a v0.2 hybrid envelope in flight and seeks classical-only evaluation.
- **Impact:** If the ML-DSA-65 leg could be stripped and the remainder treated as a v0.1-shaped receipt, breaking Ed25519 alone would again suffice to forge.
- **Verdict:** Mitigated — v0.2 §1, v0.2 §2.2, v0.2 §3.  `attest_version` is inside the signed payload and cannot be stripped or rewritten without invalidating the signature; a stripped PQ leg is not a valid fallback but an outright rejection (`hybrid envelope requires exactly two signatures`), and entry count, order, `alg` values, and the shared `kid` are all checked before either leg is verified (v0.2 §6, leaves 26d–26f).
- **Residual risk:** Downgrade resistance protects v0.2 stock only. A v0.1 receipt is Ed25519-only by definition and remains so forever (v0.2 §1); its classical exposure is TM-03, not a downgrade.

#### TM-11 — Substituted key manifest at delivery

- **Actor / precondition:** `network attacker` serves a manifest while `verifier` has no independently TLS-fetched manifest for the `issuer`.
- **Impact:** The attacker supplies a self-signed manifest naming the victim domain but listing its own keys; a matching forged receipt then reports `signature: "valid"` and `ok: true`.
- **Verdict:** Mitigated — v0.1 §7.4, v0.1 §11.1, v0.1 §4.2, v0.2 §15.  A manifest that did not arrive by a TLS fetch from the issuer's own domain is unauthenticated TOFU and MUST be reported as `trust: "unauthenticated_tofu"`, never silently upgraded; `trust` is resolved as early as `payload.issuer.id` can be read and MUST NOT be reset by a later step; and no amount of transparency or corroboration evidence may upgrade it (v0.2 §15 item 4).
- **Residual risk:** `trust` is not a component of `ok` (v0.1 §11.1), so this attack is signalled rather than prevented: a consumer that reads `ok` alone, or a UI that collapses the layered result into a boolean, cannot distinguish a TOFU-rooted forgery from a domain-rooted genuine receipt. The whole protection rests on the relying party reading `trust`.

#### TM-12 — Stripping `delivery.salt` in transit

- **Actor / precondition:** `network attacker` controls delivery carrying the salt, and `buyer` holds no other salt copy.
- **Impact:** The buyer permanently loses the ability to prove the buyer commitment for that receipt.
- **Verdict:** Out of scope — v0.1 §4.2, v0.1 §8.1, v0.1 §14.2. `delivery` is optional and unsigned, and neither specification establishes delivery reliability, detects removal, or recovers a salt when it was the `buyer`'s only copy. Custody of buyer binding secrets is a scope boundary of these specifications (§7), not a gap awaiting a mechanism: no protocol can reconstruct a secret that no party retains.
- **Residual risk:** Removing the salt neither forges nor invalidates the receipt, but it permanently prevents commitment-path binding for that receipt. A missing disclosure leaves `binding: "not_checked"`, which does not affect `ok`.

#### TM-13 — Interception of receipts in delivery

- **Actor / precondition:** `network attacker` has read access to the delivery channel carrying a bare receipt or private artifact.
- **Impact:** Exposure of purchase metadata, and — where the intercepted artifact is a private one — of the salt needed for a bearer-style binding proof.
- **Verdict:** Out of scope — v0.1 §2, v0.1 §13.  v0.1 and v0.2 define document formats, canonicalization, and verification; they define no delivery transport, and therefore no confidentiality property for one. TLS appears in the specifications solely as the manifest-fetch trust root (v0.1 §7.4), not as a delivery requirement. Channel confidentiality is the deploying party's.
- **Residual risk:** The protocol bounds the damage structurally rather than cryptographically: a shareable bundle carries no salts (v0.1 §14.1), while `delivery.salt` and `.private.attest` do (v0.1 §4.2, v0.1 §14.2). The privacy consequences of interception are analyzed in the companion `attest-privacy.md`.

### Group C — Storage and sharing

#### TM-14 — Stolen shareable `.attest` bundle presented as one's own

- **Actor / precondition:** `network attacker` possesses a `buyer`'s shareable bundle.
- **Impact:** Bearer-style presentation of someone else's purchase evidence.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §8.1, v0.1 §8.2, v0.1 §11.  The shareable bundle has `delivery.salt` stripped from every envelope, so possession alone proves nothing about the holder: `binding` stays `not_checked` or `not_proven` without either a disclosed `(identifier, salt)` or a fresh challenge-response against `buyer.pubkey`, and the per-receipt commitment confines any single disclosure to one receipt.
- **Residual risk:** A receipt's own validity is bearer-independent — `binding` is not a component of `ok` (v0.1 §11.1) — so a relying party that never requests a binding proof gains nothing from the separation. The theft-resistant path is also frequently absent outright: `buyer.pubkey` is OPTIONAL and `null` by default for client-less flows (v0.1 §5.3, v0.1 §8.2).

#### TM-15 — Stolen `.private.attest` bundle

- **Actor / precondition:** `network attacker` has access to the `buyer` storage or backups containing the private bundle.
- **Impact:** Every salt in the file becomes usable for commitment recomputation, and where per-receipt buyer keypairs are stored, the thief can answer binding challenges as the buyer for every affected receipt.
- **Verdict:** Out of scope — v0.1 §14.1, v0.1 §14.2, v0.1 §8.2. The two-file split reduces accidental sharing but does not protect the private file against theft, detect its theft, or revoke the exposed binding secrets. Custody of the private bundle is a scope boundary of these specifications (§7), not a gap awaiting a mechanism: v0.1 §8.2 places mandatory key custody outside the specification.
- **Residual risk:** Theft of a `.private.attest` bundle compromises every salt and buyer private key it contains. The private-file naming, documentation, and access warning requirements do not mitigate that theft; they only support the accidental-sharing case in TM-16.

#### TM-16 — Casual re-sharing of a shareable bundle

- **Actor / precondition:** `buyer` forwards an export to another recipient or public location.
- **Impact:** Unintended disclosure of binding secrets or of purchase history.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §14.2, v0.1 §13.  The file a buyer is invited to share contains no salts and no buyer keys; the private file is separately named and documented as unshareable; the bundle's generated `README.html` MUST explain which file MUST NOT be shared; and per-receipt `disclose` exists so that sharing one receipt never means forwarding a library.
- **Residual risk:** The shareable bundle still discloses the full content of every receipt it contains — issuer, work, edition, timestamps, license terms — to whoever receives it. The split protects binding secrets, not purchase-history privacy; that surface is analyzed in `attest-privacy.md`.

#### TM-17 — Replay of a receipt across works or stores

- **Actor / precondition:** `network attacker` holds a valid receipt and presents it as evidence for a different work, series, or `issuer`.
- **Impact:** One purchase would license many.
- **Verdict:** Mitigated — v0.1 §5, v0.1 §9, v0.1 §11, v0.1 §8.2.  Issuer, work identity, series, and license terms all live inside the single signed object, so nothing can be re-pointed without breaking the signature; the signing key is resolved only from the claimed issuer's own manifest; and a `buyer.pubkey` binding proof is bound to a fresh per-challenge nonce and to the receipt's own `receipt_id`, so a captured transcript cannot be replayed onto another receipt.
- **Residual risk:** The commitment-disclosure binding path is replayable by design (v0.1 §8.1) — TM-19. `work.identifiers` are issuer-scoped strings, so two issuers naming the same work carry no cross-issuer relationship any verifier can check.

#### TM-18 — Identifier recovery from a leaked salt

- **Actor / precondition:** `network attacker` holds a receipt and its salt, and the identifier is drawn from a guessable population such as email.
- **Impact:** Recovery of the `buyer`'s plaintext identifier from the signed commitment, re-identifying the purchase and, for `email`, the person.
- **Verdict:** Mitigated — v0.1 §8.1, v0.1 §5.3.  The commitment is scrypt at fixed parameters (`N=32768, r=8, p=1, dkLen=32`) over a domain-separated, normalized identifier with a per-receipt 16-byte salt, and the RECOMMENDED `identifier_type` is `issuer-account` — a store-scoped identifier whose disclosure links nothing globally.
- **Residual risk:** scrypt RAISES the cost of dictionary recovery; it does not eliminate it. Against exactly the low-entropy identifiers v0.1 §8.1 names as the reason for choosing scrypt, an attacker holding the salt can still enumerate candidates, and the parameters are fixed by the specification version and MUST NOT be tuned upward per-issuer. An `email` receipt additionally links the buyer across issuers once recovered.

#### TM-19 — Replay of a disclosed `(identifier, salt)` pair

- **Actor / precondition:** `verifier` received a commitment-path disclosure, or `network attacker` later obtains it.
- **Impact:** The recipient can re-present the same disclosure to claim buyer status for that receipt, and holds the plaintext identifier.
- **Verdict:** Mitigated — v0.1 §8.2, v0.1 §8.1, v0.1 §5.3.  The non-replayable path exists and is RECOMMENDED wherever a client app can hold a key: a challenge-response over a fresh nonce of at least 16 bytes, bound to `receipt_id`, proves possession without handing over anything reusable; and per-receipt salts confine a disclosure's damage to the single receipt disclosed.
- **Residual risk:** Disclosing `(identifier, salt)` is a REPLAYABLE BEARER PROOF, stated as such normatively: it permanently burns that receipt's binding secrecy toward that verifier and hands over the identifier itself. v0.1 §8.1 requires only that the verifier treat the identifier as personal data not retained beyond verification, and that issuers SHOULD offer re-issue via `supersedes` — neither is enforceable by the buyer, and `buyer.pubkey` is `null` by default (v0.1 §5.3), so this is the common path, not the exceptional one.

### Group D — Verification-time

#### TM-20 — Canonicalization ambiguity

- **Actor / precondition:** `issuer`, `buyer`, or `network attacker` constructs an envelope whose canonical bytes could be interpreted differently by signer and `verifier`.
- **Impact:** Two implementations compute different signature inputs for the same document — a signature valid to one and invalid to another, or an accepted payload whose meaning differs from the one actually signed.
- **Verdict:** Mitigated — v0.1 §9, v0.1 §9.1, v0.1 §11.  attest-JCS is RFC 8785 restricted by design to integers with `|n| < 2^53`, removing the IEEE-754 `Number::toString` interoperability surface entirely; duplicate member names are a parse-time rejection rather than last-value-wins; lone surrogates are rejected; key order is fixed by UTF-16BE code-unit sort; and step 0 requires every later step and every downstream consumer to operate on the single parsed object, never on the raw transmitted bytes or a re-serialization of them (v0.1 §15, vectors 6 and 7).
- **Residual risk:** None identified for the canonical form itself. The one subtlety a reimplementation must get right is placement rather than outcome: an over-range integer is rejected at canonicalization, not at schema validation, so the conforming result is `signature: "invalid"` with `schema: "not_checked"` (v0.1 §9).

#### TM-21 — Unknown-field smuggling

- **Actor / precondition:** `issuer` places an additional field in a payload before signing; the receipt is otherwise well-formed and validly signed.
- **Impact:** A signed field some consumers act on and others never see, letting one document mean two things.
- **Verdict:** Mitigated — v0.1 §11.2, v0.1 §5.  Unknown fields are allowed and are inside the signature input, so they cannot be added after the fact; and every unrecognized **top-level** payload field MUST be surfaced as a warning — the mechanism that separates "unrecognized" from "invalid" without letting either pass silently (v0.1 §15, vector 10).
- **Residual risk:** The warning obligation is scoped to top-level keys. The schema sets `additionalProperties: false` nowhere (v0.1 §5), so an unknown member nested inside `issuer`, `buyer`, `work`, `license`, or `survivability` is signed and accepted with no mandated warning; a consumer that acts on such a nested extension diverges from one that ignores it, and no protocol-level signal distinguishes them.

#### TM-22 — Resource exhaustion via a hostile receipt envelope

- **Actor / precondition:** `network attacker` submits a hostile envelope to a `verifier` that accepts untrusted input.
- **Impact:** Deeply nested, highly repetitive, or very large input consumes memory and CPU out of all proportion to the work of rejecting it, denying verification service.
- **Verdict:** Out of scope — v0.1 §9, v0.1 §11. Neither specification defines normative envelope byte-size or JSON-nesting ceilings. Parse-once and short-circuit behavior do not bound attacker-controlled allocation, so this is a tracked protocol gap whose limits are implementation-local and outside the conformance surface.
- **Residual risk:** A conforming implementation may accept an arbitrarily large or deeply nested document before it can reject it. The specifications bound neither the allocation nor the work required to reach rejection.

#### TM-23 — Resource exhaustion via hostile transparency evidence

- **Actor / precondition:** `mirror operator` or `network attacker` supplies a hostile Stage 2 evidence bundle, including one imported from a proofs member.
- **Impact:** Oversized checkpoint text, long proof lists, or unbounded operation chains make evidence evaluation the cheapest denial-of-service surface in the protocol; a raised exception on hostile input would additionally turn evidence handling into a crash oracle.
- **Verdict:** Out of scope — v0.2 §8, v0.2 §9.4, v0.2 §10.2, v0.2 §11.1. Neither specification defines normative ceilings for proof-list length, operation-chain length, or checkpoint text length. One bundle per claim and failure degradation do not bound attacker-controlled allocation, so this is a tracked protocol gap whose limits are implementation-local and outside the conformance surface.
- **Residual risk:** A conforming verifier can avoid raising on hostile evidence but still consume unbounded resources before it degrades the result to `not_checked`.

#### TM-24 — Archive expansion during bundle import

- **Actor / precondition:** `network attacker` supplies an oversized or highly compressible bundle to an importer.
- **Impact:** Archive expansion exhausts disk, memory, or CPU during import and denies service.
- **Verdict:** Out of scope — v0.1 §14.1, v0.2 §14. Neither specification defines decompressed-size, member-count, or compression-ratio ceilings for bundle import. This is a tracked protocol gap whose necessary limits are implementation-local and outside the conformance surface.
- **Residual risk:** The `proofs/` path-traversal slice is separately mitigated by TM-45. It does not bound archive expansion or allocation before an importer can reject the bundle.

#### TM-25 — Cross-implementation verdict divergence

- **Actor / precondition:** `network attacker` selects which `verifier` receives a receipt when conforming implementations differ by language or runtime.
- **Impact:** Verdict shopping — a receipt accepted by one implementation and rejected by another destroys the evidentiary value of any single verdict.
- **Verdict:** Mitigated — v0.1 §15, v0.2 §6, v0.2 §16, v0.2 §9.3.  Conformance is defined as producing the expected `VerificationResult`, every component matched exactly, for **every** vector in a 66-leaf corpus run against every conformance runner from the same shared golden files; the hybrid and checkpoint paths pin their error literals verbatim so divergence surfaces as a literal mismatch rather than a silent difference; and grammar decisions that would otherwise drift between runtimes — checkpoint `origin` and `LogKey.name` character classes, diagnostic escaping — are restricted to printable ASCII so acceptance can never depend on a runtime's Unicode tables.
- **Residual risk:** v0.1 §15 names one uncovered property itself: small-order and non-canonical `A`/`R` rejection, half of the pinned ruleset in v0.1 §10, is not separately vectorized and currently relies on the pinned library's guarantee rather than on a fixture. v0.2 §9.3 also records a known TypeScript/Python quote-style deviation in checkpoint diagnostics; it affects rendered text only, never parsing, acceptance, or verdicts.

#### TM-26 — Corroboration presented as authenticity

- **Actor / precondition:** `issuer`, `log operator`, or `mirror operator` assembles evidence for an artifact genuinely in a log, and the audience treats logging as authenticity.
- **Impact:** A TOFU-rooted, or outright invalid, artifact is accepted because it arrives with transparency evidence attached.
- **Verdict:** Mitigated — v0.2 §10, v0.2 §7.1, v0.2 §14, v0.2 §15.  The three Stage 2 components are informational by construction: they never affect `signature`, `schema`, `revocation`, `binding`, or `ok`; the log NEVER upgrades `trust`; `corroboration` says an artifact was independently observable, never who was entitled to write it; the transparency verdict is resolved before and independently of the receipt's own verdict, so a receipt rejected for a compromised key still reports its genuine `logged` standing without being rescued by it (v0.2 §16, leaves 28a and 28i); and a bundle's `README.html` MUST state in plain language that a proof is corroboration, not authenticity.
- **Residual risk:** The separation is enforced in the result vocabulary, not in what a consumer does with it — the same reading risk as TM-11. `manifest_freshness: verified_as_of:<N>` is the sharpest case: it proves only that a manifest existed unmodified at that point in the log's history and MUST NOT be read as a claim about a key's current status, since a later manifest version may since have marked the same key `compromised` (v0.2 §10.4).

#### TM-27 — Fabricated or withheld evidence from a mirror

- **Actor / precondition:** `mirror operator` or `network attacker` serves the static file set from which `verifier` fetches transparency evidence.
- **Impact:** Fabricated inclusion or checkpoint evidence would manufacture standing; withheld evidence denies genuine standing.
- **Verdict:** Mitigated — v0.2 §10.2, v0.2 §9.2, v0.2 §7.3.  Anything a mirror serves is untrusted evidence exactly like an adversary's: the `entry` MUST deep-equal the entry the verifier computed itself from the artifact being corroborated, the checkpoint MUST verify under a `LogKey` pinned out-of-band in the verifier's own trust store — never taken from a bundle — under the fail-closed Ed25519 **and** ML-DSA-65 rule, the declared `tree_size` MUST equal the verified checkpoint's own, and the inclusion proof MUST verify against that checkpoint's root; anything short of that degrades to `not_checked` rather than to partial trust.
- **Residual risk:** Availability is not a protocol property. A mirror — or the log's own primary host — that simply withholds evidence leaves `transparency: "not_checked"`, and nothing distinguishes censorship from an artifact that was never logged. Fabrication beyond the verifier's pinned keys is impossible; a mirror colluding with a compromised log key is TM-33.

### Group E — Rotation, continuity, and key compromise

#### TM-28 — Key-substitution hijack of the manifest chain

- **Actor / precondition:** `network attacker` serves a `verifier` a manifest at a version above the one it already trusts.
- **Impact:** Attacker-controlled keys are adopted as the issuer's current keys, making every subsequent forgery verify.
- **Verdict:** Mitigated — v0.1 §7.3, v0.1 §7.1, v0.1 §11.1.  A version-N+1 manifest is auto-trusted only if signed by a key that was `active` in the version-N manifest already trusted; version gaps are bridgeable only by validating every intermediate manifest in sequence; a discontinuous rotation, or conflicting manifests for the same issuer, MUST force `trust: "unverified_rotation"` — overriding provenance — and MUST NOT be auto-accepted; and each key's `kid`, `pub`, `valid_from`, `valid_to`, and `status` lives inside the manifest's own signed body, so nothing about a key's lifecycle is tamperable without breaking `manifest_signature` (v0.1 §15, vectors 11, 14, 14b).
- **Residual risk:** `trust` is not a component of `ok` (v0.1 §11.1): a receipt verified against a discontinuously-rotated manifest still reports `signature: "valid"` and `ok: true` alongside `unverified_rotation`. The rule bounds *auto-acceptance* and labels the result; it does not by itself refuse the receipt.

#### TM-29 — Stale manifest presented as current

- **Actor / precondition:** `network attacker` or `mirror operator` serves an older, genuinely `issuer`-signed key manifest while a newer version marks a key compromised.
- **Impact:** The fail-closed compromise rule never fires, and forgeries made with the compromised key keep verifying.
- **Verdict:** Out of scope — v0.1 §7.3, v0.2 §10.4. No current specification mechanism establishes key-manifest currency. Rotation continuity authenticates a chain the `verifier` already has, and log freshness proves historical inclusion only; neither discovers that a newer manifest exists. This is a tracked protocol gap.
- **Residual risk:** A `verifier` resolving only version N cannot learn that version N+1 marks the key `compromised`, so forgeries continue to verify against the old manifest. Offline and long-lived trust stores retain this exposure until refreshed outside the protocol.

#### TM-30 — Hybrid-to-Ed25519-only downgrade of a manifest signature

- **Actor / precondition:** `network attacker` has CRQC capability to break Ed25519 but not ML-DSA-65 and targets a hybrid `issuer` signer.
- **Impact:** A rotation forged with the classical primitive alone would install attacker keys and thereby bypass hybrid protection on every receipt that rotation vouches for.
- **Verdict:** Mitigated — v0.2 §2.3, v0.2 §4, v0.2 §6.  `manifest_signature` is AND-verified fail-closed in both directions: a hybrid signer's manifest missing `sig_ml_dsa_65` is invalid, and an Ed25519-only signer's manifest carrying a stray `sig_ml_dsa_65` is equally invalid. A downgraded rotation candidate is therefore not validly signed *for continuity purposes*, the chain is discontinuous at that point, and `trust: "unverified_rotation"` follows.
- **Residual risk:** v0.2 §6, leaf 26h pins the honest outcome: the receipt's own hybrid signature still verifies and the receipt still reports `ok: true` — the downgrade degrades `trust`, it does not invalidate anything. A consumer that ignores `trust` gains nothing from this rule (TM-11).

#### TM-31 — Compromise of a single hybrid leg

- **Actor / precondition:** `network attacker` has compromised exactly one leg of a hybrid `issuer` signing key, through CRQC capability or a cryptanalytic advance.
- **Impact:** With one primitive broken, forgery would follow immediately if either leg alone sufficed.
- **Verdict:** Mitigated — v0.2 §3, v0.2 §2.3, v0.2 §13.  Verification is AND semantics: both legs must independently verify over the same canonical bytes, and both resolve through one signed manifest key entry under one shared `kid`, so pairing one signer's Ed25519 key with another's ML-DSA-65 key is structurally impossible without forging the manifest itself; the same AND rule governs manifest signatures, artifact manifests, and revocation records.
- **Residual risk:** The AND rule protects v0.2 artifacts. An Ed25519-only key entry remains legitimate (v0.2 §2.3), and a v0.1 receipt has one leg by definition (v0.2 §1) — for those, single-leg compromise is total compromise, i.e. TM-32.

#### TM-32 — Compromise of both hybrid legs (full signer compromise)

- **Actor / precondition:** `network attacker` possesses both legs of a hybrid `issuer` key, or the single Ed25519 key of a non-hybrid signer.
- **Impact:** Arbitrary receipts, backdated within the key window, verifying cleanly against the issuer's own manifest.
- **Verdict:** Mitigated — v0.1 §7.3, v0.1 §11, v0.2 §10, v0.2 §12.  Compromise fails closed and retroactively: a key marked `compromised` in the resolving manifest invalidates **all** signatures ever made with it, regardless of `issued_at`, unconditionally, on receipts and on side-documents alike (v0.1 §15, vector 13); the one-key-per-period discipline v0.1 §7.3 RECOMMENDS bounds the blast radius to a single period where an issuer follows it; and receipts that were logged and PQ-anchored keep honest, independently-resolved `transparency`/`corroboration` standing describing what existed and when (v0.2 §16, leaf 28i).
- **Residual risk:** The fail-closed rule takes effect only once a **resolving** manifest marks the key `compromised`. Until it does — and indefinitely, for any verifier whose trust store still resolves an older manifest (TM-29) — the attacker's forgeries report `signature: "valid"`, `ok: true`. The retroactive invalidation is also indiscriminate by design: every genuine receipt signed by that key is invalidated with the forgeries, and re-issue of affected receipts is a SHOULD (v0.1 §7.3), not a guarantee.

#### TM-33 — Log signing-key compromise

- **Actor / precondition:** `network attacker` possesses both checkpoint-signing legs of a `log operator`.
- **Impact:** The attacker signs checkpoints for trees of its choosing, fabricating `logged` standing and equivocating at will.
- **Verdict:** Out of scope — v0.2 §7.3, v0.2 §9.1, v0.2 §11.1. The offline-signer split protects the append path, not theft of both ceremony-side signing keys. No current specification mechanism revokes a compromised pinned log key or prevents it from signing fabricated checkpoints; this is a tracked protocol gap.
- **Residual risk:** OpenTimestamps proves that `checkpoint.note_bytes` existed by the pinned-header time, not that checkpoint signature lines existed then: v0.2 §9.1 excludes those lines from `note_bytes`. An attacker can pre-anchor a chosen unsigned note and, after acquiring both log keys, sign it later; the specifications do not detect this post-anchor signing case.

#### TM-34 — Log equivocation and split views

- **Actor / precondition:** `log operator` serves two self-consistent but mutually inconsistent histories to different audiences.
- **Impact:** An artifact appears logged to one `verifier` and absent to another; inclusion evidence stops meaning "in the one true log".
- **Verdict:** Mitigated — v0.2 §10.3, v0.2 §10.2, v0.2 §16.  When a verifier holds a validly hybrid-signed prior checkpoint for the same pinned origin whose tree is not RFC 6962-consistent with the current one, that is conclusive proof the log signed two incompatible histories, and it MUST surface as the hard verdict `transparency: "equivocation_detected"` — the one Stage 2 outcome never absorbed into `not_checked` (v0.2 §16, leaf 28f). A prior checkpoint that does not itself verify, or that arrives with no consistency proof, is fail-safe rather than an accusation.
- **Residual risk:** Detection requires the verifier to **already hold both** inconsistent checkpoints. v0.2 §15 item 1 states the bound normatively: there is no mechanism for a verifier that has seen only one branch to discover a second, and a keyed log with no independent witness quorum can maintain parallel self-consistent branches indefinitely. Anchors bound *time*, not *branching*, and `corroboration: "witnessed"` is defined but unreachable — a conforming Stage 2 implementation MUST NOT emit it (v0.2 §10.1).

#### TM-35 — Theft of a buyer binding key

- **Actor / precondition:** `network attacker` possesses a `buyer` binding private key, typically from the private bundle.
- **Impact:** The thief answers binding challenges as the buyer, on the strong path that exists precisely to be theft-resistant.
- **Verdict:** Mitigated — v0.1 §8.2, v0.1 §8.1, v0.1 §11.1.  The binding key is OPTIONAL and keys SHOULD be per-receipt, so a stolen key compromises one purchase rather than a buyer identity; a verifier MUST NOT treat `buyer.pubkey` equality across two receipts as proof of buyer identity, which denies the thief any cross-receipt leverage; and the base commitment (v0.1 §8.1) is untouched by the loss.
- **Residual risk:** Nonce-binding prevents transcript *replay*, not impersonation: a thief holding the private key answers any fresh challenge correctly. Where the keys live in `.private.attest`, this is the same event as TM-15. v0.1 defines no binding-key revocation or rotation path, and a superseding re-issue does not invalidate the superseded receipt absent buyer consent (v0.1 §5.1) — so the compromised receipt stays answerable by the thief.

#### TM-36 — Artifact-manifest rollback

- **Actor / precondition:** `network attacker`, `mirror operator`, or `coercive third party` serves an older, genuinely `issuer`-signed artifact manifest while a newer one exists.
- **Impact:** The `buyer` is steered to a superseded artifact set — an outdated or withdrawn build, or one whose known-bad hashes have since been replaced — while every integrity check the protocol defines passes.
- **Verdict:** Out of scope — v0.1 §7.2, v0.2 §13. No current specification mechanism establishes artifact-manifest currency. Authentication verifies that the served manifest is genuinely issuer-signed, but v0.1 §7.2 requires acceptance of any issuer-signed manifest for the series and defines no ordering or recency rule. This is a tracked protocol gap.
- **Residual risk:** A `verifier` cannot distinguish the current artifact manifest from a validly signed older one, including a manifest that points to an outdated or withdrawn artifact set.

### Group F — Revocation, refund, issuer disappearance, buyer loss

#### TM-37 — Forged revocation record

- **Actor / precondition:** `network attacker` injects a record into a revocation view that `verifier` consults but does not control.
- **Impact:** A receipt reads `revoked` (and `ok: false`) on the strength of a record the `issuer` never signed.
- **Verdict:** Mitigated — v0.1 §12.1, v0.1 §12.2, v0.1 §7.3.  A record counts only if its resolving key manifest is self-consistent, its `signature.kid` resolves to a key entry with `status == "active"` — a `compromised` or `retired` key's record is rejected exactly as it would be on a receipt — its `revoked_at` falls inside that key's validity window, and its signature verifies over `JCS(record)` with `signature` removed under the pinned ruleset. Anything else MUST be ignored with a warning, never honored, and malformed, wrong-typed, or missing input fails closed rather than raising.
- **Residual risk:** `revoked_at` is signed by the issuer and is therefore exactly as trustworthy as the issuer, subject only to the key-window check (TM-41). v0.2 §15 item 5 confirms revocation records are not a loggable entry type, so no transparency evidence can corroborate when a record actually appeared.

#### TM-38 — Post-CRQC forged revocation through the classical leg

- **Actor / precondition:** `network attacker` has CRQC capability to break Ed25519 but not ML-DSA-65 and targets a hybrid `issuer` key.
- **Impact:** A forged `policy` or `refund_window` record would drive `revocation: "revoked"`, `ok: false`, through the classical primitive alone — killing genuine receipts despite hybrid protection holding everywhere else.
- **Verdict:** Mitigated — v0.2 §13, v0.2 §2.3, v0.2 §16.  The hybrid AND rule is extended to revocation records and artifact manifests: if the signing key's own manifest entry carries `pub_ml_dsa_65`, the side-document MUST also carry a valid `sig_ml_dsa_65` over the same signed bytes or it is invalid and ignored, symmetrically fail-closed in both directions. An Ed25519-only record against a hybrid key is unconditionally ignored — `revocation: "unknown"`, `ok: true` — regardless of any transparency or anchor evidence presented alongside it (v0.2 §16, leaf 28m).
- **Residual risk:** The rule protects hybrid-keyed issuers only. A receipt whose issuer is Ed25519-only has no PQ leg to require, so its revocation records stay exactly as forgeable post-CRQC as its receipts (TM-03). v0.2 §13 also scopes the fix precisely: it closes the hybrid-downgrade gap in side-document authentication, and extends neither transparency coverage nor anti-equivocation to those documents (v0.2 §15 item 5).

#### TM-39 — Revocation-feed suppression

- **Actor / precondition:** `network attacker` suppresses records, leaving the `verifier` revocation view incomplete or absent.
- **Impact:** A genuinely revoked receipt is presented to a verifier that cannot learn it was revoked.
- **Verdict:** Mitigated — v0.1 §12.3, v0.1 §11.1, v0.1 §11.2.  Suppression cannot be laundered into false confidence: the freshness anchor `T` in `not_revoked_as_of:<T>` MUST be the maximum `revoked_at` across **authenticated** records only, so an injected far-future record cannot inflate reported freshness; with zero authenticated records the result MUST be the bare literal `unknown`; and the layered result reports the state of the feed rather than collapsing it into the receipt's validity.
- **Residual risk:** This is a disclosure guarantee, not an availability one. `unknown` and any `not_revoked_as_of:<T>` — however stale — leave `ok` unaffected by design, and an offline verifier reports `unknown` honestly rather than failing closed (v0.1 §11.2), so an attacker who withholds the feed can have a revoked receipt read as `ok: true`. Neither document defines a maximum acceptable staleness for `T`, nor requires a verifier to refuse a receipt whose feed is too old; that policy belongs to the relying party.

#### TM-40 — Unjustified mass revocation

- **Actor / precondition:** `issuer` in control of an active signing key, acting in bad faith or under commercial pressure.
- **Impact:** A large body of legitimately issued receipts is declared revoked.
- **Verdict:** Mitigated — v0.1 §6.1, v0.1 §6.2, v0.1 §12.2, v0.1 §11.1.  The revocation class is fixed inside the signed payload at issuance and cannot be changed afterwards: against a `revocability: "none"` receipt an authenticated, matching record is itself treated as invalid (`revocation: "invalid_revocation_ignored"`, a warning, `ok` unaffected) — without which the revocation machinery would falsify every irrevocability assertion made under the v0.1 §6.1 conditional (v0.1 §15, vector 16). Revocation never erases evidence either: the receipt's `signature` component stays `valid` and the signed terms remain readable in the bundle.
- **Residual risk:** `refund_window` and `policy` receipts are revocable by their own signed terms, and a `policy` record is honored as-is because a verifier cannot evaluate the referenced policy — so for those classes an unjustified revocation does drive `ok: false`, with no in-protocol counter-evidence path for the buyer. Restitution is a commercial and legal matter the protocol does not address (v0.1 §2).

#### TM-41 — Coerced revocation of `revocability: "none"` receipts

- **Actor / precondition:** `coercive third party` compels an `issuer` holding valid key material to sign a matching revocation record for an irrevocable receipt.
- **Impact:** The compelled record would invalidate an irrevocable receipt.
- **Verdict:** Mitigated — v0.1 §6.2, v0.1 §12.2. A conforming verifier treats an authenticated, matching record for this class as `invalid_revocation_ignored`, leaves `ok` unaffected, and emits a warning.
- **Residual risk:** This verdict is limited to the signed `revocability: "none"` class. Coerced revocation of `refund_window` or `policy` receipts, false signed revocation times, and compelled key-compromise markings are addressed separately in TM-47.

#### TM-42 — Receipt presented after a refund

- **Actor / precondition:** `buyer` holds a refund-window receipt whose purchase was refunded and for which `issuer` signed a matching record.
- **Impact:** The refunded buyer presents the receipt as live entitlement evidence.
- **Verdict:** Mitigated — v0.1 §12.2, v0.1 §5.5, v0.1 §12.1.  An authenticated, matching record inside the window yields `revocation: "revoked"` and `ok: false`; the window is anchored to the receipt's own signed `issued_at` and evaluated against the record's own signed `revoked_at`, never the verifier's clock; and a record that authenticates but falls outside the window is ignored with a warning rather than silently honored, so the boundary cuts both ways.
- **Residual risk:** This works only for a verifier that actually consults the feed. TM-39's suppression case and the ordinary offline case (v0.1 §11.2) both leave a refunded receipt reading `ok: true` with `revocation: "unknown"`. The window length itself is issuer-declared at issuance (`1 ≤ n ≤ 3650` days), so its adequacy is a commercial term, not a protocol property.

#### TM-43 — Issuer disappearance

- **Actor / precondition:** `issuer` ceases operating its domain, manifest endpoint, and services, or `coercive third party` forces that shutdown.
- **Impact:** Verification material and the referenced terms could become unobtainable, silently voiding evidence the buyer holds.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §7.4, v0.1 §2, v0.2 §7.2.  Verification is user-held and offline-capable: the shareable bundle carries the receipts, the key and artifact manifests, and the license, mirror-policy, and end-of-life texts, each verified against its signed hash binding at export time — a receipt whose referenced terms can no longer be produced is a signature without a deal, so the bundle preserves the deal; offline verification MUST work from a local trust store of key manifests; and a Stage 2 log is a static, mirrorable file set any independent party can republish, whose root is always recomputable from `entries.jsonl`.
- **Residual risk:** Offline cryptographic verification survives disappearance, but a `verifier` with no domain trust root previously established by TLS can never reach `trust: "verified"` afterwards; a bundle-supplied manifest remains `unauthenticated_tofu` (v0.1 §7.4). The evidence and terms survive, not access: no later compromise marking or artifact manifest can be published, and redownload still depends on hosting.

#### TM-44 — Buyer loses salts, keys, or bundles

- **Actor / precondition:** `buyer` loses every binding secret available for a receipt: all salt copies, every applicable binding private key, and the private bundle holding them.
- **Impact:** The buyer can no longer prove that the receipt is theirs.
- **Verdict:** Out of scope — v0.1 §8.2, v0.1 §14.2, v0.1 §2.  Custody is the buyer's: mandatory key custody is explicitly out of scope for v0.1, and the specification's obligations stop at requiring the private file to be named and documented as private and a conforming CLI to warn whenever it is accessed.
- **Residual risk:** The loss is unrecoverable from inside the protocol — the commitment is a one-way scrypt output over an unrecoverable per-receipt salt, and no backup, escrow, or recovery mechanism is defined; the only remedy is issuer re-issue (v0.1 §8.1), which requires the issuer still to exist (TM-43). The receipt itself keeps verifying, since `binding` is not a component of `ok` (v0.1 §11.1); what is lost is exclusivity — anyone else holding a copy of that receipt is thereafter no less able to present it than the buyer.

#### TM-45 — Path traversal through `proofs/` member names

- **Actor / precondition:** `network attacker` supplies a bundle with a hostile proofs member name.
- **Impact:** A crafted member name escapes the import directory when an importer derives a filesystem path.
- **Verdict:** Mitigated — v0.2 §14. A conforming importer must accept only the `proofs/<ULID>.json` shape and reject every other proofs shape before deriving a filesystem path.
- **Residual risk:** This verdict is limited to proofs members. It does not establish generic archive-resource limits, which remain out of scope in TM-24.

#### TM-46 — Resource exhaustion via manifests and revocation views

- **Actor / precondition:** `network attacker` supplies hostile key manifests, artifact manifests, or revocation views to a `verifier`.
- **Impact:** Huge manifest arrays or all-record revocation scans consume unbounded verifier memory or CPU and deny service.
- **Verdict:** Out of scope — v0.1 §7.1, v0.1 §7.2, v0.1 §12. Neither specification defines normative array-size, document-size, or revocation-view scan ceilings. This is a tracked protocol gap whose necessary limits are implementation-local and outside the conformance surface.
- **Residual risk:** Signature authentication does not bound parsing, allocation, or scanning before a hostile input can be rejected. A conforming verifier may therefore retain unbounded resource exposure for these inputs.

#### TM-47 — Coerced revocation of revocable receipts and key-compromise markings

- **Actor / precondition:** `coercive third party` compels an `issuer` holding valid key material to sign a revocation record or publish a key-compromise marking.
- **Impact:** A revocable receipt is invalidated with a false signed revocation time, or every receipt using a marked key is invalidated despite no actual compromise.
- **Verdict:** Out of scope — v0.1 §7.3, v0.1 §12.1, v0.1 §12.2. The specifications authenticate `revoked_at` and key status but do not establish their truthfulness or distinguish coercion from voluntary signing. A signed refund-window time can be backdated inside the key-validity window, policy-class records are honored as signed, and a compelled `compromised` marking invalidates every signature under that key. Compulsion itself is a scope boundary (§7) — no signature scheme distinguishes a compelled signer from a willing one — but the undetectability of a backdated `revoked_at` is a tracked protocol gap (§6.3): revocation records are not among the two loggable entry types (v0.2 §8, v0.2 §15 item 5), so nothing bounds when such a record actually came into existence.
- **Residual risk:** TM-41 separately mitigates a matching compelled record against a `revocability: "none"` receipt. It does not protect revocable classes or counter a compelled key-status publication.

### Group G — Transparency log

#### TM-48 — Self-signed manifest logged to manufacture issuer standing

- **Actor / precondition:** `network attacker` publishes a key manifest naming a victim domain, submits it to a Stage 2 log, and presents the resulting inclusion evidence to a `verifier`.
- **Impact:** An attacker-controlled manifest would acquire the appearance of issuer standing from the log itself, converting an open-ingestion host into a domain-control authority.
- **Verdict:** Mitigated — v0.2 §7.1, v0.2 §10, v0.2 §10.4, v0.2 §15.  The specifications name this exact confusion and close it structurally: key manifests are self-signed (v0.1 §7.1) and a log is an open-ingestion host, so inclusion says nothing about who controls a domain; the log NEVER upgrades `trust`, which continues to require the v0.1 §7.4 domain-control root and nothing else, ever (v0.2 §15 item 4); and a claim for a manifest whose own `manifest_version` is greater than 1 has `corroboration` forced back down to `none`, with the warning `corroboration_requires_rotation_chain`, unless the verifier's own trust store independently holds a validated, gapless rotation chain from version 1 through that manifest — a rule deliberately stricter than v0.1 §7.3 continuity, because publication is not a rotation history (v0.2 §16, leaf 28h).
- **Residual risk:** The rotation-chain rule is scoped to `manifest_version` greater than 1, so a freshly minted attacker manifest at version 1 still reaches `transparency: "logged"` and `corroboration: "logged"` on its own merits — honestly, since those components only ever assert observability. What prevents the confusion is the consumer reading `trust`, the same reading dependency as TM-11 and TM-26; nothing in the result vocabulary is misstated, and nothing forces a UI to show it.

#### TM-49 — Split view against a verifier that has seen only one branch

- **Actor / precondition:** `log operator` maintains two self-consistent branches and serves each audience only its own; the `verifier` holds checkpoints from one branch only.
- **Impact:** Inclusion evidence stops meaning "in the one true log" without any verifier being able to notice, so a receipt can be logged for one audience and invisible to another indefinitely.
- **Verdict:** Out of scope — v0.2 §10.3, v0.2 §15, v0.2 §10.1. This is the discovery half of equivocation, and the specifications state as a normative limitation that Stage 2 does not address it: Stage 2 defines no mechanism for a verifier that has seen only one branch to discover a second, and a keyed log with no independent witness quorum can maintain parallel self-consistent branches indefinitely. Anchors bound time, not branching. The answer is an independent witness quorum whose wire contract is deliberately frozen but whose operation is not delivered here — `corroboration: "witnessed"` is defined and a conforming Stage 2 implementation MUST NOT emit it.
- **Residual risk:** TM-34 mitigates only the detection half, and only once the verifier already holds both inconsistent checkpoints. Until witness federation exists (§6.2), a verifier's confidence that a log has not branched rests on nothing the protocol supplies.

#### TM-50 — Stale manifest laundered into apparent currency by an inclusion proof

- **Actor / precondition:** `mirror operator` or `network attacker` pairs a genuinely `issuer`-signed but superseded key manifest with genuine, correctly verifying transparency evidence for it.
- **Impact:** A verifier that reads inclusion as recency treats a superseded manifest — potentially one whose successor marks a key `compromised` — as the issuer's current key state.
- **Verdict:** Mitigated — v0.2 §10.4, v0.2 §10.1, v0.2 §15.  The result vocabulary refuses to express currency at all: `manifest_freshness: verified_as_of:<N>` proves only that the manifest existed unmodified as of a point in the log's history, MUST NOT by itself be read as a claim about a key's current status — the specification names the exact case, a later manifest version having since marked the same key `compromised` — and `<N>` is a tree size, not a wall-clock time, so it cannot be misread as recency; `corroboration` says an artifact was independently observable and never who was entitled to write it (v0.2 §15 item 3).
- **Residual risk:** Refusing to assert currency is not establishing it. Nothing here lets a `verifier` discover that a newer manifest exists, which is TM-29's tracked gap; the mechanisms bound how the evidence may be *described*, leaving the underlying rollback exposure exactly where TM-29 leaves it.

#### TM-51 — Log entry poisoning through admitted content

- **Actor / precondition:** `network attacker` submits entries to a Stage 2 log that admits submissions from parties other than the `issuer` named in them.
- **Impact:** Attacker-chosen content inside the log would be replicated by every mirror and could carry attribution, payloads, or schema extensions that consumers act on.
- **Verdict:** Mitigated — v0.2 §8, v0.2 §7.2.  Entries are content-free and closed by construction: exactly two versioned entry types are defined, each with exactly the required member set and no more, unknown members are rejected outright rather than silently tolerated, and every member is a domain name, a version integer, or a lowercase-hex hash — there is nowhere in an entry for attacker-chosen content to live. The `issuer` member of a `receipt` entry is normatively a NON-AUTHENTICATED hint for log browsing that a conforming verifier MUST NOT read as attribution, and an entry whose type or member set does not match resolves to `transparency: "not_checked"` rather than being partially trusted. `entries.jsonl` is the sole source of truth and the tile cache carries no authority, so a poisoned cache cannot outlive a rebuild.
- **Residual risk:** This bounds *what* may be admitted, not *how much*. Neither specification defines submitter authentication, admission quotas, or rate limits, so nothing bounds the volume of well-formed entries an adversary may submit to an openly-ingesting log. As in TM-27 and TM-39, log availability is not a protocol property; a flooded log denies no verifier a verdict, because evidence evaluation degrades to `not_checked` rather than failing.

#### TM-52 — Mirror serving a truncated or stale tree

- **Actor / precondition:** `mirror operator` or `network attacker` republishes a log's static file set at an earlier or rewritten tree state.
- **Impact:** Entries appended after the truncation point vanish from view, and a verifier could be steered onto a history the log never signed.
- **Verdict:** Mitigated — v0.2 §10.2, v0.2 §9.2, v0.2 §7.3.  Truncation cannot manufacture standing and cannot be silently rewritten: the checkpoint MUST verify under a `LogKey` pinned out-of-band in the verifier's own trust store under the fail-closed Ed25519 **and** ML-DSA-65 rule, the evidence's declared `tree_size` MUST equal that verified checkpoint's own, and the inclusion proof MUST verify against its root — so a rewritten tree requires the ceremony-side signing keys, not merely control of the served files. Where the verifier supplies a validly-signed prior checkpoint plus a consistency proof, a truncation that is not RFC 6962-consistent is the hard verdict `transparency: "equivocation_detected"`, and the ceremony-side signer MUST itself refuse to sign any successor that is not a valid consistency extension of the prior signed tree.
- **Residual risk:** A `verifier` holding no prior checkpoint cannot distinguish a truncated tree from a genuinely small one; serving an old but internally consistent checkpoint is undetectable and confers genuine, merely older, standing. Withholding evidence outright is TM-27, and a signer able to produce a consistent rewrite is TM-33.

#### TM-53 — Side-documents outside transparency coverage

- **Actor / precondition:** `issuer`, `mirror operator`, or `coercive third party` alters, withholds, or backdates an artifact manifest or a revocation record, for which no log evidence can exist.
- **Impact:** The two document classes that carry post-issuance state — what artifacts are current, and what is revoked — get none of the existence, ordering, or anti-equivocation properties Stage 2 gives receipts and key manifests.
- **Verdict:** Out of scope — v0.2 §8, v0.2 §15, v0.2 §13. The log defines exactly two entry types, `key-manifest` and `receipt`; artifact manifests and revocation records are not loggable entry types, and v0.2 §15 item 5 states the boundary directly — the v0.2 §13 hybrid AND-rule closes the specific hybrid-downgrade gap in side-document *authentication* and extends neither transparency-log coverage, inclusion proofs, nor anti-equivocation guarantees to those documents.
- **Residual risk:** Two catalogued exposures rest on precisely this absence: TM-36's artifact-manifest rollback has no log-ordering evidence available to close it, and TM-37's residual — that no transparency evidence can corroborate when a revocation record actually appeared — is a direct consequence. Authentication of these documents is unaffected and remains as strong as TM-37 and TM-38 describe.

### Group H — Anchoring

#### TM-54 — Forged OpenTimestamps attestation

- **Actor / precondition:** `mirror operator` or `network attacker` supplies fabricated `ots` anchor evidence alongside otherwise genuine transparency evidence.
- **Impact:** A fabricated anchor would manufacture `anchored_before:<T>`, the one component that carries post-horizon evidentiary weight, converting unanchored material into apparently pre-CRQC standing.
- **Verdict:** Mitigated — v0.2 §11.1, v0.2 §11.2, v0.2 §10.2.  The anchor path is hash-only and terminates in the verifier's own trust store rather than in anything the evidence asserts: starting from `SHA-256(checkpoint.note_bytes)`, an op-chain of `sha256`/`append`/`prepend` operations is replayed and MUST land on the `header_merkle_root` of a Bitcoin block header pinned by header hash in the verifier's own `AnchorPolicy.pinned_headers` — never fetched live, never trusted from the evidence's own claimed header time — so forging one means finding a preimage against a pinned header's Merkle root, and a proof naming a header absent from that map contributes nothing at all. `anchored_before` is the minimum pinned header time across every verified proof, never a single authority's self-asserted time.
- **Residual risk:** `anchored_before:<T>` is an upper bound on the earliest provable existence time, never a lower bound (v0.2 §11.1): it can establish that the checkpoint bytes existed by `T` and can never establish that they did not exist earlier, nor that they are recent. Coverage also depends entirely on the verifier's own header store, whose distribution and refresh neither specification defines — a gap in that store is fail-safe (no standing) rather than fail-open. What the anchor commits to is `note_bytes` alone, which is TM-33.

#### TM-55 — Post-CRQC break of the classical RFC 3161 leg

- **Actor / precondition:** `network attacker` with CRQC capability forges, or simply fabricates, an RFC 3161 timestamp token presented as anchor evidence.
- **Impact:** If the classical timestamping leg carried evidentiary weight, breaking it would re-open exactly the retroactive-fabrication path the anchoring layer exists to close.
- **Verdict:** Mitigated — v0.2 §11.1, v0.2 §11.3, v0.2 §16.  RFC 3161 is defined as optional classical convenience carrying no post-horizon weight, and the specification enforces that by refusing to derive anything from it: the token is accepted as OPAQUE evidence, parsed only far enough to note its presence and never validated as a certificate chain, it carries a fixed warning stating it has no post-horizon weight, and an `rfc3161` proof alone NEVER sets `pq_surviving` and NEVER sets `anchored_before`. A verdict resting on it can never pass a configured `crqc_horizon`, regardless of how early its claimed time is (v0.2 §16, leaf 28k). OpenTimestamps is the required post-quantum leg precisely because it is hash-based.
- **Residual risk:** Because the token is never validated, a fabricated one is indistinguishable from a genuine one; it sets `anchored: true` while contributing nothing to `transparency`, so a consumer reading `anchored` in isolation rather than `transparency` can still be misled by a token that proves nothing. The horizon gate that formalizes this is also inert until configured — `crqc_horizon` is `null` by default (v0.2 §11.2).

#### TM-56 — Horizon manipulation to claim pre-CRQC standing

- **Actor / precondition:** `network attacker` assembles evidence intended to place post-horizon material on the pre-horizon side of a verifier's configured `crqc_horizon`.
- **Impact:** Post-CRQC forgeries would inherit the standing reserved for material demonstrably predating the quantum transition.
- **Verdict:** Mitigated — v0.2 §11.3, v0.2 §10.2, v0.2 §12.  The horizon is mechanized rather than advisory: a verdict passes only if the policy declares no horizon, or the verdict is PQ-surviving **and** its `anchored_before` is strictly earlier than the horizon; when it does not pass, the whole result caps back down to `(transparency: "not_checked", corroboration: "none")` — a checkpoint signature alone does not survive a declared cutoff. The times compared are pinned-header times from the verifier's own store, not attacker-supplied claims, and the only accepted receipt-entry hash domain commits to the signature bytes themselves, so early standing cannot be obtained for a signature that did not yet exist (TM-04).
- **Residual risk:** The horizon is verifier-local policy and `null` by default, so the gate protects only operators who configure it. It also gates `transparency` and `corroboration` alone: as TM-03 records, no horizon setting can ever make a post-CRQC Ed25519-only forgery report `signature: "invalid"`, so discrimination still rests entirely on the presence of anchored-before-horizon evidence — which un-logged stock, by definition, does not have (v0.2 §15 item 2).

### Group I — Coercion and supply chain

#### TM-57 — Compelled issuer denial of an issued receipt

- **Actor / precondition:** `coercive third party` compels an `issuer` to deny that a purchase occurred, to erase its own records of it, or to withdraw the verification material behind it.
- **Impact:** The buyer's evidence would evaporate with the seller's cooperation, which is precisely the failure mode a buyer-held receipt exists to prevent.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §11.1, v0.1 §11.2, v0.2 §7.2.  Evidence is user-held and does not depend on the issuer's continued cooperation: the shareable bundle carries the receipts, the key and artifact manifests, and the license, mirror-policy, and end-of-life texts, each verified against its signed hash binding at export time, so the terms survive alongside the signature; offline verification MUST work from a local trust store with no issuer endpoint reachable, reporting `revocation: "unknown"` honestly rather than failing closed; the layered result never collapses, so even a receipt driven to `ok: false` still reports `signature: "valid"` and keeps its signed terms readable; and a Stage 2 log is a static file set whose root is recomputable by any independent party.
- **Residual risk:** What survives is the evidence, not the entitlement. A compelled revocation of a `refund_window` or `policy` receipt still drives `ok: false` with no in-protocol counter-evidence path (TM-40, TM-47), a `verifier` with no previously established TLS root can never reach `trust: "verified"` afterwards (TM-43), and whether preserved evidence produces any remedy is a legal question this protocol does not adjudicate (§7).

#### TM-58 — Compelled transparency-log takedown

- **Actor / precondition:** `coercive third party` compels a `log operator` to withdraw a Stage 2 log, or seizes the infrastructure serving it.
- **Impact:** Every artifact whose corroboration depended on that log loses its standing, retroactively erasing the transparency layer's contribution.
- **Verdict:** Mitigated — v0.2 §7.2, v0.2 §14, v0.2 §10.2.  Standing already obtained is portable and does not require the log to be reachable: the log is a static, mirrorable file set that any independent party may republish, `entries.jsonl` is the sole source of truth from which the tree root and checkpoint body are recomputable by anyone, an `.attest` bundle MAY carry each receipt's evidence as a `proofs/<ULID>.json` member so verification stays offline, and evidence is evaluated as untrusted input regardless of where it came from — a mirror's copy is worth exactly what the log's own host's copy is worth.
- **Residual risk:** Nothing new can be corroborated while the log is down: no entries are admitted, no successor checkpoints are signed, and no anchors accrue. Recovery onto a successor log is not a protocol operation either, since `LogKey` trust stores are pinned out-of-band and a conforming verifier MUST NOT take log keys from a bundle (v0.2 §7.3) — adopting a replacement requires an out-of-band trust-store update. Mirrors are permitted by the substrate but not required to exist, so portability is an opportunity, not a guarantee.

#### TM-59 — Compromise of an implementation's dependency, build, or release pipeline

- **Actor / precondition:** `supply chain` compromise of a dependency, build step, or published package of a verifier or issuer implementation, with no cryptographic primitive attest defines being broken.
- **Impact:** A verifier that reports whatever verdict the attacker chooses — accepting forgeries, suppressing revocation, or exfiltrating disclosed identifiers and salts — while every document it handles remains perfectly well-formed.
- **Verdict:** Out of scope — v0.1 §2, v0.1 §15, v0.2 §6, v0.2 §16. `attest-v0.1.md` and `attest-v0.2.md` define document formats, a canonicalization profile, a signing and verification algorithm, and a conformance corpus; they define no build, packaging, or distribution requirement for any implementation, so a compromised toolchain is not something these specifications constrain. What they do supply is structural rather than preventive: conformance is defined as producing the expected `VerificationResult` for every leaf of a 66-leaf corpus run against every runner from shared golden files, so no single implementation is a required trust root and an independently written verifier is checkable against the same fixtures.
- **Residual risk:** A relying party running a compromised verifier gets that verifier's answer, and no amount of conformance testing changes it. The corpus establishes conformance of an implementation as tested, never of the artifact a user actually installed; nothing in either specification binds a published package to the source that passed the corpus, and an implementation's own release provenance, where it publishes any, is a property of that distribution rather than a conformance requirement. Reducing the exposure is a matter of running independent implementations from different supply chains against the same artifact — available because the corpus makes independent implementations practical, but not required by anything normative.

## 5. Traceability

Every numbered section of the two normative specifications maps to at least one catalog entry. Rows cover `attest-v0.1.md` §2–§15 and `attest-v0.2.md` §2–§16, excluding each document's §1 (status and conformance language) and v0.2 §5 (a worked example of §2–§4, carrying no mechanism of its own). Sections whose own text defines no attack surface map to the entry that scopes them, or to the out-of-scope register in §7; no cell is empty.

| Spec feature | TM entries |
| --- | --- |
| v0.1 §2 — Scope and out-of-scope boundaries | TM-05, TM-13, TM-43, TM-44, TM-59; §7 register |
| v0.1 §3 — Terminology and actors | TM-02, TM-05, TM-06; §2 actor table |
| v0.1 §4 — Envelope structure (`signatures`, `delivery`) | TM-09, TM-12, TM-13, TM-20, TM-22 |
| v0.1 §5 — Payload field registry | TM-08, TM-17, TM-18, TM-21, TM-40 |
| v0.1 §6 — Legal-weight field semantics | TM-05, TM-40, TM-41; §7 register |
| v0.1 §7 — Issuer identity, keys, and manifests | TM-07, TM-11, TM-28, TM-29, TM-32, TM-36, TM-43, TM-46 |
| v0.1 §8 — Buyer commitment and binding | TM-14, TM-18, TM-19, TM-35, TM-44 |
| v0.1 §9 — attest-JCS canonicalization profile | TM-20, TM-22, TM-25 |
| v0.1 §10 — Cryptography and pinned ruleset | TM-01, TM-03, TM-25 |
| v0.1 §11 — Verification algorithm and result vocabulary | TM-01, TM-07, TM-09, TM-11, TM-21, TM-25, TM-26, TM-39 |
| v0.1 §12 — Revocation records | TM-37, TM-38, TM-39, TM-40, TM-42, TM-47 |
| v0.1 §13 — Delivery member and single-receipt sharing | TM-12, TM-13, TM-16 |
| v0.1 §14 — Export bundle formats | TM-14, TM-15, TM-16, TM-24, TM-43, TM-45, TM-57 |
| v0.1 §15 — Test vectors and conformance | TM-25, TM-59 |
| v0.2 §2 — Hybrid signature profile | TM-10, TM-30, TM-31, TM-32 |
| v0.2 §3 — Verification algorithm, hybrid path | TM-01, TM-10, TM-31 |
| v0.2 §4 — Manifest continuity and trust | TM-28, TM-30 |
| v0.2 §6 — Conformance, group 26 | TM-25, TM-59 |
| v0.2 §7 — Stage 2 architecture and substrate | TM-27, TM-33, TM-48, TM-51, TM-52, TM-58 |
| v0.2 §8 — Log entry schemas | TM-51, TM-53 |
| v0.2 §9 — Checkpoints, hybrid signed-note profile | TM-23, TM-25, TM-27, TM-33, TM-52 |
| v0.2 §10 — Result contract and decision order | TM-26, TM-27, TM-34, TM-48, TM-49, TM-50, TM-52 |
| v0.2 §11 — Anchoring, `AnchorPolicy`, CRQC horizon | TM-03, TM-33, TM-54, TM-55, TM-56 |
| v0.2 §12 — Signed-receipt-core commitment | TM-04, TM-56 |
| v0.2 §13 — Hybrid AND-rule for side-documents | TM-31, TM-36, TM-38, TM-53 |
| v0.2 §14 — Bundle transparency evidence (`proofs/`) | TM-23, TM-24, TM-26, TM-45, TM-58 |
| v0.2 §15 — Limitations (normative) | TM-03, TM-26, TM-34, TM-48, TM-49, TM-53 |
| v0.2 §16 — Conformance, group 28 | TM-25, TM-26, TM-34 |

## 6. Forward-looking requirements

This section states requirements for work not yet in the normative specifications, and gaps the current specifications do not close. It is not part of the attack catalog: it carries no entries and no verdicts, and nothing in it may be read as a mitigation available today.

### 6.1 Transfer records

`license.transferable` is a reserved field, and v0.1 §2 requires that implementations MUST NOT read `transferable: true` as authorization to resell or transfer a license; issuer-mediated transfer records remain forthcoming in a later revision of `attest-v0.2.md` (v0.2 §1). When that revision defines them, it MUST address the following, each of which the current documents leave undefined because the record type they would attach to does not exist:

- **Transfer-record forgery.** A transfer record MUST be authenticated at least as strongly as the receipt it moves, which under v0.2 §13's existing discipline means the hybrid AND-rule applies whenever the signing key entry carries `pub_ml_dsa_65`; a classical-only transfer record against a hybrid key MUST fail closed exactly as revocation records now do.
- **Chain-of-title hijack.** A chain of transfers MUST be evaluable as a chain, not as isolated records: the revision MUST define how a verifier establishes that the party transferring is the party who last received, since neither `buyer.commitment` nor the optional `buyer.pubkey` currently carries ordering, and v0.1 §8.2 forbids treating `buyer.pubkey` equality across receipts as proof of buyer identity.
- **Double assignment.** The revision MUST define what a verifier reports when two records transfer the same receipt to different parties. Detecting that condition requires an ordering source the current documents do not provide for side-documents, since artifact manifests and revocation records are not loggable entry types (v0.2 §8, §15 item 5) — extending the log's closed entry schema to transfer records, or defining an equivalent ordering mechanism, is a precondition rather than an optimization.
- **Revocation interplay after transfer.** The revision MUST state whose receipt a post-transfer revocation record affects and how `revocability` classes survive a transfer, including whether a `refund_window` remains anchored to the original `issued_at` (v0.1 §12.2) once the holder has changed.
- **Coerced transfer.** The revision MUST NOT claim to distinguish a compelled transfer from a voluntary one. A signature establishes what was signed, not why, and TM-47 already records that limitation for revocation; a transfer profile inherits it and MUST scope its claims accordingly.

### 6.2 Witness federation (Stage 2b)

Stage 2 detects equivocation only when a verifier already holds two inconsistent, validly-signed checkpoints for the same origin (v0.2 §10.3); it defines no mechanism for discovering a second branch, so a keyed log with no independent witness quorum can maintain parallel self-consistent branches indefinitely (v0.2 §15 item 1, TM-49). Until an independent witness quorum exists, documentation and implementations MUST NOT describe split view as prevented — only as detectable in the two-checkpoint case — and a conforming Stage 2 implementation MUST NOT emit `corroboration: "witnessed"` (v0.2 §10.1). The wire contract is already C2SP tlog-cosignature compatible, so what is missing is federation and operations, not format: standing up independent witnesses does not require a change to the checkpoint or evidence shapes this document analyzes.

### 6.3 Tracked protocol gaps

The following are attacks the current specifications genuinely do not stop, as distinct from concerns attest deliberately excludes (§7). They are recorded here rather than resolved, and they are candidates for the versioning-and-evolution work of a future revision of these specifications. Each names the entries that carry it and what would close it.

| Gap | Entries | What closes it |
| --- | --- | --- |
| No normative resource ceilings — envelope size, nesting depth, proof-list and op-chain length, checkpoint text, archive expansion, manifest arrays, revocation-view scans — so bounds are implementation-local and outside the conformance surface | TM-22, TM-23, TM-24, TM-46 | Normative limits stated in the conformance surface |
| Artifact-manifest rollback — v0.1 §7.2 requires accepting any issuer-signed manifest for the series, with no monotonicity or recency rule | TM-36 | A normative manifest-currency (monotonicity/recency) rule |
| Key-manifest rollback — a verifier cannot discover a newer manifest, so an old one keeps a compromised key effective; v0.2 §10.4 freshness proves historical inclusion, never current status | TM-29 | The same manifest-currency rule, plus a status-freshness mechanism |
| OpenTimestamps pre-anchoring — the anchor commits to `checkpoint.note_bytes` while the signature lines are excluded (v0.2 §9.1, §11.1), so a chosen unsigned note can be pre-anchored and signed later by a holder of both log keys | TM-33 | Anchor coverage extended over the signature, or a normative note about what the anchor does not prove |
| Unbounded revocation timing — revocation records are not among the two loggable entry types (v0.2 §8, v0.2 §15 item 5), so a `revoked_at` backdated inside the signing key's validity window cannot be contradicted by any evidence the specifications define | TM-47 | Transparency coverage for revocation records, which would bound when a record came into existence |

Two neighbouring cases deliberately do NOT appear in this table, because naming everything a gap would empty the word of meaning. TM-12 and TM-15 turn on custody of buyer secrets: no protocol can reconstruct a secret no party retains, and v0.1 §8.2 places mandatory key custody outside the specification, so they are scope boundaries recorded in §7. TM-47 appears above only for its timing slice; the compulsion that motivates it is likewise a §7 boundary, since no signature scheme distinguishes a compelled signer from a willing one. TM-49's split-view discovery problem is absent because the specifications already declare it normatively and route it to witness federation (§6.2) rather than leaving it implicit.

## 7. Out-of-scope register

Concerns that attest deliberately does not address, consolidated from the verdicts above and from the founding constraints of `attest-v0.1.md` §2. Exclusion here is a scope decision, not an oversight, and is distinct from the gaps recorded in §6.3.

| Concern | Why out of scope |
| --- | --- |
| DRM circumvention | v0.1 §2 forbids it outright — attest defines no DRM-stripping functionality and MUST NOT be used, marketed, or implemented as a means of circumventing protection — so defeating an artifact's protection is never treated here as an attack the protocol should answer. |
| Content hosting, indexing, and distribution | attest is content-free by design and a conforming implementation MUST NOT host or index the works a receipt refers to (v0.1 §2), so the availability of an artifact, and the integrity of whatever host serves it beyond the signed `sha256` binding, lie outside the protocol. |
| Issuer honesty and reputation | attest proves what an issuer signed, not that the issuer is honest (TM-05, TM-06): a dishonest issuer's receipts are cryptographically indistinguishable from an honest one's, and reputation is a marketplace and client concern the specifications deliberately do not adjudicate. |
| Buyer endpoint compromise | Malware on the buyer's device defeats every buyer-held secret at once — salts, binding keys, and the private bundle — and neither specification defines endpoint security, attestation, or a secure-element requirement; the two-file export split reduces accidental sharing, never device compromise (TM-15). |
| Legal evidentiary weight | A receipt is evidence of a license grant and its terms, and even the strongest conditional v0.1 defines is explicitly "evidence, not a compliance determination" (v0.1 §6.1), so what weight a verified receipt carries before any court or regulator is outside what a signature scheme can determine (TM-40, TM-47, TM-57). |
| Transport security of delivery channels | v0.1 and v0.2 define document formats, canonicalization, and verification, but no delivery transport and therefore no confidentiality property for one; TLS appears solely as the manifest-fetch trust root (v0.1 §7.4), not as a delivery requirement, so channel confidentiality belongs to the deploying party (TM-13). |
| Key-custody UX beyond the bundle split | Mandatory key custody is explicitly out of scope for v0.1 (v0.1 §8.2), and the specifications' obligations stop at naming the private file, documenting it as unshareable, and warning whenever a conforming CLI accesses it — no backup, escrow, rotation, or recovery mechanism is defined (TM-15, TM-35, TM-44). |
