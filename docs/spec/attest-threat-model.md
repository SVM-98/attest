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

Entries are grouped by the lifecycle stage at which the attack is mounted: issuance (Group A), delivery (Group B), storage and sharing (Group C), verification (Group D), rotation and key compromise (Group E), and revocation, refund, and end-of-life (Group F). Every entry uses the format fixed in §1 — actor and precondition, impact, exactly one verdict from the §1 vocabulary with the specification sections that carry it, and a residual-risk line — and every entry names actors using the §2 canonical names verbatim.

An entry's verdict describes only what `attest-v0.1.md` and `attest-v0.2.md` currently implement. Where a mechanism bounds one slice of an attack and leaves another open, the open slice is named in the residual-risk line rather than absorbed into the verdict; where the residual is a gap with no mechanism behind it, the line says so in those words.

### Group A — Issuance

#### TM-01 — Receipt forgery without key compromise

- **Actor / precondition:** `network attacker`, or any party without the issuer's private key material, holding a genuine receipt and the issuer's published key manifest.
- **Impact:** A fabricated receipt would verify as issuer-signed evidence of a license grant that was never made.
- **Verdict:** Mitigated — v0.1 §10, v0.1 §11, v0.2 §3.  Forgery requires a valid signature over `JCS(payload)` under the pinned RFC 8032 ruleset (non-canonical `S`, small-order and non-canonical `A`/`R` all rejected); for a v0.2 receipt both the Ed25519 and the ML-DSA-65 leg must independently verify against the same manifest key entry, so breaking one primitive is insufficient.
- **Residual risk:** The guarantee is exactly as strong as the manifest that resolves the key. A `verifier` that obtained that manifest by any path other than a TLS fetch from the issuer's own domain is in TOFU (v0.1 §7.4) and can be handed an attacker's self-signed manifest instead — TM-11.

#### TM-02 — Cross-issuer impersonation

- **Actor / precondition:** `issuer`, or any holder of some domain's valid key material, signing a payload that names a different `issuer.id`.
- **Impact:** One domain's signing key would vouch for receipts attributed to another domain.
- **Verdict:** Mitigated — v0.1 §11, v0.2 §3.  The signing key is resolved **only** from the trust store's manifest for `payload.issuer.id`, and both the `kid`'s DNS-domain prefix and the resolving manifest's own `issuer` field MUST equal it; the hybrid path applies the identical binding to the single shared `kid`.
- **Residual risk:** None identified. The check is unconditional, precedes any signature computation, and is pinned by conformance (v0.1 §15, vector 5).

#### TM-03 — Post-CRQC forgery against Ed25519-only receipt stock

- **Actor / precondition:** CRQC attacker able to derive Ed25519 private keys from published public keys; the target receipts are v0.1, hence classical-only.
- **Impact:** Arbitrary v0.1 receipts, including backdated ones, that verify cleanly — retroactively fabricated purchase history that is cryptographically indistinguishable from genuine stock.
- **Verdict:** Mitigated — v0.2 §2, v0.2 §10, v0.2 §11.3, v0.2 §12.  For a receipt whose signed-receipt-core was actually logged and PQ-anchored, the hash-only OpenTimestamps leg (PQ-surviving, unlike the classical RFC 3161 leg) proves the signature bytes existed at or before a Bitcoin header time pinned in the verifier's own policy, and a configured `crqc_horizon` refuses standing to anything not PQ-surviving and not dated strictly earlier; receipts issued under the v0.2 hybrid profile require both legs and are unaffected.
- **Residual risk:** v0.2 §15 item 2 scopes this honestly: un-logged stock gets no existence-before-`T` guarantee at all, however old and however strongly originally signed, and bulk-logging historical stock is RECOMMENDED rather than required. Further, the horizon gates `transparency` and `corroboration` only (v0.2 §10, v0.2 §11.3) — it can never make an Ed25519-only forgery report `signature: "invalid"`, so post-CRQC discrimination between genuine and forged legacy receipts rests entirely on the presence of anchored-before-horizon evidence, which is precisely what un-logged stock lacks.

#### TM-04 — Payload precommitment ("log now, sign later")

- **Actor / precondition:** CRQC attacker that can submit entries to a Stage 2 log before the horizon and expects to derive an `issuer`'s Ed25519 key afterwards.
- **Impact:** An entry logged and anchored early would appear to prove that a receipt in fact signed much later already existed before the horizon, laundering a post-horizon forgery into pre-horizon standing.
- **Verdict:** Mitigated — v0.2 §12, v0.2 §8, v0.2 §10.2.  The only accepted receipt-entry hash domain is the signed-receipt-core, `SHA-256("attest-receipt-core-v1" || 0x00 || JCS(payload) || 0x00 || JCS(signatures))`, which commits to the signature bytes themselves, so a log entry can only ever describe a signature that already existed at logging time; evidence whose `entry` does not deep-equal the entry the verifier independently computed from the artifact fails entry matching before any checkpoint is consulted (v0.2 §16, leaf 28l).
- **Residual risk:** The commitment binds the signature bytes, not the signer's honesty: an `issuer` that signs and logs a false receipt before the horizon obtains entirely genuine anchored standing for it (TM-05).

#### TM-05 — Issuer signs false or misleading receipt content

- **Actor / precondition:** `issuer` in control of its own signing key and domain, asserting a purchase, license term, or work identity that does not correspond to reality.
- **Impact:** A cleanly verifying receipt whose content is untrue.
- **Verdict:** Out of scope — v0.1 §2, v0.1 §6.1.  attest proves what an issuer signed, not that the issuer is honest (v0.1 Appendix A, "malicious issuer"). The specification's own framing of a receipt is strictly evidentiary — evidence of a license grant and its terms, signed by the issuer identified in it, determining nothing about the seller's regulatory compliance, and even the strongest conditional v0.1 defines is "evidence, not a compliance determination" (v0.1 §6.1) — so the truth of `work`, `license`, and `survivability` assertions is a reputational, contractual, and legal question the protocol deliberately does not adjudicate.
- **Residual risk:** A dishonest issuer's receipts are cryptographically indistinguishable from an honest one's, and Stage 2 logging corroborates their existence without vouching for their content (v0.2 §15 item 3). The only protocol-level consequence available — the fail-closed `compromised` status — is the issuer's own to publish (v0.1 §7.3).

#### TM-06 — Delegated-issuer misattribution of a publisher

- **Actor / precondition:** `issuer` on the delegated-issuer path signing a receipt that names a `work.publisher` which never authorized it.
- **Impact:** A named publisher of record appears to stand behind a license grant it never made.
- **Verdict:** Out of scope — v0.1 §5.4, v0.1 §4.1.  `work.publisher` is a signed but unattested string: v0.1 defines no publisher authorization or counter-signature semantics, and the multi-entry `signatures` array reserved for a future publisher counter-signature is explicitly rejected today (exactly one entry for v0.1; exactly two ordered hybrid legs for v0.2, v0.2 §2.2).
- **Residual risk:** A `verifier` cannot distinguish an authorized delegated issuer from an unauthorized one from the receipt alone; the only binding attestation in the document is the signing issuer's own.

#### TM-07 — Backdated `issued_at`

- **Actor / precondition:** `issuer`, or an attacker holding both hybrid legs, controlling the signing key at signing time.
- **Impact:** A receipt that claims to predate its real creation — manufacturing priority, landing inside a favourable window, or placing a forgery before a compromise marking.
- **Verdict:** Mitigated — v0.1 §11, v0.1 §7.3, v0.2 §11.1, v0.2 §12.  `issued_at` MUST fall inside the signed key entry's `[valid_from, valid_to]` window in the resolving manifest, so backdating cannot reach behind that key's own signed `valid_from`, and the per-period signing-key discipline narrows that window; for a logged and anchored receipt, `anchored_before:<T>` bounds the time by which the signature demonstrably already existed.
- **Residual risk:** v0.1 §7.3 states the limit plainly: because `issued_at` lives inside the signed payload and is controlled by whoever holds the key, a backdated forgery is undetectable without an external trusted timestamp — and `anchored_before:<T>` is an upper bound on existence, never a lower bound (v0.2 §11.1). Neither document defines a result component asserting that an artifact was *not* in the log before some time, so an `issued_at` earlier than reality but still inside the key window remains undetectable, and an issuer that also controls its manifest controls `valid_from`.

#### TM-08 — Bogus `supersedes` lineage read as implicit revocation

- **Actor / precondition:** `issuer`, or a `network attacker` presenting a later receipt, where that receipt's `supersedes` names the target `receipt_id`.
- **Impact:** An earlier receipt is treated as retired without the buyer's consent and without a revocation record of the class its license actually permits.
- **Verdict:** Mitigated — v0.1 §5.1, v0.1 §6.2, v0.1 §12.  `supersedes` is normatively informational lineage: a superseding re-issue does not invalidate the superseded receipt absent buyer consent, and a `verifier` MUST treat it as lineage metadata only, never as an implicit revocation. The only mechanism that can change a receipt's revocation state is an authenticated revocation record classified against the license's own signed `revocability`.
- **Residual risk:** `supersedes` is an unverified pointer: nothing requires the named `receipt_id` to exist, to be verifiable, or to have been issued to the same `buyer`, so it can carry a misleading lineage claim that a human reader may over-interpret even though no conforming verifier acts on it.

### Group B — Delivery

#### TM-09 — In-transit tampering with a receipt

- **Actor / precondition:** `network attacker` controlling the path between `issuer` and `buyer`, or between `buyer` and `verifier`.
- **Impact:** Altered license terms, work identity, artifact hashes, or timestamps inside an otherwise genuine receipt.
- **Verdict:** Mitigated — v0.1 §9, v0.1 §10, v0.1 §11, v0.2 §3.  `payload` is the sole signed object and every byte of it is inside `JCS(payload)`; any change breaks the Ed25519 leg — and, for a v0.2 receipt, the ML-DSA-65 leg over the same canonical bytes — yielding `signature: "invalid"` (v0.1 §15, vector 3).
- **Residual risk:** Only `payload` is signature-covered. `delivery` is unsigned by construction (v0.1 §4.2); TM-11 and TM-12 state what tampering there can and cannot achieve.

#### TM-10 — Hybrid downgrade of a v0.2 receipt in transit

- **Actor / precondition:** `network attacker` with a v0.2 hybrid envelope in flight, seeking to have it evaluated under classical-only rules.
- **Impact:** If the ML-DSA-65 leg could be stripped and the remainder treated as a v0.1-shaped receipt, breaking Ed25519 alone would again suffice to forge.
- **Verdict:** Mitigated — v0.2 §1, v0.2 §2.2, v0.2 §3.  `attest_version` is inside the signed payload and cannot be stripped or rewritten without invalidating the signature; a stripped PQ leg is not a valid fallback but an outright rejection (`hybrid envelope requires exactly two signatures`), and entry count, order, `alg` values, and the shared `kid` are all checked before either leg is verified (v0.2 §6, leaves 26d–26f).
- **Residual risk:** Downgrade resistance protects v0.2 stock only. A v0.1 receipt is Ed25519-only by definition and remains so forever (v0.2 §1); its classical exposure is TM-03, not a downgrade.

#### TM-11 — Substituted key manifest at delivery

- **Actor / precondition:** `network attacker`, where the `verifier` holds no independently fetched manifest for the issuer and takes one from `delivery.issuer_manifest` or from a bundle.
- **Impact:** The attacker supplies a self-signed manifest naming the victim domain but listing its own keys; a matching forged receipt then reports `signature: "valid"` and `ok: true`.
- **Verdict:** Mitigated — v0.1 §7.4, v0.1 §11.1, v0.1 §4.2, v0.2 §15.  A manifest that did not arrive by a TLS fetch from the issuer's own domain is unauthenticated TOFU and MUST be reported as `trust: "unauthenticated_tofu"`, never silently upgraded; `trust` is resolved as early as `payload.issuer.id` can be read and MUST NOT be reset by a later step; and no amount of transparency or corroboration evidence may upgrade it (v0.2 §15 item 4).
- **Residual risk:** `trust` is not a component of `ok` (v0.1 §11.1), so this attack is signalled rather than prevented: a consumer that reads `ok` alone, or a UI that collapses the layered result into a boolean, cannot distinguish a TOFU-rooted forgery from a domain-rooted genuine receipt. The whole protection rests on the relying party reading `trust`.

#### TM-12 — Stripping `delivery.salt` in transit

- **Actor / precondition:** `network attacker` on a delivery path carrying a populated `delivery.salt`, where the `buyer` holds no other copy.
- **Impact:** The buyer permanently loses the ability to prove the buyer commitment for that receipt.
- **Verdict:** Mitigated — v0.1 §4.2, v0.1 §11.1, v0.1 §14.2.  Tampering with `delivery` can neither forge nor invalidate a receipt — the salt is meaningful only insofar as it reproduces the signed `buyer.commitment` — and the salt's durable home is the buyer's `.private.attest` bundle rather than the delivery envelope; a missing disclosure merely leaves `binding: "not_checked"`, which is not a component of `ok`.
- **Residual risk:** If no `.private.attest` copy exists the loss is unrecoverable from inside the protocol: the commitment is a one-way scrypt output and only the `issuer` can re-issue (v0.1 §8.1). This is TM-44's end state reached by an active attacker rather than by accident.

#### TM-13 — Interception of receipts in delivery

- **Actor / precondition:** `network attacker` with read access to the delivery channel — for a bare `.attest.json` in an order-confirmation email, that is the mail path (v0.1 §13).
- **Impact:** Exposure of purchase metadata, and — where the intercepted artifact is a private one — of the salt needed for a bearer-style binding proof.
- **Verdict:** Out of scope — v0.1 §2, v0.1 §13.  v0.1 and v0.2 define document formats, canonicalization, and verification; they define no delivery transport, and therefore no confidentiality property for one. TLS appears in the specifications solely as the manifest-fetch trust root (v0.1 §7.4), not as a delivery requirement. Channel confidentiality is the deploying party's.
- **Residual risk:** The protocol bounds the damage structurally rather than cryptographically: a shareable bundle carries no salts (v0.1 §14.1), while `delivery.salt` and `.private.attest` do (v0.1 §4.2, v0.1 §14.2). The privacy consequences of interception are analyzed in the companion `attest-privacy.md`.

### Group C — Storage and sharing

#### TM-14 — Stolen shareable `.attest` bundle presented as one's own

- **Actor / precondition:** Any party in possession of a victim's shareable bundle — a thief, or the recipient of a forwarded file.
- **Impact:** Bearer-style presentation of someone else's purchase evidence.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §8.1, v0.1 §8.2, v0.1 §11.  The shareable bundle has `delivery.salt` stripped from every envelope, so possession alone proves nothing about the holder: `binding` stays `not_checked` or `not_proven` without either a disclosed `(identifier, salt)` or a fresh challenge-response against `buyer.pubkey`, and the per-receipt commitment confines any single disclosure to one receipt.
- **Residual risk:** A receipt's own validity is bearer-independent — `binding` is not a component of `ok` (v0.1 §11.1) — so a relying party that never requests a binding proof gains nothing from the separation. The theft-resistant path is also frequently absent outright: `buyer.pubkey` is OPTIONAL and `null` by default for client-less flows (v0.1 §5.3, v0.1 §8.2).

#### TM-15 — Stolen `.private.attest` bundle

- **Actor / precondition:** Any party with access to the `buyer`'s storage or backups.
- **Impact:** Every salt in the file becomes usable for commitment recomputation, and where per-receipt buyer keypairs are stored, the thief can answer binding challenges as the buyer for every affected receipt.
- **Verdict:** Mitigated — v0.1 §14, v0.1 §13, v0.1 §8.1.  The two-file split keeps salts and buyer keys out of everything the buyer routinely shares; `attest disclose` is the per-receipt sharing unit precisely so that ordinary sharing never requires handling the whole private file; and per-receipt salts mean one receipt's secrets are not another's.
- **Residual risk:** The split bounds accidental exposure, not custody failure: a stolen `.private.attest` is a full compromise of every binding secret it contains, including the `buyer.pubkey` private keys that make TM-14 theft-resistant. Custody is the buyer's, and v0.1 §14.2 mandates only that the file be named and documented as private and that a conforming CLI warn whenever it is accessed.

#### TM-16 — Casual re-sharing of a shareable bundle

- **Actor / precondition:** `buyer` forwarding an export to a friend, a support desk, or a public post.
- **Impact:** Unintended disclosure of binding secrets or of purchase history.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §14.2, v0.1 §13.  The file a buyer is invited to share contains no salts and no buyer keys; the private file is separately named and documented as unshareable; the bundle's generated `README.html` MUST explain which file MUST NOT be shared; and per-receipt `disclose` exists so that sharing one receipt never means forwarding a library.
- **Residual risk:** The shareable bundle still discloses the full content of every receipt it contains — issuer, work, edition, timestamps, license terms — to whoever receives it. The split protects binding secrets, not purchase-history privacy; that surface is analyzed in `attest-privacy.md`.

#### TM-17 — Replay of a receipt across works or stores

- **Actor / precondition:** Any holder of a valid receipt attempting to present it as evidence for a different work, series, or issuer.
- **Impact:** One purchase would license many.
- **Verdict:** Mitigated — v0.1 §5, v0.1 §9, v0.1 §11, v0.1 §8.2.  Issuer, work identity, series, and license terms all live inside the single signed object, so nothing can be re-pointed without breaking the signature; the signing key is resolved only from the claimed issuer's own manifest; and a `buyer.pubkey` binding proof is bound to a fresh per-challenge nonce and to the receipt's own `receipt_id`, so a captured transcript cannot be replayed onto another receipt.
- **Residual risk:** The commitment-disclosure binding path is replayable by design (v0.1 §8.1) — TM-19. `work.identifiers` are issuer-scoped strings, so two issuers naming the same work carry no cross-issuer relationship any verifier can check.

#### TM-18 — Identifier recovery from a leaked salt

- **Actor / precondition:** Any party holding a receipt together with its salt — after TM-15, after a disclosure, or from an intercepted private artifact — where the identifier is drawn from a guessable population, which is typical for `email`.
- **Impact:** Recovery of the `buyer`'s plaintext identifier from the signed commitment, re-identifying the purchase and, for `email`, the person.
- **Verdict:** Mitigated — v0.1 §8.1, v0.1 §5.3.  The commitment is scrypt at fixed parameters (`N=32768, r=8, p=1, dkLen=32`) over a domain-separated, normalized identifier with a per-receipt 16-byte salt, and the RECOMMENDED `identifier_type` is `issuer-account` — a store-scoped identifier whose disclosure links nothing globally.
- **Residual risk:** scrypt RAISES the cost of dictionary recovery; it does not eliminate it. Against exactly the low-entropy identifiers v0.1 §8.1 names as the reason for choosing scrypt, an attacker holding the salt can still enumerate candidates, and the parameters are fixed by the specification version and MUST NOT be tuned upward per-issuer. An `email` receipt additionally links the buyer across issuers once recovered.

#### TM-19 — Replay of a disclosed `(identifier, salt)` pair

- **Actor / precondition:** A `verifier` that received a disclosure, or any party that later obtains it, where the `buyer` proved binding through the commitment path rather than the `buyer.pubkey` path.
- **Impact:** The recipient can re-present the same disclosure to claim buyer status for that receipt, and holds the plaintext identifier.
- **Verdict:** Mitigated — v0.1 §8.2, v0.1 §8.1, v0.1 §5.3.  The non-replayable path exists and is RECOMMENDED wherever a client app can hold a key: a challenge-response over a fresh nonce of at least 16 bytes, bound to `receipt_id`, proves possession without handing over anything reusable; and per-receipt salts confine a disclosure's damage to the single receipt disclosed.
- **Residual risk:** Disclosing `(identifier, salt)` is a REPLAYABLE BEARER PROOF, stated as such normatively: it permanently burns that receipt's binding secrecy toward that verifier and hands over the identifier itself. v0.1 §8.1 requires only that the verifier treat the identifier as personal data not retained beyond verification, and that issuers SHOULD offer re-issue via `supersedes` — neither is enforceable by the buyer, and `buyer.pubkey` is `null` by default (v0.1 §5.3), so this is the common path, not the exceptional one.

### Group D — Verification-time

#### TM-20 — Canonicalization ambiguity

- **Actor / precondition:** Any party constructing an envelope, where signer and `verifier` could disagree about which bytes are canonical.
- **Impact:** Two implementations compute different signature inputs for the same document — a signature valid to one and invalid to another, or an accepted payload whose meaning differs from the one actually signed.
- **Verdict:** Mitigated — v0.1 §9, v0.1 §9.1, v0.1 §11.  attest-JCS is RFC 8785 restricted by design to integers with `|n| < 2^53`, removing the IEEE-754 `Number::toString` interoperability surface entirely; duplicate member names are a parse-time rejection rather than last-value-wins; lone surrogates are rejected; key order is fixed by UTF-16BE code-unit sort; and step 0 requires every later step and every downstream consumer to operate on the single parsed object, never on the raw transmitted bytes or a re-serialization of them (v0.1 §15, vectors 6 and 7).
- **Residual risk:** None identified for the canonical form itself. The one subtlety a reimplementation must get right is placement rather than outcome: an over-range integer is rejected at canonicalization, not at schema validation, so the conforming result is `signature: "invalid"` with `schema: "not_checked"` (v0.1 §9).

#### TM-21 — Unknown-field smuggling

- **Actor / precondition:** `issuer`, or any party that can place a field into the payload before signing; the receipt is otherwise well-formed and validly signed.
- **Impact:** A signed field some consumers act on and others never see, letting one document mean two things.
- **Verdict:** Mitigated — v0.1 §11.2, v0.1 §5.  Unknown fields are allowed and are inside the signature input, so they cannot be added after the fact; and every unrecognized **top-level** payload field MUST be surfaced as a warning — the mechanism that separates "unrecognized" from "invalid" without letting either pass silently (v0.1 §15, vector 10).
- **Residual risk:** The warning obligation is scoped to top-level keys. The schema sets `additionalProperties: false` nowhere (v0.1 §5), so an unknown member nested inside `issuer`, `buyer`, `work`, `license`, or `survivability` is signed and accepted with no mandated warning; a consumer that acts on such a nested extension diverges from one that ignores it, and no protocol-level signal distinguishes them.

#### TM-22 — Resource exhaustion via a hostile receipt envelope

- **Actor / precondition:** `network attacker`, or any party that can submit a document to a `verifier` accepting envelopes from untrusted sources.
- **Impact:** Deeply nested, highly repetitive, or very large input consumes memory and CPU out of all proportion to the work of rejecting it, denying verification service.
- **Verdict:** Mitigated — v0.1 §9, v0.1 §11.  Rejection is early and single-pass: parsing is a precondition step performed exactly once, a rejecting step MUST short-circuit the remainder, no later step may re-parse or re-serialize the payload, and the attest-JCS profile rejects whole input classes — floats, `NaN`/`Infinity`, over-range integers, duplicate member names, lone surrogates — before any signature verification is attempted.
- **Residual risk:** Neither v0.1 nor v0.2 defines a normative ceiling on envelope byte size or JSON nesting depth, and the conformance corpora (v0.1 §15, v0.2 §16) pin none, so such ceilings are implementation-defined and sit outside the conformance surface: an implementation can be fully conforming and still accept an arbitrarily large or arbitrarily deep document. This is an open gap, not a closed one; what the specifications bound today is the amount of work done *per accepted parse*, not the size of input a verifier must be willing to refuse.

#### TM-23 — Resource exhaustion via hostile transparency evidence

- **Actor / precondition:** `mirror operator`, `network attacker`, or any party that supplies a Stage 2 evidence bundle — including one imported from a `.attest` bundle's `proofs/` member.
- **Impact:** Oversized checkpoint text, long proof lists, or unbounded operation chains make evidence evaluation the cheapest denial-of-service surface in the protocol; a raised exception on hostile input would additionally turn evidence handling into a crash oracle.
- **Verdict:** Mitigated — v0.2 §10.2, v0.2 §8, v0.2 §9.4.  Evidence is untrusted by contract and evaluation NEVER raises because of anything in it: at most one evidence bundle is evaluated per claim, every failure degrades to `(transparency: "not_checked", corroboration: "none")` with a warning naming the condition, entry admission is a closed schema that rejects any unknown member or unrecognized `type` before a checkpoint or proof is consulted (v0.2 §16, leaf 28n), and diagnostics render untrusted origin, name, tree-size, and signature-line values through a length-bounded `ascii()` escape rather than echoing them (v0.2 §9.3).
- **Residual risk:** As in TM-22, the numeric ceilings that actually bound work on a hostile bundle — proof-list length, operation count per proof, checkpoint text length — are implementation-defined. v0.2 fixes the failure *mode* (degrade, never raise) and the evaluation *count* (one bundle per claim); it does not fix the *size* of input a conforming verifier must accept or refuse.

#### TM-24 — Hostile bundle member names and archive contents

- **Actor / precondition:** Any party that can hand a `.attest` bundle to an importer that derives filesystem paths from member names.
- **Impact:** A crafted member name escapes the import directory (path traversal), or an oversized/highly compressible archive exhausts disk or memory during import.
- **Verdict:** Mitigated — v0.2 §14, v0.1 §14.1.  `proofs/` members are constrained to the single shape `proofs/<ULID>.json`, using the same 26-character Crockford base32 grammar the receipt schema already pins `receipt_id` to, and a conforming importer MUST reject any other shape — a nested path, a nested member, a non-`.json` suffix, a filename that is not a syntactically valid ULID — **before** deriving any filesystem path from it, precisely because the member name is attacker-supplied bundle content.
- **Residual risk:** That validate-before-join rule is normative for `proofs/` only; the other bundle members (`receipts/`, `manifests/`, `legal/`, `README.html`, v0.1 §14.1) carry no equally explicit member-name grammar or ordering requirement. Neither document sets a decompressed-size, member-count, or compression-ratio ceiling for bundle import — the same implementation-defined-ceiling gap as TM-22.

#### TM-25 — Cross-implementation verdict divergence

- **Actor / precondition:** Any party who can choose which `verifier` a receipt is presented to, given that conforming implementations exist in more than one language and runtime.
- **Impact:** Verdict shopping — a receipt accepted by one implementation and rejected by another destroys the evidentiary value of any single verdict.
- **Verdict:** Mitigated — v0.1 §15, v0.2 §6, v0.2 §16, v0.2 §9.3.  Conformance is defined as producing the expected `VerificationResult`, every component matched exactly, for **every** vector in a 66-leaf corpus run against every conformance runner from the same shared golden files; the hybrid and checkpoint paths pin their error literals verbatim so divergence surfaces as a literal mismatch rather than a silent difference; and grammar decisions that would otherwise drift between runtimes — checkpoint `origin` and `LogKey.name` character classes, diagnostic escaping — are restricted to printable ASCII so acceptance can never depend on a runtime's Unicode tables.
- **Residual risk:** v0.1 §15 names one uncovered property itself: small-order and non-canonical `A`/`R` rejection, half of the pinned ruleset in v0.1 §10, is not separately vectorized and currently relies on the pinned library's guarantee rather than on a fixture. v0.2 §9.3 also records a known TypeScript/Python quote-style deviation in checkpoint diagnostics; it affects rendered text only, never parsing, acceptance, or verdicts.

#### TM-26 — Corroboration presented as authenticity

- **Actor / precondition:** `issuer`, `log operator`, `mirror operator`, or any party assembling a bundle, where the artifact genuinely is in a log and the audience conflates "logged" with "authentic".
- **Impact:** A TOFU-rooted, or outright invalid, artifact is accepted because it arrives with transparency evidence attached.
- **Verdict:** Mitigated — v0.2 §10, v0.2 §7.1, v0.2 §14, v0.2 §15.  The three Stage 2 components are informational by construction: they never affect `signature`, `schema`, `revocation`, `binding`, or `ok`; the log NEVER upgrades `trust`; `corroboration` says an artifact was independently observable, never who was entitled to write it; the transparency verdict is resolved before and independently of the receipt's own verdict, so a receipt rejected for a compromised key still reports its genuine `logged` standing without being rescued by it (v0.2 §16, leaves 28a and 28i); and a bundle's `README.html` MUST state in plain language that a proof is corroboration, not authenticity.
- **Residual risk:** The separation is enforced in the result vocabulary, not in what a consumer does with it — the same reading risk as TM-11. `manifest_freshness: verified_as_of:<N>` is the sharpest case: it proves only that a manifest existed unmodified at that point in the log's history and MUST NOT be read as a claim about a key's current status, since a later manifest version may since have marked the same key `compromised` (v0.2 §10.4).

#### TM-27 — Fabricated or withheld evidence from a mirror

- **Actor / precondition:** `mirror operator`, or a `network attacker` in front of one, serving the republished static file set a `verifier` fetches transparency evidence from.
- **Impact:** Fabricated inclusion or checkpoint evidence would manufacture standing; withheld evidence denies genuine standing.
- **Verdict:** Mitigated — v0.2 §10.2, v0.2 §9.2, v0.2 §7.3.  Anything a mirror serves is untrusted evidence exactly like an adversary's: the `entry` MUST deep-equal the entry the verifier computed itself from the artifact being corroborated, the checkpoint MUST verify under a `LogKey` pinned out-of-band in the verifier's own trust store — never taken from a bundle — under the fail-closed Ed25519 **and** ML-DSA-65 rule, the declared `tree_size` MUST equal the verified checkpoint's own, and the inclusion proof MUST verify against that checkpoint's root; anything short of that degrades to `not_checked` rather than to partial trust.
- **Residual risk:** Availability is not a protocol property. A mirror — or the log's own primary host — that simply withholds evidence leaves `transparency: "not_checked"`, and nothing distinguishes censorship from an artifact that was never logged. Fabrication beyond the verifier's pinned keys is impossible; a mirror colluding with a compromised log key is TM-33.

### Group E — Rotation, continuity, and key compromise

#### TM-28 — Key-substitution hijack of the manifest chain

- **Actor / precondition:** `network attacker`, or any party able to serve a manifest, offering a `verifier` a manifest at a version above the one it already trusts.
- **Impact:** Attacker-controlled keys are adopted as the issuer's current keys, making every subsequent forgery verify.
- **Verdict:** Mitigated — v0.1 §7.3, v0.1 §7.1, v0.1 §11.1.  A version-N+1 manifest is auto-trusted only if signed by a key that was `active` in the version-N manifest already trusted; version gaps are bridgeable only by validating every intermediate manifest in sequence; a discontinuous rotation, or conflicting manifests for the same issuer, MUST force `trust: "unverified_rotation"` — overriding provenance — and MUST NOT be auto-accepted; and each key's `kid`, `pub`, `valid_from`, `valid_to`, and `status` lives inside the manifest's own signed body, so nothing about a key's lifecycle is tamperable without breaking `manifest_signature` (v0.1 §15, vectors 11, 14, 14b).
- **Residual risk:** `trust` is not a component of `ok` (v0.1 §11.1): a receipt verified against a discontinuously-rotated manifest still reports `signature: "valid"` and `ok: true` alongside `unverified_rotation`. The rule bounds *auto-acceptance* and labels the result; it does not by itself refuse the receipt.

#### TM-29 — Stale manifest presented as current

- **Actor / precondition:** `network attacker`, `mirror operator`, or a bundle assembler serving an older, genuinely issuer-signed key manifest while a newer version exists — typically one that has since marked a key `compromised`.
- **Impact:** The fail-closed compromise rule never fires, and forgeries made with the compromised key keep verifying.
- **Verdict:** Mitigated — v0.1 §7.3, v0.2 §10.4, v0.2 §16.  Continuity is version-chained rather than newest-wins, so a bundle cannot dodge the chain by shipping only a high version; a log-corroborated `key-manifest` claim above version 1 is honored only when the verifier's **own** trust store independently holds a validated, gapless chain from version 1, and otherwise `corroboration` is forced back to `none` with `corroboration_requires_rotation_chain` (v0.2 §16, leaf 28h) — deliberately stricter than the `unverified_rotation` check, which tolerates an absent chain; and `manifest_freshness: verified_as_of:<N>` is explicitly a historical statement, never a current-status claim.
- **Residual risk:** A verifier holding only version N has no in-protocol mechanism to learn that version N+1 exists and marks a key `compromised`; the fail-closed rule can only act on the manifest that actually resolves. Log inclusion proves publication, not currency (v0.2 §10.4), and Stage 2 defines no latest-version map. Offline verifiers and long-lived trust stores carry this exposure for as long as they go un-refreshed.

#### TM-30 — Hybrid-to-Ed25519-only downgrade of a manifest signature

- **Actor / precondition:** CRQC attacker that has broken Ed25519 only, against an `issuer` whose signer is hybrid, forging a rotation manifest without the PQ leg.
- **Impact:** A rotation forged with the classical primitive alone would install attacker keys and thereby bypass hybrid protection on every receipt that rotation vouches for.
- **Verdict:** Mitigated — v0.2 §2.3, v0.2 §4, v0.2 §6.  `manifest_signature` is AND-verified fail-closed in both directions: a hybrid signer's manifest missing `sig_ml_dsa_65` is invalid, and an Ed25519-only signer's manifest carrying a stray `sig_ml_dsa_65` is equally invalid. A downgraded rotation candidate is therefore not validly signed *for continuity purposes*, the chain is discontinuous at that point, and `trust: "unverified_rotation"` follows.
- **Residual risk:** v0.2 §6, leaf 26h pins the honest outcome: the receipt's own hybrid signature still verifies and the receipt still reports `ok: true` — the downgrade degrades `trust`, it does not invalidate anything. A consumer that ignores `trust` gains nothing from this rule (TM-11).

#### TM-31 — Compromise of a single hybrid leg

- **Actor / precondition:** CRQC attacker (Ed25519 leg) or a classical cryptanalytic advance against ML-DSA-65, with exactly one leg of a hybrid signer's key pair compromised.
- **Impact:** With one primitive broken, forgery would follow immediately if either leg alone sufficed.
- **Verdict:** Mitigated — v0.2 §3, v0.2 §2.3, v0.2 §13.  Verification is AND semantics: both legs must independently verify over the same canonical bytes, and both resolve through one signed manifest key entry under one shared `kid`, so pairing one signer's Ed25519 key with another's ML-DSA-65 key is structurally impossible without forging the manifest itself; the same AND rule governs manifest signatures, artifact manifests, and revocation records.
- **Residual risk:** The AND rule protects v0.2 artifacts. An Ed25519-only key entry remains legitimate (v0.2 §2.3), and a v0.1 receipt has one leg by definition (v0.2 §1) — for those, single-leg compromise is total compromise, i.e. TM-32.

#### TM-32 — Compromise of both hybrid legs (full signer compromise)

- **Actor / precondition:** Any party obtaining the `issuer`'s private key material — both legs, or the single Ed25519 key of a non-hybrid signer.
- **Impact:** Arbitrary receipts, backdated within the key window, verifying cleanly against the issuer's own manifest.
- **Verdict:** Mitigated — v0.1 §7.3, v0.1 §11, v0.2 §10, v0.2 §12.  Compromise fails closed and retroactively: a key marked `compromised` in the resolving manifest invalidates **all** signatures ever made with it, regardless of `issued_at`, unconditionally, on receipts and on side-documents alike (v0.1 §15, vector 13); the one-key-per-period discipline v0.1 §7.3 RECOMMENDS bounds the blast radius to a single period where an issuer follows it; and receipts that were logged and PQ-anchored keep honest, independently-resolved `transparency`/`corroboration` standing describing what existed and when (v0.2 §16, leaf 28i).
- **Residual risk:** The fail-closed rule takes effect only once a **resolving** manifest marks the key `compromised`. Until it does — and indefinitely, for any verifier whose trust store still resolves an older manifest (TM-29) — the attacker's forgeries report `signature: "valid"`, `ok: true`. The retroactive invalidation is also indiscriminate by design: every genuine receipt signed by that key is invalidated with the forgeries, and re-issue of affected receipts is a SHOULD (v0.1 §7.3), not a guarantee.

#### TM-33 — Log signing-key compromise

- **Actor / precondition:** Any party obtaining a Stage 2 log's checkpoint-signing keys — both legs, since checkpoint standing is itself AND-verified (v0.2 §9.2).
- **Impact:** The attacker signs checkpoints for trees of its choosing, fabricating `logged` standing and equivocating at will.
- **Verdict:** Mitigated — v0.2 §7.3, v0.2 §10, v0.2 §15.  Signing capability is operationally separated from the far more exposed ingestion path: the CI-side append step holds no key material of any kind, so compromising it confers only the ability to propose entries; the ceremony-side signer independently recomputes the tree root from `entries.jsonl` and refuses to sign unless it matches the candidate and unless the new tree is a valid RFC 6962 consistency extension of the prior signed tree. Verifier-side, log keys are pinned out-of-band and MUST NOT be taken from a bundle; and no value of `transparency` or `corroboration` can change `trust`, `signature`, or `ok`, so even a fully compromised log cannot make an invalid receipt valid (v0.2 §15 items 3 and 4).
- **Residual risk:** A compromised log key does let an attacker manufacture `transparency: "logged"` / `corroboration: "logged"` for artifacts never actually appended, and lets it equivocate silently (TM-34). It cannot backdate: `anchored_before:<T>` derives from Bitcoin block headers pinned in the verifier's own `AnchorPolicy` (v0.2 §11.1, v0.2 §11.2), so fabricated standing can never be dated earlier than the moment the note was actually produced. Neither document defines an in-protocol revocation for a pinned `LogKey`; withdrawing one is an out-of-band trust-store update (v0.2 §7.3).

#### TM-34 — Log equivocation and split views

- **Actor / precondition:** `log operator`, or a party holding its keys, serving two self-consistent but mutually inconsistent histories to different audiences.
- **Impact:** An artifact appears logged to one `verifier` and absent to another; inclusion evidence stops meaning "in the one true log".
- **Verdict:** Mitigated — v0.2 §10.3, v0.2 §10.2, v0.2 §16.  When a verifier holds a validly hybrid-signed prior checkpoint for the same pinned origin whose tree is not RFC 6962-consistent with the current one, that is conclusive proof the log signed two incompatible histories, and it MUST surface as the hard verdict `transparency: "equivocation_detected"` — the one Stage 2 outcome never absorbed into `not_checked` (v0.2 §16, leaf 28f). A prior checkpoint that does not itself verify, or that arrives with no consistency proof, is fail-safe rather than an accusation.
- **Residual risk:** Detection requires the verifier to **already hold both** inconsistent checkpoints. v0.2 §15 item 1 states the bound normatively: there is no mechanism for a verifier that has seen only one branch to discover a second, and a keyed log with no independent witness quorum can maintain parallel self-consistent branches indefinitely. Anchors bound *time*, not *branching*, and `corroboration: "witnessed"` is defined but unreachable — a conforming Stage 2 implementation MUST NOT emit it (v0.2 §10.1).

#### TM-35 — Theft of a buyer binding key

- **Actor / precondition:** Any party obtaining a `buyer`'s `buyer.pubkey` private key, typically together with the `.private.attest` that stores it.
- **Impact:** The thief answers binding challenges as the buyer, on the strong path that exists precisely to be theft-resistant.
- **Verdict:** Mitigated — v0.1 §8.2, v0.1 §8.1, v0.1 §11.1.  The binding key is OPTIONAL and keys SHOULD be per-receipt, so a stolen key compromises one purchase rather than a buyer identity; a verifier MUST NOT treat `buyer.pubkey` equality across two receipts as proof of buyer identity, which denies the thief any cross-receipt leverage; and the base commitment (v0.1 §8.1) is untouched by the loss.
- **Residual risk:** Nonce-binding prevents transcript *replay*, not impersonation: a thief holding the private key answers any fresh challenge correctly. Where the keys live in `.private.attest`, this is the same event as TM-15. v0.1 defines no binding-key revocation or rotation path, and a superseding re-issue does not invalidate the superseded receipt absent buyer consent (v0.1 §5.1) — so the compromised receipt stays answerable by the thief.

#### TM-36 — Artifact-manifest rollback

- **Actor / precondition:** `network attacker`, `mirror operator`, or a coerced `issuer`, where an older but genuinely issuer-signed artifact manifest for the series exists and is served in place of the current one.
- **Impact:** The `buyer` is steered to a superseded artifact set — an outdated or withdrawn build, or one whose known-bad hashes have since been replaced — while every integrity check the protocol defines passes.
- **Verdict:** Mitigated — v0.1 §7.2, v0.1 §7.3, v0.2 §13.  An artifact manifest is accepted only if its resolving key manifest is self-consistent, its `kid` resolves to a key entry with `status == "active"`, its `released_at` falls inside that key's validity window, its `issuer` matches the key manifest's, and its signature verifies — with the hybrid AND rule applied for a hybrid signer — so the served document is authentic, unmodified, and genuinely the issuer's.
- **Residual risk:** Authenticity is not currency, and this is an open gap rather than a bounded one. v0.1 §7.2 requires a verifier to accept **any** issuer-signed artifact manifest for the series and states no monotonicity, recency, or freshness rule over its `version` field; v0.2 §8 defines exactly two loggable entry types and v0.2 §15 item 5 confirms artifact manifests are not among them, so no transparency evidence exists to date one manifest against another. A verifier therefore cannot distinguish the current artifact manifest from a validly-signed older one.

### Group F — Revocation, refund, issuer disappearance, buyer loss

#### TM-37 — Forged or replayed revocation record

- **Actor / precondition:** `network attacker`, or any party able to inject records into a revocation view the `verifier` consults but does not control.
- **Impact:** A receipt reads `revoked` (and `ok: false`) on the strength of a record the `issuer` never signed.
- **Verdict:** Mitigated — v0.1 §12.1, v0.1 §12.2, v0.1 §7.3.  A record counts only if its resolving key manifest is self-consistent, its `signature.kid` resolves to a key entry with `status == "active"` — a `compromised` or `retired` key's record is rejected exactly as it would be on a receipt — its `revoked_at` falls inside that key's validity window, and its signature verifies over `JCS(record)` with `signature` removed under the pinned ruleset. Anything else MUST be ignored with a warning, never honored, and malformed, wrong-typed, or missing input fails closed rather than raising.
- **Residual risk:** `revoked_at` is signed by the issuer and is therefore exactly as trustworthy as the issuer, subject only to the key-window check (TM-41). v0.2 §15 item 5 confirms revocation records are not a loggable entry type, so no transparency evidence can corroborate when a record actually appeared.

#### TM-38 — Post-CRQC forged revocation through the classical leg

- **Actor / precondition:** CRQC attacker that has broken Ed25519 only, against an `issuer` whose signing key is hybrid.
- **Impact:** A forged `policy` or `refund_window` record would drive `revocation: "revoked"`, `ok: false`, through the classical primitive alone — killing genuine receipts despite hybrid protection holding everywhere else.
- **Verdict:** Mitigated — v0.2 §13, v0.2 §2.3, v0.2 §16.  The hybrid AND rule is extended to revocation records and artifact manifests: if the signing key's own manifest entry carries `pub_ml_dsa_65`, the side-document MUST also carry a valid `sig_ml_dsa_65` over the same signed bytes or it is invalid and ignored, symmetrically fail-closed in both directions. An Ed25519-only record against a hybrid key is unconditionally ignored — `revocation: "unknown"`, `ok: true` — regardless of any transparency or anchor evidence presented alongside it (v0.2 §16, leaf 28m).
- **Residual risk:** The rule protects hybrid-keyed issuers only. A receipt whose issuer is Ed25519-only has no PQ leg to require, so its revocation records stay exactly as forgeable post-CRQC as its receipts (TM-03). v0.2 §13 also scopes the fix precisely: it closes the hybrid-downgrade gap in side-document authentication, and extends neither transparency coverage nor anti-equivocation to those documents (v0.2 §15 item 5).

#### TM-39 — Revocation-feed suppression

- **Actor / precondition:** `network attacker`, or a host that stops serving records, leaving the `verifier`'s revocation view incomplete or absent.
- **Impact:** A genuinely revoked receipt is presented to a verifier that cannot learn it was revoked.
- **Verdict:** Mitigated — v0.1 §12.3, v0.1 §11.1, v0.1 §11.2.  Suppression cannot be laundered into false confidence: the freshness anchor `T` in `not_revoked_as_of:<T>` MUST be the maximum `revoked_at` across **authenticated** records only, so an injected far-future record cannot inflate reported freshness; with zero authenticated records the result MUST be the bare literal `unknown`; and the layered result reports the state of the feed rather than collapsing it into the receipt's validity.
- **Residual risk:** This is a disclosure guarantee, not an availability one. `unknown` and any `not_revoked_as_of:<T>` — however stale — leave `ok` unaffected by design, and an offline verifier reports `unknown` honestly rather than failing closed (v0.1 §11.2), so an attacker who withholds the feed can have a revoked receipt read as `ok: true`. Neither document defines a maximum acceptable staleness for `T`, nor requires a verifier to refuse a receipt whose feed is too old; that policy belongs to the relying party.

#### TM-40 — Unjustified mass revocation

- **Actor / precondition:** `issuer` in control of an active signing key, acting in bad faith or under commercial pressure.
- **Impact:** A large body of legitimately issued receipts is declared revoked.
- **Verdict:** Mitigated — v0.1 §6.1, v0.1 §6.2, v0.1 §12.2, v0.1 §11.1.  The revocation class is fixed inside the signed payload at issuance and cannot be changed afterwards: against a `revocability: "none"` receipt an authenticated, matching record is itself treated as invalid (`revocation: "invalid_revocation_ignored"`, a warning, `ok` unaffected) — without which the revocation machinery would falsify every irrevocability assertion made under the v0.1 §6.1 conditional (v0.1 §15, vector 16). Revocation never erases evidence either: the receipt's `signature` component stays `valid` and the signed terms remain readable in the bundle.
- **Residual risk:** `refund_window` and `policy` receipts are revocable by their own signed terms, and a `policy` record is honored as-is because a verifier cannot evaluate the referenced policy — so for those classes an unjustified revocation does drive `ok: false`, with no in-protocol counter-evidence path for the buyer. Restitution is a commercial and legal matter the protocol does not address (v0.1 §2).

#### TM-41 — Coerced revocation or coerced signing

- **Actor / precondition:** `coercive third party` compelling an `issuer` through legal process; the issuer retains valid key material and can be ordered to use it.
- **Impact:** A validly-signed revocation — or key-status change — that the issuer would not otherwise have produced, including one dated to fall inside a refund window.
- **Verdict:** Mitigated — v0.1 §6.2, v0.1 §12.2, v0.1 §5.1.  Compulsion cannot exceed what the receipt's own signed class permits: a `revocability: "none"` receipt absorbs a compelled record as `invalid_revocation_ignored`; a compelled `refund_window` record is honored only if its own signed `revoked_at` falls at or before `issued_at + revocation_window_days`, evaluated against the record's signed time and never the verifier's clock, so neither side can shift the boundary by lying about local time; and a compelled re-issue cannot retire the original, since `supersedes` is lineage metadata and never an implicit revocation.
- **Residual risk:** For `policy`-class receipts a compelled record is honored as-is. More sharply, a compelled issuer can publish a manifest marking its own key `compromised`, which fails closed across **all** past signatures by that key regardless of `issued_at` (v0.1 §7.3) — a safety rule a coercive third party can weaponize into a blanket invalidation. Nothing in v0.1 or v0.2 offers the buyer a counter-attestation, and no mechanism distinguishes a compelled signature from a voluntary one.

#### TM-42 — Receipt presented after a refund

- **Actor / precondition:** `buyer` holding a `revocability: "refund_window"` receipt whose purchase was refunded and for which the issuer signed a matching record.
- **Impact:** The refunded buyer presents the receipt as live entitlement evidence.
- **Verdict:** Mitigated — v0.1 §12.2, v0.1 §5.5, v0.1 §12.1.  An authenticated, matching record inside the window yields `revocation: "revoked"` and `ok: false`; the window is anchored to the receipt's own signed `issued_at` and evaluated against the record's own signed `revoked_at`, never the verifier's clock; and a record that authenticates but falls outside the window is ignored with a warning rather than silently honored, so the boundary cuts both ways.
- **Residual risk:** This works only for a verifier that actually consults the feed. TM-39's suppression case and the ordinary offline case (v0.1 §11.2) both leave a refunded receipt reading `ok: true` with `revocation: "unknown"`. The window length itself is issuer-declared at issuance (`1 ≤ n ≤ 3650` days), so its adequacy is a commercial term, not a protocol property.

#### TM-43 — Issuer disappearance

- **Actor / precondition:** No adversary required — insolvency, acquisition, or a `coercive third party` forcing a shutdown; the issuer's domain, manifest endpoint, and services cease to exist.
- **Impact:** Verification material and the referenced terms could become unobtainable, silently voiding evidence the buyer holds.
- **Verdict:** Mitigated — v0.1 §14.1, v0.1 §7.4, v0.1 §2, v0.2 §7.2.  Verification is user-held and offline-capable: the shareable bundle carries the receipts, the key and artifact manifests, and the license, mirror-policy, and end-of-life texts, each verified against its signed hash binding at export time — a receipt whose referenced terms can no longer be produced is a signature without a deal, so the bundle preserves the deal; offline verification MUST work from a local trust store of key manifests; and a Stage 2 log is a static, mirrorable file set any independent party can republish, whose root is always recomputable from `entries.jsonl`.
- **Residual risk:** What survives is the evidence and the terms — which is exactly what v0.1 §2 promises — not access. After disappearance nothing further can be signed: the revocation feed freezes and `T` stops advancing (v0.1 §12.3), a compromise discovered afterwards can never be published as a `compromised` status (v0.1 §7.3), no artifact manifest can be issued for a new build (TM-36's rollback residual becomes permanent), and redownload depends on hosting that no longer exists. `survivability.end_of_life` records the issuer's declared intent, including the seed value `escrow` (v0.1 §5.6), but v0.1 defines no escrow mechanism that enforces it.

#### TM-44 — Buyer loses salts, keys, or bundles

- **Actor / precondition:** `buyer` whose `.private.attest` — or the delivery envelope carrying the salt — is lost, never backed up, or destroyed.
- **Impact:** The buyer can no longer prove that the receipt is theirs.
- **Verdict:** Out of scope — v0.1 §8.2, v0.1 §14.2, v0.1 §2.  Custody is the buyer's: mandatory key custody is explicitly out of scope for v0.1, and the specification's obligations stop at requiring the private file to be named and documented as private and a conforming CLI to warn whenever it is accessed.
- **Residual risk:** The loss is unrecoverable from inside the protocol — the commitment is a one-way scrypt output over an unrecoverable per-receipt salt, and no backup, escrow, or recovery mechanism is defined; the only remedy is issuer re-issue (v0.1 §8.1), which requires the issuer still to exist (TM-43). The receipt itself keeps verifying, since `binding` is not a component of `ok` (v0.1 §11.1); what is lost is exclusivity — anyone else holding a copy of that receipt is thereafter no less able to present it than the buyer.
