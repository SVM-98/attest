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
