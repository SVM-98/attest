# attest — Relationship to Existing Standards (non-normative)

**Non-normative.** This document imposes no requirements and uses no RFC 2119
keywords (MUST, SHOULD, MAY, and their negatives, as fixed in `attest-v0.1.md`
§1) with conformance force. For each of seven adjacent standards it states
where attest's boundary lies against it — in terms an expert in *that*
standard would recognize as an accurate description of their own standard's
concepts, not a simplified restatement built to be easy to dismiss. Where a
concrete future bridge between attest and a given standard is plausible, the
entry says what it could look like; where none is, the entry says that
instead.

This document exists in part because several of the standards below define a
concept that sounds like, or is literally named, something attest also
defines — most pointedly SCITT's "receipt" (entry 6) and RATS's "attestation"
(entry 7). Each entry states the actual relationship precisely enough that
the collision cannot be mistaken for equivalence, or for one standard being a
redundant reinvention of the other.

## 1. W3C Verifiable Credentials

The W3C Verifiable Credentials Data Model describes a claim as three
cooperating roles: an `issuer`, a `credentialSubject` carrying the claimed
attributes, and one or more securing mechanisms — embedded Data Integrity
proofs or an enveloping JOSE/COSE wrapper — that establish who signed the
credential and that it has not been altered. The claim shape itself is
open-world: a credential's properties are defined by whatever vocabulary its
`@context` (or, for a plain-JSON credential, its declared `type`) brings in,
and a verifier is expected to accept credentials whose issuer or type it has
never seen before, deferring to trust-list or issuer-registry policy to
decide whether to honor them. Proof formats are deliberately plural by
design, not a single pinned mechanism — a verifier that speaks the data model
still has to implement whichever proof suite a given credential actually
used.

attest's payload takes the opposite position on both axes. Its field set is
a single closed JSON Schema (`docs/spec/schema/attest-receipt.schema.json`)
with no `@context` indirection and no open vocabulary to resolve; and its
signing step is not a choice among proof suites but one mandatory
canonicalization profile, attest-JCS (v0.1 §9), whose output is byte-exact
across the Python and TypeScript reference implementations by construction
of the 97-leaf conformance corpus — a verifier that does not reproduce
attest-JCS exactly cannot verify an attest receipt at all. Choosing a
purpose-built envelope over a Verifiable Credential is choosing that
closed-schema, single-canonicalization determinism over the VC model's
open-world extensibility and proof-suite plurality; the two are trading in
opposite directions on purpose, not one failing to be the other.

What a future bridge could look like: an attest envelope (`payload` plus
`signatures`) could be embedded as an opaque, independently-verifiable object
inside a `credentialSubject`, letting a wallet that already speaks the VC
ecosystem carry a receipt as one more presentable claim. That would be
carriage, not equivalence — the VC's own proof would establish
wallet-presentation trust, while the embedded attest signature would still be
verified on its own terms by an attest-aware verifier. Nothing in v0.1 or
v0.2 defines such a wrapper, and attest depends on none existing.

## 2. eIDAS 2.0 and the EUDI Wallet

eIDAS 2.0 (Regulation (EU) 2024/1183) builds the European Digital Identity
Wallet framework around Person Identification Data, Electronic Attestations
of Attributes (EAAs) — with a separately defined, more strongly regulated
qualified-EAA tier — issued by attestation providers and presented to relying
parties through a wallet under the supervision of Member State conformity
assessment and a qualified-trust-service-provider trust framework. An EAA's
evidentiary weight comes from that regulatory apparatus: which provider
issued it, whether the provider and its issuance process are qualified, and
which trust list vouches for the provider's certificate.

attest issues merchant purchase evidence with none of that apparatus present
anywhere in its verification path: an issuer-signed record of a license
grant (v0.1 §4), verified entirely offline against a trust-on-first-use or
TLS-rooted key manifest (v0.1 §7.4), with no wallet, no attestation
provider, no qualified trust service, and no Member State supervision
involved in producing or checking one. A receipt's evidentiary weight comes
from the issuer's own signature and reputation — v0.1 §2 is explicit that a
receipt is evidence of a license grant, not a claim of ownership or of any
seller's regulatory compliance, and the threat model's TM-05/TM-06 note that
a dishonest issuer's receipts are cryptographically indistinguishable from an
honest one's. The two frameworks attest to different kinds of fact for
different kinds of relying party, and neither depends on the other existing.

What a future bridge could look like: an attest receipt could be carried as
one of the attributes an EAA attests to (a wallet holding "this identity
purchased title X" as a wallet-presentable attestation), or the buyer-side
binding proof attest already defines (v0.1 §8) could someday be satisfied by
a wallet-mediated presentation instead of a bare public-key challenge.
Either direction is potential future carriage; attest depends on neither.

## 3. JOSE/JWS and COSE

This is the objection an expert in either format will raise first: why not
just sign a detached JWS or a COSE_Sign1 structure over the payload? JOSE
(JWS, RFC 7515) and COSE (RFC 9052) both sign a serialized, encoded wire
form of the payload — the base64url header and payload segments joined by
JWS Compact Serialization, or a COSE_Sign1 structure's protected header and
payload bytes — and the signature covers exactly those transmitted bytes,
whatever a particular signer happened to encode. That is precisely why
detached content is a first-class, well-used feature of both formats: the
payload segment can be stripped from the envelope and carried separately,
because the signature was never over a canonical re-derivation of a parsed
object, only over the octets the signer chose to transmit.

attest inverts that relationship. The signature input is `JCS(payload)`
(v0.1 §9) — the RFC 8785-canonical serialization of the *parsed* payload
object, computed fresh from its content rather than preserved from the wire.
Anyone holding the parsed `payload` as a JSON object, in any language, can
recompute the exact bytes that were signed by re-running the canonicalizer;
there is no side channel, no detached segment, and no particular wire
encoding a holder must preserve to keep a receipt verifiable. That is what
offline determinism buys: a receipt's signed bytes are a pure function of
its parsed content, so an exported bundle re-serialized by a different tool
years later (v0.1 §14) still verifies. The cost is the mirror image of that
benefit and is stated here plainly: every implementation must canonicalize
identically — UTF-16BE member-name ordering, the integer-only number
restriction with `|n| < 2^53` that v0.1 §9 layers on top of RFC 8785's own
I-JSON number rule, duplicate-member rejection, lone-surrogate rejection —
and a canonicalizer bug is a silent signature mismatch, not a loud parse
error. JOSE and COSE avoid that requirement entirely by making the
transmitted wire form itself the trust anchor; attest's bet is that a
strict, narrow, corpus-enforced canonicalizer is the safer engineering
trade-off across independent language runtimes, and the 97-leaf conformance
corpus — exercised byte-identically by the Python and TypeScript reference
verifiers — is what makes that bet checkable rather than merely asserted.

What is given up is real and worth naming: JOSE's mature multi-language
tooling ecosystem (JWK sets, negotiable `alg`/`kid` headers, broad library
support) and COSE's constrained-device profile (compact binary framing with
no canonicalization pass required on a small embedded verifier). attest's
own `kid` and `alg` fields (v0.1 §4.1) borrow JOSE's vocabulary for
readability without adopting JOSE's negotiation model: `alg` is pinned per
`attest_version` and is never used for verifier-side algorithm dispatch — the
opposite of JOSE's negotiable `alg` header, and stated as a MUST NOT in v0.1
§4.1 for exactly that reason.

What a future bridge could look like: a COSE_Sign1 wrapper carrying an
unmodified attest envelope as an opaque payload is a plausible
constrained-device transport profile — it would carry attest inside COSE's
framing for a small-device transport hop without adopting COSE's own
signing-over-the-wire-form model for the receipt itself. Nothing in v0.1 or
v0.2 defines this today.

## 4. RFC 8785 (JCS)

attest builds directly on RFC 8785, not beside it. Taken verbatim from JCS:
object-member ordering by sorting each member name's UTF-16 code-unit
sequence; number serialization via the ECMAScript `Number::toString`
algorithm for any number JCS accepts; RFC 8785's string-escaping rules; and
the underlying I-JSON (RFC 7493) constraint that the input already carry no
duplicate object members and no non-finite numeric values. v0.1 §9 states
this relationship explicitly: every attest-JCS output is also a valid JCS
output, because the profile is a restriction of RFC 8785, never an
incompatible extension to it.

What v0.1 §9 layers on top, and RFC 8785 itself leaves unresolved: full JCS
permits any I-JSON number and requires every implementation's
`Number::toString` to reproduce IEEE-754 double rounding identically to stay
interoperable — a genuine cross-language risk that RFC 8785 does not close
on its own. attest-JCS closes it by restricting numbers to integers only,
with `|n| < 2^53`, rejecting any float, `NaN`/`Infinity`/`-Infinity`
construct, or over-range integer outright at canonicalization time — before
schema validation or signature verification ever run (v0.1 §9's "Correction"
paragraph walks the exact failure path). Layered alongside that restriction:
outright rejection of a duplicate object member name as a parse failure (RFC
8785 requires rejection, never silent last-value-wins deduplication, and
attest-JCS enforces that literally), a parse-tree nesting-depth cap (v0.1
§11.3), and rejection of lone UTF-16 surrogates whether they arrive as
literal bytes or as `\uXXXX` escapes. None of this competes with JCS; each
rule narrows the accepted input set within RFC 8785's own envelope, so any
attest-JCS-canonical document remains a valid RFC 8785 document that a
general-purpose JCS canonicalizer would reproduce unchanged.

## 5. C2PA

A C2PA manifest is a signed, structured record of assertions about an
asset's provenance — actions describing how it was produced or edited,
ingredient assertions chaining in the manifests of source assets it was
derived from, and hash-binding assertions tying the manifest to the exact
asset bytes it describes — embedded in or alongside the asset itself, and
accumulated into a manifest store as the asset passes through further tools.
A C2PA manifest answers what an asset is and how it came to be, and it
travels physically with the asset it describes.

attest answers an adjacent but different question about a different
relationship to the same asset: not what the asset is or how it was made,
but that a license to hold or use a copy of it was granted, by whom, to
whom, and under what terms — a signed side-document (the receipt envelope,
v0.1 §4) that references an artifact by hash (`work.artifact_sha256` and
related fields) rather than embedding anything inside the asset itself. A
receipt says nothing about an artifact's authorship or edit history; a C2PA
manifest says nothing about who is licensed to hold a copy of the asset it
describes.

The two are adjacent and non-overlapping by construction, and were designed
to be checkable from opposite directions against the same object: a game
binary could ship with an embedded C2PA manifest recording its build
provenance, sold to a buyer who separately holds an attest receipt recording
the license grant for that exact binary, both referencing the same
underlying artifact hash. Nothing in either specification requires the
other's presence, and nothing prevents both existing side by side for one
artifact today — that coexistence is not a hypothetical future bridge, it is
how the two already compose without any new mechanism in either
specification.

## 6. SCITT and RFC 9943

The name collision here is the first thing an expert in either protocol
will notice, so it is defused precisely rather than left for someone else to
frame. A SCITT "receipt," per RFC 9943 (the SCITT architecture), is a
transparency service's proof that a signed statement was registered —
cryptographic evidence of *inclusion* in an append-only log, returned to
whoever registered the statement. An attest "receipt" is not that: it is the
signed purchase statement itself, the `payload`-plus-`signatures` envelope a
buyer holds as evidence of a license grant (v0.1 §4). The two protocols use
one word for two different things — a proof of registration, and the thing
being registered.

The structures underneath the naming collision are close to isomorphic, and
mapping them explicitly is the point of this entry:

| SCITT (RFC 9943) | attest |
| --- | --- |
| Statement | Payload (`payload`, v0.1 §5) |
| Signed statement | Signed envelope (`payload` + `signatures`, v0.1 §4) |
| Transparency service | Stage 2 log (`entries.jsonl` / tlog-tiles substrate, v0.2 §7) |
| Receipt | Stage 2 inclusion evidence (`transparency` / `corroboration`, v0.2 §10) |

Why attest is not "already SCITT," despite that structural overlap: SCITT
standardizes the registration and inclusion layer itself — how a
transparency service admits a COSE-signed statement, what a conforming
receipt (in SCITT's sense) must contain, how a relying party verifies one
against a service's key — as a general-purpose substrate for arbitrary
signed statements from arbitrary issuers, with registration as the
trust-establishing act for a statement's discoverability inside that
ecosystem. attest standardizes the purchase-evidence statement's own content
and verification semantics first, and treats its log as strictly
corroborative, never authoritative: v0.2 §10 states as Stage 2's central
correctness property that log evidence never upgrades `trust` and can never
make an unsigned or invalidly-signed receipt authentic — a receipt that
fails signature verification stays failed regardless of what the log says
about it (conformance vector 28i pins exactly this: a receipt rejected for a
compromised signing key still honestly reports `transparency: "logged"` for
its own genuinely-logged evidence). That is a design inversion of SCITT's
registration-centric trust model, not an oversight, and not a claim that
SCITT's model is the wrong one for its own purpose.

Where Stage 2 genuinely does touch SCITT's territory, stated honestly rather
than as a concession: the C2SP tlog-tiles log substrate and inclusion-proof
machinery (v0.2 §7–§9 — an RFC 6962 Merkle tree, leaf hashing, hybrid signed
checkpoints, consistency proofs) solve the same append-only-registration
problem a SCITT transparency service solves. That overlap is real and does
not undermine the boundary drawn above: attest's log substrate is built from
the same class of transparency-log machinery SCITT's architecture
describes, applied to a narrower, purchase-evidence-specific evidence model
with the log kept deliberately out of the trust decision.

This entry closes the corresponding item on the standards-engagement
checklist. Per the standing decision to keep outbound contacts frozen for
this phase, nothing in this entry has been or is being sent to the SCITT
mailing list — it is preparatory material only.

## 7. RATS (RFC 9334): a terminology note

"attest" is this project's name, chosen with no relationship intended to the
IETF Remote Attestation Procedures (RATS) architecture (RFC 9334), and the
protocol defined in `attest-v0.1.md`/`attest-v0.2.md` makes no RATS claims of
any kind: there is no Attester, no RATS-sense Verifier (attest's own
"verifier," v0.1 §3, is simply any software executing the algorithm in v0.1
§11 against a receipt, not a RATS Verifier evaluating Evidence against
Reference Values), and no Relying Party role mapping anywhere in either
specification; no Evidence, Attestation Results, or Endorsement semantics;
and no claim, implicit or explicit, about the integrity or trustworthiness of
any execution environment, TEE, or hardware root of trust. A reader arriving
from a RATS background should treat the project name as a false cognate and
read no remote-attestation semantics into any attest document.

## Revision log

- **2026-07-23 (rev 1)**: initial annex — vectors: none
