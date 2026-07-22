# Formal verification (Tamarin)

`attest.spthy` is the Tamarin model of the attest v0.1/v0.2 trust, rotation,
revocation and hybrid (Ed25519+ML-DSA) acceptance protocol. Its lemma corpus
is gated by `tools/check_formal.py`, which pins every lemma *statement* by
sha256 digest of its normalized text — a renamed, weakened, trait-flipped or
annotation-edited lemma fails the gate even when the prover says `verified` —
and pins the prover itself, fail-closed.

## Pinned toolchain

Reproducing (or gating) the proofs requires EXACTLY:

| tool | version |
|---|---|
| `tamarin-prover` | **1.12.0** |
| `maude` | **3.5.1** |

The authoritative constants are `TAMARIN_VERSION` / `MAUDE_VERSION` in
`tools/check_formal.py`. On every valid gate invocation, including an injected
`--summary-file` run, the checker asserts both `tamarin-prover --version` and
`maude --version`. Any mismatch, missing binary, non-zero exit, timeout, or
unparseable output exits 1 (never a skip). `--prover` and `--maude` can inject
binary paths for tests. Usage errors (exit 2) are validated first.

Check what you have with:

```sh
tamarin-prover --version
maude --version
```

## Running the gate

CI runs the four sharded invocations in [Shards (`--only`)](#shards---only)
below. For a local one-shot reproduction of the full corpus:

```sh
python tools/check_formal.py formal/attest.spthy
```

This invokes `tamarin-prover --prove --derivcheck-timeout=60 formal/attest.spthy`
(the default 5s derivation-check timeout expires on this theory and would turn
into a wellformedness warning, which the gate treats as failure), parses the
`summary of summaries` block, and asserts for every pinned lemma: present,
result `verified`, trait (`all-traces`/`exists-trace`) matching, and statement
digest matching the contract. The theory's complete declared-lemma set must
equal the contract set on every run; any extra or missing declaration fails,
even when a shard summary does not mention it. Any lemma in the summary that
is not in the contract is also a failure (drift). Prover crash, timeout, or an
empty/garbled summary is a failure. Exit 0 only if everything holds.

### Shards (`--only`)

Two lemmas are scheduled long-runners and get their own CI shards. A shard
run restricts the *result* assertions to its lemmas:

```sh
python tools/check_formal.py --only no_downgrade_revocation_allhybrid formal/attest.spthy
```

`--only name1,name2,...` proves only the named lemmas
(`--prove=<name>` per lemma) and asserts `verified` only for them, but the
statement-digest check ALWAYS runs over the FULL contract against the theory
source — statements stay pinned globally even when results are verified
shard-by-shard. A shard relaxes only which contract lemmas must be present: if
its parsed summary reports any contract lemma as `falsified` or `analysis
incomplete`, that run still fails. An unknown name or an empty scope such as
`--only ','` or `--only ''` is a usage error (exit 2). `--timeout <seconds>`
bounds the prover subprocess.

CI runs the corpus as a four-shard matrix (the `formal` job in
`.github/workflows/ci.yml`): the two scheduled long-runners each get a
dedicated shard, the revocation chain is a third, and every remaining
contract lemma is the fourth. The shard lists live in the workflow and are
pinned against drift by tests in `tests/tools/test_check_formal.py` that
parse the workflow and assert the four `--only` lists are pairwise disjoint
with union exactly equal to the checker contract — a lemma added to the
contract without a shard assignment turns CI red in pytest before any prover
minute is spent.

### Injected summaries

`--summary-file` is a test/injection mode: the checker reads that summary
instead of launching Tamarin. `--theory-file` is legal only with
`--summary-file`, so an injected result always has an explicitly paired theory
source for the digest and census checks. In real-prover mode, the positional
theory path is used for both the proof run and the digest/census checks.

## Property ↔ lemma ↔ spec map

The four roadmap properties, as proved (their exact scope is in the next
section — the scoping is part of the claim, not a footnote):

- **P1 — issuer-signed acceptance**: an accepted receipt under verified trust
  was really issued, or a key of that issuer had been revealed first — the
  reveal branch is real, not theoretical: `attack_v01_post_crqc` exhibits a
  verified/clean acceptance with no issuance after `EdBroken`.
- **P2 — rotation continuity**: no unflagged authority hijack.
- **P3 — revocation soundness and effectiveness**: only authentic revocations
  are honored, and honored means honored.
- **P4 — hybrid downgrade resistance**: breaking Ed25519 alone does not forge
  what the hybrid profile protects.

Security theorems (all-traces):

| Lemma | Property | Statement (informal) | Spec anchor |
| --- | --- | --- | --- |
| `acceptance_issuer_signed` | P1 | `Ok` under verified/clean trust ⇒ prior honest issuance, or a prior `RevealKey` of ANY key named by that issuer — the formula does not tie the revealed key to the verifier's trusted manifest. The reveal branch is exhibited by `attack_v01_post_crqc` | v0.1 §10, §11; TM-01/TM-02 |
| `no_cross_version_confusion` | P1, P4 | any v0.2-dispatch acceptance traces to a version-exact `"0.2"` issuance; a v0.1-signed payload is never accepted via the hybrid rule. Covers the receipt-downgrade case causally, under weaker hypotheses than a dedicated reveal-conditioned theorem would need (see the in-theory comment) | v0.2 §1, §2.2 |
| `rotation_no_hijack` | P2 | any change of the verifier's authority set was signed by a key `active` in the previously-trusted manifest, or is flagged `UnverifiedRotation` | v0.1 §7.3, §11.1; TM-28 |
| `old_key_powerless` | P2 | revealing a key that is not `active` in the currently-trusted manifest never enables an unflagged authority change | v0.1 §7.3 |
| `compromised_key_rejected` | P3 | no `Ok` via key `k` after the verifier trusts a manifest marking `k` compromised | v0.1 §7.3, §11 step 3 |
| `rev_record_authentic` `[reuse]` | P3 | an admitted revocation record under verified/clean trust was honestly issued, or an issuer key was revealed first (the TOFU boundary of this claim is exhibited by `attack_tofu_revocation_forgery`) | v0.1 §12.1 |
| `revocation_auth_soundness` | P3 | under verified/clean trust, `RevocationHonored` ⇒ an `active` key, class and window witnesses, and prior admission of that exact record; moreover it was previously issued by the issuer **or** an issuer key was previously revealed | v0.1 §12.1–12.2 |
| `revocation_effectiveness` | P3 | **The name overstates the result.** Starting from `RevocationIgnored`, it proves ignore-reason integrity: `class_none` has an independent `RevClass(..., 'none')` witness, or `out_of_window` has an independent matching `OutWindowMark` and no matching `InWindowActive`. It does not force honoring: an admitted record then neither honored nor ignored satisfies it vacuously. | v0.1 §12.2 |
| `irrevocability_none` | P3 | a `revocability: "none"` receipt is never `RevocationHonored` — any record, any signer | v0.1 §6.2, §12.2 |
| `refund_window_bound` | P3 | no `RevocationHonored` on an out-of-window record | v0.1 §12.2 |
| `revoked_view_never_ok` | P3 | per invocation, `Ok` and consulting an honored revocation for the same receipt cannot co-occur. The revocation view is per-invocation, so a later verification with a different view may accept. | v0.1 §12.2 |
| `no_downgrade_artifact_manifest` | P4 | an accepted hybrid-signer artifact manifest was honestly issued — unconditional, no Ed-intact assumption | v0.2 §13 |
| `no_downgrade_revocation_allhybrid` | P4 | at the hybrid-record ADMISSION boundary, any published `active` hybrid entry (no trusted-head premise and no every-active-key-hybrid guard) admits only a record with a prior exact honest hybrid issuance — exact issuer/key/record binding. It does not cover the G6 rotation-authority gap. | v0.2 §13 |

Helper cuts (`[reuse]`, proved and pinned like every other lemma), each a
DISJUNCTION, not an absolute: `verified_clean_head_honest` (a verified/clean
trust head is honestly produced OR an issuer key was revealed first — the
attacker-manifest-after-reveal branch is in the formula; the cut discharges
that branch once instead of per induction step) and the three message-origin
cuts `pq_receipt_sig_source`, `am_pq_sig_source`, `rev_pq_sig_source` (a
`verify_pq`-true leg for receipts / artifact manifests / revocation records
originates from honest hybrid issuance OR from an adversary who knows the PQ
secret `skPQ` — the downstream theorems are what close that second branch,
via `!PqKeyMat` secrecy; v0.2 §2.2, §13).

Attack exhibits (exists-trace; `verified` means the attack trace was FOUND —
these are first-class deliverables, not regressions):

| Lemma | Exhibits | Status of the hole |
| --- | --- | --- |
| `attack_tofu_forgery` | TOFU-path acceptance of a never-issued receipt | Known, by design — TM-11 ("signalled rather than prevented") |
| `attack_v01_post_crqc` | fresh `"0.1"`-profile receipt forged post-CRQC against an issuer's Ed key | Known — TM-03 (Ed-only stock) |
| `attack_tofu_revocation_forgery` | forged revocation record admitted under TOFU-adopted trust | the stated TOFU boundary of `rev_record_authentic` |
| `attack_mixed_keyset_hijack` | the G6 mixed-keyset gap: Ed-only `active` sibling key + `EdBroken` ⇒ unflagged authority hijack of a hybrid-protected issuer | **NEW protocol gap**, spec-verified; normative fix deferred to P1.4 |

The witness corpus has distinct roles. `sanity_attacker_distinct_mid` and
`sanity_same_version_conflict` are attacker-manifest sanity lemmas, not
honest-path witnesses. `reach_refund_window_honored` and
`reach_revocation_out_of_window` are verified-trust operational witnesses,
not attacker-action witnesses. The remaining `sanity_*` and `reach_*` lemmas
provide their individually scoped executability, anti-vacuity, or adversarial
reachability evidence. Restrictions in the theory are confined to local
well-formedness — every acceptance/authorization check is a rule premise, so
bad traces exist and theorems must defeat them, not define them away.

## Abstraction register

What the model deliberately does not represent, and why that is sound to
claim on:

| Abstraction | Justification |
| --- | --- |
| Symbolic terms, not JCS bytes | byte-level canonicalization drift is pinned by the cross-language conformance corpus (TM-20 territory); a symbolic model cannot see bytes |
| No numeric time; abstract window/class predicates where authorization depends on them | `issued_at` is attacker-controlled input, so time-freeness costs nothing there; `refund_window` *authorizes*, so the model carries an abstract in/out-of-window fact per record, nondeterministically chosen — both branches are exercised without wall-clock arithmetic |
| Ideal signatures; CRQC = Ed key reveal | standard symbolic treatment; the pinned byte-level signing ruleset is implementation-level (conformance vectors) |
| TOFU modeled, NOT proven safe | TOFU acceptance of a forgery is a real trace, exhibited by `attack_tofu_forgery` — see scoping item 1 |
| Buyer commitment/binding absent | not among the four properties; future work (non-transferability) |
| Transparency/anchoring absent | corroboration never upgrades trust (v0.2 §7.1, §15.4); equivocation/witness properties belong with P1.1b |
| Manifest freshness not modeled | `compromised_key_rejected` holds once the verifier trusts the marking manifest; stale-manifest exposure (TM-29/TM-32) is a distribution problem the model does not close — see scoping item 2 |
| Post-admission hybrid revocation dispatch absent | hybrid revocation is proved at the admission (authentication) boundary; honor/ignore/reject dispatch of admitted hybrid records is carried by the implementation — see scoping item 4 |

## What is NOT proved (honest scoping)

The theorems above are exactly as strong as their hypotheses. Bluntly:

1. **P1 holds only under `trust: "verified"`.** On the TOFU path there is no
   authenticity claim to make: a verifier that adopts whatever manifest it is
   handed accepts a never-issued receipt, and that is a real forgery — TM-11
   calls it signalled rather than prevented — machine-exhibited by
   `attack_tofu_forgery`. The same boundary applies to revocation
   authentication (`attack_tofu_revocation_forgery`).
2. **`compromised_key_rejected` bounds auto-acceptance once the verifier
   trusts the manifest that marks the key compromised — it says nothing about
   stale-manifest rollback.** A verifier still holding the older manifest has
   no marking to act on (TM-29/TM-32); manifest freshness/distribution is
   outside the model.
3. **The mixed-keyset gap (G6) is real and unfixed here.** A hybrid-protected
   issuer with an Ed-only `active` sibling key is hijackable by an Ed-only
   attacker — `attack_mixed_keyset_hijack` is the machine-checked
   counterexample. It is a rotation-authority gap and is not covered by the
   hybrid revocation admission theorem. That theorem is unconditional at its
   admission boundary: any published `active` hybrid entry may admit a record,
   with no trusted-head premise and no every-active-key-hybrid guard. The
   normative G6 fix (forbidding Ed-only `active` siblings under claimed hybrid
   protection + a migration ceremony) is deferred to P1.4.
4. **Hybrid revocation is proved at the ADMISSION boundary; post-admission
   hybrid dispatch is out of the model's scope.**
   `no_downgrade_revocation_allhybrid` says forged hybrid records do not get
   past authentication — and since every honor path consumes an admitted
   record, forgery stopped at admission is stopped downstream. It does NOT
   say the model drives `revocation: "revoked"` from a hybrid record: the
   security half (unforgeability at the boundary) is proved; the behavioural
   half (dispatch of admitted hybrid records) is carried by the
   implementation. The in-theory comments at the hybrid admission rule and
   `no_downgrade_revocation_allhybrid` state this scope; do not read the
   theorem as more.
5. **One witness was withdrawn as intractable.** The T4-era ok-linkage
   witness `reach_revoked_then_rejected` (an honored revocation later routed
   to the explicit reject path) is no longer in the corpus: its backward
   search became structurally intractable once the second (hybrid) issuance
   rule existed, and the search does not fit in 16 GB of RAM at any time
   budget — reproducing it is a 32–64 GB-machine exercise. The full formula,
   the measured evidence, and the replacement argument
   (`sanity_issued_receipt_revoked` as an exact state witness + a manual
   append-one-enabled-step argument, which is strictly weaker as a
   regression detector) are preserved verbatim in the `WITHDRAWN IN TASK 5`
   comment block inside `formal/attest.spthy`.

The gate's own limit, restated: `tools/check_formal.py` detects statement
drift and prover failure; model *fidelity* rests on the Group-B reachability
lemmas, the restriction discipline above, and review.

## Reproducing

One command, from the repo root, with the pinned toolchain installed:

```sh
python tools/check_formal.py formal/attest.spthy
```

For the raw prover run without the gate's pinning:

```sh
tamarin-prover --prove --derivcheck-timeout=60 formal/attest.spthy
```

Expect a long run: two lemmas are scheduled long-runners (the CI shard split
above exists for exactly that reason).

## Future work

Equivalence-based privacy properties (observational equivalence is
ProVerif/DeepSec territory, not trace properties); witness/equivocation
properties for transparency anchoring, together with P1.1b; the G6 normative
fix in P1.4.

## Updating the contract

The statements are pinned as they are on this branch. After an INTENDED
statement change, regenerate the digests with the one-liner in the
`CONTRACT` comment block of `tools/check_formal.py` and update the pinned
entries in the same change that touches the theory — the gate makes silent
drift impossible, not evolution.
