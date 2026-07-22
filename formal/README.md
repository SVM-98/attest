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

The exact command the gate runs (CI and locally):

```sh
python tools/check_formal.py formal/attest.spthy
```

This invokes `tamarin-prover --prove formal/attest.spthy`, parses the
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

### Injected summaries

`--summary-file` is a test/injection mode: the checker reads that summary
instead of launching Tamarin. `--theory-file` is legal only with
`--summary-file`, so an injected result always has an explicitly paired theory
source for the digest and census checks. In real-prover mode, the positional
theory path is used for both the proof run and the digest/census checks.

## Updating the contract

The statements are pinned as they are on this branch. After an INTENDED
statement change, regenerate the digests with the one-liner in the
`CONTRACT` comment block of `tools/check_formal.py` and update the pinned
entries in the same change that touches the theory — the gate makes silent
drift impossible, not evolution.
