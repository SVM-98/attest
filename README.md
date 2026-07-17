# attest

**The store dies, the receipt survives.**

attest is an open standard and reference implementation for cryptographically-signed
purchase receipts, for *any* digital purchase — games, music, film and TV, books.
The store signs a receipt once; the buyer holds it forever; anyone can verify it
offline. No wallet, no blockchain, no server that has to stay alive for the proof
to still work.

**Try it in your browser:** <https://svm-98.github.io/attest/> — drop a `.attest`
bundle (or the built-in sample) and watch it verify entirely client-side; the
page's CSP forbids it from talking to any other host.

## The problem

A digital "purchase" today is a revocable license living inside one company's
platform, not a thing you hold. When the platform shuts down, delists a title, or
changes terms, the buyer's library goes with it — regardless of medium: Robot Cache
bricked already-downloaded games at its May 2026 shutdown; Funimation wiped
customers' digital anime libraries in 2024; Kindle removed book export in
February 2025; Sony ends PlayStation disc production for new games in
January 2028, pushing more purchases into pure platform dependency. None of this is
hypothetical or gaming-specific — it is what "buy" already means for every kind of
digital media, and regulators are starting to notice: California's AB 2426 and
Maryland's [HB 208](https://mgaleg.maryland.gov/mgawebsite/Legislation/Details/hb0208?ys=2025RS) both require disclosure that a digital "purchase" is a license,
and the EU's end-of-life industry code of conduct is due by the end of 2026. What's
missing is not more disclosure law — it's an open technical standard for a purchase
record the buyer actually holds, independent of whether the seller survives.

## How it works, for humans

At checkout, the store signs a receipt and hands the buyer an `.attest` bundle —
a small file the buyer keeps anywhere: disk, cloud, USB, wherever. There is no
account to keep alive and nothing to sync. Later, anyone with a verifier — a
friend, a marketplace, the buyer themself — can check that bundle's signature
offline against the issuer's published key material and confirm it's a genuine,
unrevoked receipt. If the buyer needs to prove the receipt is specifically
*theirs* (not just a copy that has floated around), they can do so by disclosing
a salt or answering a key challenge, without exposing their identity to the
verifier. Nothing in this loop requires a server: there is no central attest
authority, no registry that must exist, and no phone-home — a verifier needs only
the receipt bytes, the issuer's key material, and, optionally, a revocation feed.

## What it is / is not

attest is a normative specification for a signed receipt envelope, a restricted
JSON canonicalization profile, a pinned Ed25519 signing/verification ruleset,
issuer key/artifact manifests with rotation and compromise handling, a layered
offline verification algorithm, revocation-by-class semantics, and buyer-binding
proof — plus a Python reference implementation and an independent TypeScript
verifier.

It is **not** a DRM-stripping tool, a content host, an index of content, a
marketplace, a resale/transfer protocol (not in v0.1 — see the reserved
`transferable` field), a blockchain or NFT product, or a payment instrument. A
receipt is evidence of a license grant, not the artifact itself and not the
transaction that paid for it.

None of this bypasses an unwilling seller: a receipt is issuer-signed, and attest
cannot conjure a valid one out of a store that refuses to sign. For incumbents who
won't adopt voluntarily, the lever is regulation and market pressure, not forgery.

## Status

Spec v0.1 is complete, with two independent implementations — a Python reference
implementation and a TypeScript verifier — that agree on all 18 conformance
vectors (23 leaf cases spanning format/crypto and lifecycle/policy behavior), plus
an end-to-end demo that deletes a store's entire infrastructure mid-lifecycle and
proves the receipt still verifies.

## Quickstart

Install the reference implementation from PyPI (the distribution is named
`attest-receipts`; the import package and the CLI are both `attest`):

```sh
pip install attest-receipts
attest --help
```

The TypeScript verifier is on npm as
[`attest-verifier`](https://www.npmjs.com/package/attest-verifier):

```sh
npm install attest-verifier
```

Or work from a checkout of this repo:

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv -e '.[dev]'
# or: pip install -e .
```

```sh
.venv/bin/attest --help
```

```sh
.venv/bin/python demo/store_dies.py
```

```sh
.venv/bin/pytest --cov=attest --cov-report=term-missing
```

and a TypeScript verifier quickstart:

```sh
cd verifiers/ts && npm install && npm test
```

See [demo/README.md](demo/README.md) for what each step of the demo proves, and
[docs/spec/attest-v0.1.md](docs/spec/attest-v0.1.md) plus its companion
[JSON Schema](docs/spec/schema/attest-receipt.schema.json) for the normative
specification. [docs/spec/vectors/](docs/spec/vectors/) holds the conformance
corpus every implementation is checked against.

[docs/spec/attest-v0.2.md](docs/spec/attest-v0.2.md) is an additive delta
specification defining the v0.2 hybrid Ed25519+ML-DSA-65 signature profile
(post-quantum-resistant receipts, `attest_version: "0.2"`); v0.1 receipts
remain valid and verifiable forever, and this profile is Stage 1 of a larger
v0.2 — issuer key transparency/anchoring and transfer records are forthcoming
in later stages.

## Roadmap / north star

Non-normative, and deliberately undated — these are directions, not commitments:

- **Evidence capture for non-cooperating stores.** A research track into
  TLS-session-proof techniques (the zkTLS/TLSNotary class) that could let a buyer
  capture their own evidence of a purchase from a store that never signs anything,
  at weaker-than-issuer-signed trust. Legal review is required before any of this
  is built.
- **Rights-holder-authorized transfer.** A future profile that gives real meaning
  to the reserved `license.transferable` field, once rights holders actually
  authorize resale or transfer.
- **Registry / replication layer.** An optional layer for replicating verification
  material, with optional Merkle-root transparency anchoring — the only place a
  chain will ever appear in this project, and even then strictly optional.

## Licensing, contributing, contact

**License.** Code is licensed [Apache-2.0](LICENSE); the specification and other
documentation are licensed [CC BY 4.0](LICENSE-docs) — reuse and derivatives of
the spec must credit the original author, since attribution is a condition of
that license, not a courtesy. [`NOTICE`](NOTICE) and [`AUTHORS`](AUTHORS) carry
the required attribution.

**Naming.** The name *attest* identifies this project and implementations that
actually conform to it; forks are welcome to use the technology but not the name
for a divergent derivative. This paragraph is a naming norm, not a trademark
registration — real trademark enforcement would require actually registering the
mark, which has not happened.

**Contributing.** See [`CONTRIBUTING.md`](CONTRIBUTING.md). Implementation pull
requests must pass all 23 conformance vector leaves and keep both the Python and
TypeScript suites green.

**Contact.** Use GitHub Issues for technical bugs, GitHub Discussions for
everything else, or email `SVM-98@proton.me`.
Security issues follow a different path — see [`SECURITY.md`](SECURITY.md), and
do not open a public issue for a vulnerability.

Skeptical about any of this? [docs/faq.md](docs/faq.md) answers the first
questions a reasonable person asks.
