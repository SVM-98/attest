# openmarket

**The store dies, the receipt survives.**

Open Purchase Receipt (OPR) is a specification and reference implementation for cryptographically-signed purchase receipts that outlive the store that issued them — offline-verifiable, portable proof of a license grant, with no wallet, no RPC endpoint, and no blockchain knowledge required to check.

## Why

Digital "purchases" today are revocable licenses locked inside a single platform. When the platform dies, delists, or changes terms, the library dies with it (Robot Cache bricked already-downloaded games at its April 2026 shutdown; Funimation wiped digital libraries in 2024; Kindle removed book export in February 2025; Sony ends PlayStation disc production for new games in January 2028). Regulation is moving (California AB 2426, Maryland HB 208, the EU end-of-life industry code of conduct due end-2026), but no open technical standard exists for portable, verifiable entitlements. OPR is that standard: a receipt an issuer signs once, a buyer holds forever, and any verifier can check offline against nothing but the receipt bytes, the issuer's public key material, and (optionally) a revocation feed.

## What it is — and is not

- **Is**: a normative specification for a signed receipt envelope, a restricted JSON canonicalization profile, a pinned Ed25519 signing/verification ruleset, issuer key/artifact manifests with rotation and compromise handling, a layered offline verification algorithm, revocation-by-class semantics, and buyer-binding proof — plus a Python reference implementation (`opr`) and a shareable export bundle format (`.oprx`).
- **Is not**: a content host, an index of content, a marketplace, a DRM system, a DRM-stripping tool, a resale/transfer protocol, or a crypto/NFT product. A receipt is evidence of a license grant, not the artifact itself, and it never touches the work it refers to. A federated registry/replication layer and a public whitepaper are deliberately out of scope for v0.1 (see [docs/spec/opr-v0.1.md](docs/spec/opr-v0.1.md) §2).

## Status

OPR v0.1 is complete: a [normative specification](docs/spec/opr-v0.1.md), a companion [JSON Schema](docs/spec/schema/opr-receipt.schema.json), [18 deterministic conformance vectors](docs/spec/vectors/) (format/crypto + lifecycle/policy), a Python reference implementation (the `opr` package: issuance, verification, key/artifact manifests, revocation, buyer binding, `.oprx` export/import, and an `opr` CLI), and an end-to-end demo proving the core thesis against a real filesystem. Foundation research (prior art, legal, tech, market, preservation — with sources) lives in [docs/research/](docs/research/).

## Quickstart

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv -e '.[dev]'
# or: pip install -e .
```

Explore the CLI:

```sh
.venv/bin/opr --help
```

Watch the thesis play out end to end — a store issues a receipt, gets deleted entirely (`shutil.rmtree`, keys and all), and the receipt still verifies from a bundle the buyer held independently:

```sh
.venv/bin/python demo/store_dies.py
```

See [demo/README.md](demo/README.md) for what each step of the demo proves. Core modules measure 90–100% line coverage (≥80% target); check with:

```sh
.venv/bin/pytest --cov=opr --cov-report=term-missing
```

## Spec and conformance

The normative v0.1 specification lives at [docs/spec/opr-v0.1.md](docs/spec/opr-v0.1.md); its companion JSON Schema is at [docs/spec/schema/opr-receipt.schema.json](docs/spec/schema/opr-receipt.schema.json). Conformance vectors live in [docs/spec/vectors/](docs/spec/vectors/) — an implementation is OPR-conformant iff it reproduces the expected `VerificationResult` for every vector there. See [docs/spec/vectors/README.md](docs/spec/vectors/README.md) for the vector index.

## Scope

v1 wedge: DRM-free PC gaming. North star (staged, conditional): music → books → video verticals, and a legally separate, institution-based preservation federation (CDSM art. 6 model) as mandates mature. A federated registry/replication layer, on-chain anchoring, and resale/transfer are explicitly out of scope for v0.1 (docs/spec/opr-v0.1.md §2).

## License

TBD (open source — final license chosen before first public release).
