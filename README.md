# openmarket

**Your receipt outlives the store.**

An open, neutral, content-free registry standard for cryptographically signed purchase receipts — so that buying digital content produces a portable, offline-verifiable proof of license that survives the death of any storefront, including this project's founders.

## Why

Digital "purchases" today are revocable licenses locked inside single platforms. When the platform dies, delists, or changes terms, the library dies with it (Robot Cache bricked already-downloaded games at its April 2026 shutdown; Funimation wiped digital libraries in 2024; Kindle removed book export in February 2025; Sony ends PlayStation disc production for new games in January 2028). Regulation is moving (California AB 2426, Maryland HB 208, the EU end-of-life industry code of conduct due end-2026), but no open technical standard exists for portable, verifiable entitlements. This project builds that standard.

## What it is — and is not

- **Is**: a specification + reference implementation for signed purchase receipts (Open Purchase Receipt, working name): issued by stores, exportable by users, verifiable offline with no wallet, no RPC, no blockchain knowledge required. Paired with a contractual re-download right for DRM-free artifacts with content hashes and mirror obligations.
- **Is not**: a content host, an index of content, a marketplace, a DRM system, a DRM-stripping tool, or a crypto/NFT product. The registry records licenses; it never touches the works themselves.

## Scope

v1 wedge: DRM-free PC gaming. North star (staged, conditional): music → books → video verticals, and a legally separate, institution-based preservation federation (CDSM art. 6 model) as mandates mature.

## Status

Pre-spec. Foundation research (prior art, legal, tech, market, preservation — with sources) lives in [docs/research/](docs/research/).

## License

TBD (open source — final license chosen before first public release).
