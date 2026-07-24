# attest-bridge

attest-bridge is a self-hosted webhook facilitator that turns purchase events
from a payment or storefront platform (Stripe, itch.io, ...) into signed
attest receipts, automatically, at the moment of sale. It runs as a small
service the merchant deploys and operates themselves, alongside their
existing checkout flow — normalizing each platform's webhook payload into a
common purchase shape and handing it to the same `attest` issuance path the
CLI uses, so the resulting receipt is indistinguishable from one minted by
hand.

It is NOT a hosted service attest operates on a merchant's behalf, and it
never holds or transmits a third-party's keys: the merchant's issuer signing
key lives only where the merchant's bridge instance runs, and no buyer key
material ever passes through it beyond the buyer's own public key used to
bind a receipt. It is not a payment processor, a store, or a source of truth
for purchase history — those remain the platform's job; the bridge only
reacts to their events.

Every receipt the bridge issues survives the bridge's own death: it is a
plain attest v0.1/v0.2 envelope, offline-verifiable with nothing but the
issuer's public key manifest, with no dependency on the bridge process, its
database, or its uptime ever again.

## Get started

- [`docs/setup-stripe.md`](docs/setup-stripe.md) — zero to a verified
  receipt selling through Stripe Checkout or Payment Links, including a
  local synthetic-webhook test you can run before touching a real account.
- [`docs/setup-itch.md`](docs/setup-itch.md) — the same, for itch.io (a
  claim-queue poller, not a webhook — itch.io exposes neither).
- [`docs/deploy.md`](docs/deploy.md) — the four deploy targets (Docker
  Compose, Fly.io, Render, Cloud Run), all built from
  [`deploy/Dockerfile`](deploy/Dockerfile), plus the TLS requirement common
  to all of them.
- [`examples/bridge.toml`](examples/bridge.toml) — the annotated config
  template every setup guide above starts from.
