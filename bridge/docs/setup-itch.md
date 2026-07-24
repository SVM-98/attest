# itch.io setup: zero to a verified receipt

Read [setup-stripe.md](setup-stripe.md) first if you haven't — steps 1–2
(keypair + key manifest) and 5 (deploy) are identical regardless of platform;
this page only covers what's itch-specific: configuration, and how buyers
actually get their receipt.

## The honest limitation, up front

itch.io has no purchase webhook and no purchase-list/pagination API at all —
this is source-verified against `api.itch.io`'s documented surface
(`credentials/info`, `profile`, `profile/games`,
`games/{id}/purchases?email=|user_id=`, `games/{id}/download_keys`,
`wharf/latest`; nothing else). So issuance here can never be push-driven the
way Stripe's webhook is. Instead, this bridge runs a **claim-queue poller**:
something (a buyer, or your own CSV backfill) enqueues an `(email, game_id)`
claim, and a background poller drains due claims by calling
`GET /games/{game_id}/purchases?email=...` on the real itch API — **that API
response is the sole issuance authority**. A claim by itself never issues
anything; only an itch-API-confirmed purchase does. This also means: itch
receipts are **email-bound only** — itch has no metadata/custom-field
carrier like Stripe's Checkout Session, so there is no way for a buyer to
attach a public key at purchase time (upgrading an itch receipt to a
transferable, pubkey-bound one later is a separate re-issue flow, out of
scope for this bridge).

## 1. Get your itch.io API key

itch.io Dashboard → your account → **API keys** (or directly
`https://itch.io/user/settings/api-keys`) → generate one. This is the key
`attest-bridge` uses to confirm purchases against the live API — it is a
secret; never commit it.

## 2. Configure the bridge

In your `bridge.toml` (see [setup-stripe.md](setup-stripe.md) step 3 for the
rest of the file):

```toml
[itch]
api_key_env = "ITCH_API_KEY"
poll_interval_seconds = 60
max_attempts = 10
```

Set `ITCH_API_KEY` in your deploy environment to the key from step 1
(alongside `STRIPE_WEBHOOK_SECRET` etc. — see [deploy.md](deploy.md)).

Add one `[products.itch_<game_id>]` table per game you sell — the product
key is always `itch_` followed by the itch game id (the numeric id in your
game's itch.io URL/dashboard, not the game's slug):

```toml
[products.itch_123456]
title = "Nebula Drifters"
publisher = "Example Games Store"
artifact_series = "store.example.com/works/nebula-drifters"
terms_uri = "https://store.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
[products.itch_123456.identifiers]
itch_game_id = "123456"
```

`legal_text_sha256` must be exactly 64 lowercase hex characters (the schema
rejects anything else, including a placeholder like `"…"` — every issuance
for a product table with a malformed hash fails before signing, not after).
The all-zeros value above is a format-valid placeholder, matching the
shipped [`bridge/examples/bridge.toml`](../examples/bridge.toml); replace it
with the real SHA-256 of your license terms text:

```sh
shasum -a 256 license.txt | cut -d' ' -f1      # macOS/BSD
sha256sum license.txt | cut -d' ' -f1          # Linux
```

`poll_interval_seconds` is how often the poller checks due claims;
`max_attempts` is how many times a single claim retries (with exponential
backoff) against the itch API before it's marked `exhausted` and needs a
fresh claim to try again — a claim never issues on its own, so a merchant
with a lot of one-off failures is not at risk of double-issuing, only of a
buyer needing to re-submit their claim.

## 3. The two ways a claim gets enqueued

**Buyer self-service.** Point a "Get your signed receipt" link on your
game's page (or in the itch download/thank-you page) at:

```
https://<your-bridge-host>/itch/claim
```

`GET` on that URL serves a plain HTML form (email + a dropdown of your
configured games); submitting it (`POST` to the same URL) enqueues the claim
and returns a token. Give buyers a way to check status — poll
`GET https://<your-bridge-host>/itch/claim/<token>` — it returns
`{"status": "pending"}` while waiting, and once the itch API confirms the
purchase and the poller issues the receipt, `{"status": "confirmed",
"download_url": "https://<your-bridge-host>/r/<download-token>"}`.

**CSV backfill**, for buyers who purchased before you set the bridge up, or
in bulk: export your buyer list from the itch.io dashboard (Analytics/Sales
→ export CSV) and run:

```sh
attest-bridge itch-import --config bridge.toml --game-id 123456 purchases.csv
```

Only the CSV's `email` column is read (any other columns are ignored, and
the header match is case-insensitive) — every unique email in the file gets
one claim enqueued for that game id. Exactly like the buyer-facing form
above, enqueuing here **never issues a receipt by itself**: the poller still
has to confirm each one against the live itch API before anything is
signed. A CSV row for someone who never actually bought the game simply
never resolves (its claim keeps retrying, then exhausts).

## 4. Test it

Once the poller has run (within `poll_interval_seconds` of enqueuing), check
a claim's status via `/itch/claim/<token>` and, once `confirmed`, download
and verify:

```sh
curl "https://<your-bridge-host>/r/<download-token>" -o receipt.attest
chmod 600 receipt.attest   # the envelope carries delivery.salt, a buyer-binding secret
attest verify receipt.attest --trust-dir <dir-containing-key-manifest.json>
```

`"ok": true` closes the loop. See [setup-stripe.md](setup-stripe.md)'s
notice boxes (salt tradeoff, the Ledger database is a secret, Stage 2 is
opt-in) — they apply here identically; itch changes nothing about the
receipt's trust properties, only how a purchase gets confirmed.
