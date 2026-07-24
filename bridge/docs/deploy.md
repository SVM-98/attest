# Deploying attest-bridge

Four one-click targets, all built from the same
[`bridge/deploy/Dockerfile`](../deploy/Dockerfile). Pick one; you don't need
more than one. Every target needs the same four things somewhere on the
machine/container it runs on:

- `bridge.toml` and `key-manifest.json` (config + the public key manifest —
  not secret, but private to your deployment; mounted read-only at
  `/etc/attest-bridge/` by the Dockerfile's `ENTRYPOINT`)
- `issuer.seed` and `issuer.mldsa.json` (your signing keys — genuinely
  secret; mounted read-only at `/secrets/`)
- the four env vars your `bridge.toml` references via `*_env`:
  `STRIPE_WEBHOOK_SECRET`, `STRIPE_API_KEY`, `ITCH_API_KEY`, `SMTP_PASSWORD`
  (only set the ones you actually use)
- a writable path for `ledger_path` — the Ledger's sqlite3 file — that
  **survives restarts**. This is the one requirement that's easy to get
  wrong: an ephemeral/scratch disk here doesn't lose already-delivered
  receipts (those are safe with the buyer forever), but it does lose your
  replay-dedup memory, so a redeploy right after a webhook retry could
  double-issue.

**TLS is not optional.** Every target below terminates TLS for you
(Fly/Render/Cloud Run do this automatically; the Docker Compose target needs
a reverse proxy in front of it — Caddy or nginx with a Let's Encrypt cert are
the usual choices). Never expose the bridge directly on plain HTTP: a
webhook body and a downloaded receipt both carry a buyer-binding salt, and
that salt is a secret in transit, not just at rest.

## Docker Compose (self-hosted: a VPS, a home server, ...)

```sh
mkdir -p bridge/deploy/etc bridge/deploy/secrets
cp bridge.toml key-manifest.json bridge/deploy/etc/
cp issuer.seed issuer.mldsa.json bridge/deploy/secrets/
printf 'STRIPE_WEBHOOK_SECRET=whsec_...\n' > bridge/deploy/.env   # + STRIPE_API_KEY / ITCH_API_KEY / SMTP_PASSWORD as needed
docker compose -f bridge/deploy/docker-compose.yml up -d
```

Run from the repo root — see [`docker-compose.yml`](../deploy/docker-compose.yml)
for the exact mounts (two read-only, one named volume for the Ledger). Put a
TLS-terminating reverse proxy in front of port 8080; the bridge itself only
ever speaks plain HTTP on its listening socket.

## Fly.io

```sh
fly apps create attest-bridge
fly volumes create attest_bridge_config --region iad --size 1
fly volumes create attest_bridge_secrets --region iad --size 1
fly volumes create attest_bridge_data --region iad --size 1
fly secrets set STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_API_KEY=sk_... ITCH_API_KEY=... SMTP_PASSWORD=...
fly deploy --config bridge/deploy/fly.toml
```

Run from the repo root (the build context [`fly.toml`](../deploy/fly.toml)
expects). The three volumes start empty — populate them once, after the
first deploy, with `fly ssh sftp shell` (`put bridge.toml
/etc/attest-bridge/bridge.toml`, `put key-manifest.json
/etc/attest-bridge/key-manifest.json`, `put issuer.seed /secrets/issuer.seed`,
`put issuer.mldsa.json /secrets/issuer.mldsa.json`). Fly terminates TLS at
its edge and health-checks `/healthz` automatically (see `fly.toml`).

## Render

Render dashboard → **New +** → **Blueprint** → point at this repo → pick
`bridge/deploy/render.yaml` as the Blueprint file. After the service is
created, go to its **Environment** tab and:

- fill in the four `sync: false` env vars the Blueprint declared
  (`STRIPE_WEBHOOK_SECRET` etc.)
- upload `bridge.toml`, `key-manifest.json`, `issuer.seed`, and
  `issuer.mldsa.json` as **Secret Files** — Render mounts each at
  `/etc/secrets/<filename>` at runtime. [`render.yaml`](../deploy/render.yaml)
  already overrides the container command to read config from
  `/etc/secrets/bridge.toml`, so point that file's `seed_path` /
  `mldsa_key_path` / `manifest_path` at `/etc/secrets/issuer.seed` /
  `/etc/secrets/issuer.mldsa.json` / `/etc/secrets/key-manifest.json`.

Render terminates TLS and health-checks `/healthz` automatically; the
Blueprint also attaches a 1 GB persistent disk at `/var/lib/attest-bridge`
for the Ledger.

## Cloud Run

Cloud Run's "deploy from source" auto-detection only looks for a file
literally named `Dockerfile` at the root of whatever directory you point
`--source` at, so it can't find ours at `bridge/deploy/Dockerfile` with the
repo-root build context it needs. Build and push the image yourself with the
same Dockerfile the other three targets use, then deploy the image:

```sh
docker build -f bridge/deploy/Dockerfile -t <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest .
docker push <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest

gcloud run deploy attest-bridge \
  --image <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest \
  --region <region> \
  --port 8080 \
  --set-secrets="/etc/attest-bridge/bridge.toml=BRIDGE_TOML:latest,/etc/attest-bridge/key-manifest.json=KEY_MANIFEST:latest,/secrets/issuer.seed=ISSUER_SEED:latest,/secrets/issuer.mldsa.json=ISSUER_MLDSA:latest,STRIPE_WEBHOOK_SECRET=STRIPE_WEBHOOK_SECRET:latest,STRIPE_API_KEY=STRIPE_API_KEY:latest,ITCH_API_KEY=ITCH_API_KEY:latest,SMTP_PASSWORD=SMTP_PASSWORD:latest"
```

(create the six named Secret Manager secrets — `BRIDGE_TOML`,
`KEY_MANIFEST`, `ISSUER_SEED`, `ISSUER_MLDSA`, plus the four env-var ones —
with `gcloud secrets create` beforehand; `--set-secrets` mounts a secret as a
*file* when its target starts with `/`, or as an *env var* otherwise, in the
same flag). Cloud Run terminates TLS automatically.

**One real caveat for this specific service, worth reading before you pick
Cloud Run**: Cloud Run's local disk — even its "ephemeral disk" option — does
not survive an instance restart, and its persistent-volume option (Cloud
Storage FUSE) explicitly does not support file locking, which a sqlite3
database (the Ledger) needs to stay correct under concurrent access. So
`ledger_path` on Cloud Run has nowhere durable to live out of the box; you'd
need to point it at a separately-provisioned Filestore (NFS) volume for the
Ledger to actually survive redeploys and instance recycling. If you don't
want to deal with that, Fly.io/Render's built-in persistent disks or a small
VPS via Docker Compose are the simpler choice — Cloud Run is the right pick
if you're already comfortable operating Filestore, or you've accepted that
losing the Ledger only costs you replay-dedup memory and buyers' download
links, never a receipt already in a buyer's hands.
