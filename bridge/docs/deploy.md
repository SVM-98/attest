# Deploying attest-bridge

Four targets, all built from the same
[`bridge/deploy/Dockerfile`](../deploy/Dockerfile). Pick one; you don't need
more than one. Docker Compose, Fly.io, and Render are each a single
command/Blueprint; Cloud Run needs one extra piece (a Filestore volume for
the Ledger) to be a genuinely working target, not just an ephemeral one —
see its section below before picking it. Every target needs the same four
things somewhere on the machine/container it runs on:

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
chmod 600 bridge/deploy/.env
docker compose -f bridge/deploy/docker-compose.yml up -d
```

Run from the repo root — see [`docker-compose.yml`](../deploy/docker-compose.yml)
for the exact mounts (two read-only, one named volume for the Ledger). Put a
TLS-terminating reverse proxy in front of port 8080; the bridge itself only
ever speaks plain HTTP on its listening socket.

## Fly.io

A Fly Machine can mount only **one** volume, so only the Ledger (a real,
growing sqlite3 file) uses one; `bridge.toml`, `key-manifest.json`,
`issuer.seed`, and `issuer.mldsa.json` ride in as base64-encoded secrets
that Fly writes to disk at boot (the `[[files]]` blocks in
[`fly.toml`](../deploy/fly.toml)):

```sh
fly apps create attest-bridge
fly volumes create attest_bridge_data --region iad --size 1
fly secrets set \
  BRIDGE_TOML=$(cat bridge.toml | base64) \
  KEY_MANIFEST=$(cat key-manifest.json | base64) \
  ISSUER_SEED=$(cat issuer.seed | base64) \
  ISSUER_MLDSA=$(cat issuer.mldsa.json | base64) \
  STRIPE_WEBHOOK_SECRET=whsec_... STRIPE_API_KEY=sk_... ITCH_API_KEY=... SMTP_PASSWORD=...
fly deploy --config bridge/deploy/fly.toml
```

Run from the repo root (the build context [`fly.toml`](../deploy/fly.toml)
expects), and set the secrets **before** the first deploy — the files they
back are written at boot, so the Machine needs them to exist as secrets
first. The one volume (`attest_bridge_data`) starts empty and needs no
manual population: it only ever holds the Ledger, which the bridge creates
itself on first run. Fly terminates TLS at its edge and health-checks
`/healthz` automatically (see `fly.toml`).

## Render

Render dashboard → **New +** → **Blueprint** → point at this repo → pick
`bridge/deploy/render.yaml` as the Blueprint file. Render allows only **one**
persistent disk per service, so this Blueprint can't give config and the
Ledger separate mounts the way Fly/Compose do — instead the one disk is
mounted at `/etc/attest-bridge` and holds `bridge.toml`, `key-manifest.json`,
**and** the Ledger's sqlite3 file together. After the service is created
(it will crash-loop at first — expected, see below), go to its
**Environment** tab and:

- fill in the four `sync: false` env vars the Blueprint declared
  (`STRIPE_WEBHOOK_SECRET` etc.)
- upload `issuer.seed` and `issuer.mldsa.json` as **Secret Files** — Render
  mounts each at `/etc/secrets/<filename>` at runtime (fixed path, not
  configurable), so point your `bridge.toml`'s `seed_path` /
  `mldsa_key_path` at `/etc/secrets/issuer.seed` / `/etc/secrets/issuer.mldsa.json`
- set `ledger_path` in your `bridge.toml` to `/etc/attest-bridge/ledger.sqlite3`
  for this target specifically (the shipped example config's default,
  `/var/lib/attest-bridge/...`, has no disk mounted there on Render)
- open a shell to the running service (or use `magic-wormhole`, pre-installed
  on Render's native runtimes) and copy your `bridge.toml` and
  `key-manifest.json` onto the disk, at `/etc/attest-bridge/bridge.toml` and
  `/etc/attest-bridge/key-manifest.json` — the disk starts empty and this is
  the one thing the Blueprint can't do for you

There is deliberately no `dockerCommand` override in `render.yaml`: Render's
`dockerCommand` overrides the Dockerfile's `CMD`, not its `ENTRYPOINT` — with
this image's `ENTRYPOINT` already a complete `attest-bridge serve --config
/etc/attest-bridge/bridge.toml ...` invocation, anything set as
`dockerCommand` would be appended as extra, unrecognized arguments after it
(startup failure), not replace it. `--config` on Render is therefore always
`/etc/attest-bridge/bridge.toml`, unconditionally — hence mounting the disk
at exactly that path above.

Render terminates TLS and health-checks `/healthz` automatically.

## Cloud Run

Read this whole section before you pick Cloud Run — it is not a one-command
deploy for this particular service, and skipping the volume part below
silently loses the Ledger, not just on a caveat-worthy edge case but on
every cold start and every new instance.

Cloud Run's "deploy from source" auto-detection only looks for a file
literally named `Dockerfile` at the root of whatever directory you point
`--source` at, so it can't find ours at `bridge/deploy/Dockerfile` with the
repo-root build context it needs. Build and push the image yourself with the
same Dockerfile the other three targets use, then deploy the image with a
**Filestore (NFS) volume mounted for the Ledger** — without `--add-volume`/
`--add-volume-mount` below, `ledger_path` sits on Cloud Run's ephemeral
container filesystem and is wiped on every cold start or new instance:

```sh
docker build -f bridge/deploy/Dockerfile -t <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest .
docker push <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest

# Prerequisite (separate from this deploy): a Filestore instance in the same
# region/network, e.g. `gcloud filestore instances create attest-bridge-fs
# --zone=<zone> --tier=BASIC_HDD --file-share=name=ledger,capacity=1TB
# --network=name=<vpc>` — see Google Cloud's Filestore quickstart.

gcloud run deploy attest-bridge \
  --image <region>-docker.pkg.dev/<project>/<repo>/attest-bridge:latest \
  --region <region> \
  --port 8080 \
  --execution-environment gen2 \
  --min-instances 1 --max-instances 1 \
  --add-volume name=ledger-vol,type=nfs,location=<FILESTORE_IP>:/ledger \
  --add-volume-mount volume=ledger-vol,mount-path=/mnt/ledger \
  --set-secrets="/etc/attest-bridge/bridge.toml=BRIDGE_TOML:latest,/etc/attest-bridge/key-manifest.json=KEY_MANIFEST:latest,/secrets/issuer.seed=ISSUER_SEED:latest,/secrets/issuer.mldsa.json=ISSUER_MLDSA:latest,STRIPE_WEBHOOK_SECRET=STRIPE_WEBHOOK_SECRET:latest,STRIPE_API_KEY=STRIPE_API_KEY:latest,ITCH_API_KEY=ITCH_API_KEY:latest,SMTP_PASSWORD=SMTP_PASSWORD:latest"
```

Set your `bridge.toml`'s `ledger_path` to `/mnt/ledger/ledger.sqlite3` for
this target. (Create the eight named Secret Manager secrets — `BRIDGE_TOML`,
`KEY_MANIFEST`, `ISSUER_SEED`, `ISSUER_MLDSA`, plus the four env-var ones —
with `gcloud secrets create` beforehand; `--set-secrets` mounts a secret as a
*file* when its target starts with `/`, or as an *env var* otherwise, in the
same flag.) `--execution-environment gen2` is required for NFS volume
support at all. Cloud Run terminates TLS automatically.

**Two real caveats for this specific service, worth reading before you pick
Cloud Run, even with the volume mounted:**

1. NFS on Cloud Run is mounted in **no-lock mode** — Google's own docs state
   Cloud Run does not support NFS file locking. A sqlite3 database (the
   Ledger) normally leans on OS-level file locking to stay correct when more
   than one process touches it; on Cloud Run's NFS mount that protection
   is absent. The `--min-instances 1 --max-instances 1` above is not
   optional decoration — it is what keeps this safe, by guaranteeing there
   is never a second Cloud Run instance holding the same file open at the
   same time (a rolling redeploy still briefly overlaps old and new
   instances, exactly as it would on any other target).
2. Cloud Storage FUSE (Cloud Run's *other* volume option) is not a
   substitute for the NFS mount above: it has weaker POSIX semantics still,
   and Google explicitly does not support file locking there either — don't
   swap `type=nfs` for a GCS bucket mount and expect the same result.

If you don't want to deal with either of those, Fly.io/Render's built-in
persistent disks or a small VPS via Docker Compose are the simpler, safer
fit for this stateful service — they're a real local/network-attached block
device with normal file-locking semantics, not a shared network filesystem.
Cloud Run is the right pick only if you're already comfortable operating
Filestore and running this service pinned to exactly one instance.
