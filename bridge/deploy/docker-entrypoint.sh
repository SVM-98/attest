#!/bin/sh
# attest-bridge container entrypoint.
#
# On targets that mount bridge.toml / key-manifest.json / issuer.seed /
# issuer.mldsa.json directly as files before the container starts (Docker
# Compose's bind mounts, Fly.io's `[[files]]`), the four *_B64 env vars below
# are unset and every block here is a no-op: this script falls straight
# through to the real command, unchanged from a plain
# `ENTRYPOINT ["attest-bridge", "serve", ...]`.
#
# On targets with no way to mount a file at a fixed path before the first
# boot (Render: Secret Files always land at a fixed /etc/secrets/<filename>,
# not the /etc/attest-bridge/... or /secrets/... paths below, and a
# persistent Disk starts empty with no non-shell way to seed it — see
# bridge/docs/deploy.md's Render section), set the matching *_B64 env var
# (base64 of the file's content, `base64 < bridge.toml`) as a regular env var
# instead; this script decodes it to the exact path the `attest-bridge serve`
# invocation below expects, before that command ever runs — so the very
# first deploy comes up healthy, with no shell/SCP step and no crash loop.
set -eu

# Every file materialized below holds secret or trust material. umask 077 makes
# each created file 0600 from its first byte (not dependent on the image umask),
# and materialize() decodes to a temp path then atomically renames into place, so
# a failed/partial `base64 -d` never leaves readable bytes at the real path.
umask 077

# materialize <dest-path> <base64-content>: decode (tolerant of GNU line-wrapped
# base64) to a sibling temp file, then atomic rename. No secret is ever printed.
materialize() {
    dest="$1"
    tmp="$dest.tmp.$$"
    mkdir -p "$(dirname "$dest")"
    printf '%s' "$2" | base64 -d > "$tmp"
    mv "$tmp" "$dest"
}

if [ -n "${BRIDGE_TOML_B64:-}" ]; then
    materialize /etc/attest-bridge/bridge.toml "$BRIDGE_TOML_B64"
fi

if [ -n "${KEY_MANIFEST_B64:-}" ]; then
    materialize /etc/attest-bridge/key-manifest.json "$KEY_MANIFEST_B64"
fi

if [ -n "${ISSUER_SEED_B64:-}" ]; then
    materialize /secrets/issuer.seed "$ISSUER_SEED_B64"
fi

if [ -n "${ISSUER_MLDSA_B64:-}" ]; then
    materialize /secrets/issuer.mldsa.json "$ISSUER_MLDSA_B64"
fi

# Drop the decoded material from the environment before handing off to the
# long-lived server: an inherited *_B64 var would otherwise expose full copies
# of the signing key and config via /proc/<pid>/environ for the service
# lifetime. After this the bridge reads the signing key only from its 0600 file.
unset BRIDGE_TOML_B64 KEY_MANIFEST_B64 ISSUER_SEED_B64 ISSUER_MLDSA_B64

exec attest-bridge serve --config /etc/attest-bridge/bridge.toml --host 0.0.0.0 --port 8080
