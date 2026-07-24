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

if [ -n "${BRIDGE_TOML_B64:-}" ]; then
    mkdir -p /etc/attest-bridge
    printf '%s' "$BRIDGE_TOML_B64" | base64 -d > /etc/attest-bridge/bridge.toml
    chmod 600 /etc/attest-bridge/bridge.toml
fi

if [ -n "${KEY_MANIFEST_B64:-}" ]; then
    mkdir -p /etc/attest-bridge
    printf '%s' "$KEY_MANIFEST_B64" | base64 -d > /etc/attest-bridge/key-manifest.json
    chmod 600 /etc/attest-bridge/key-manifest.json
fi

if [ -n "${ISSUER_SEED_B64:-}" ]; then
    mkdir -p /secrets
    printf '%s' "$ISSUER_SEED_B64" | base64 -d > /secrets/issuer.seed
    chmod 600 /secrets/issuer.seed
fi

if [ -n "${ISSUER_MLDSA_B64:-}" ]; then
    mkdir -p /secrets
    printf '%s' "$ISSUER_MLDSA_B64" | base64 -d > /secrets/issuer.mldsa.json
    chmod 600 /secrets/issuer.mldsa.json
fi

exec attest-bridge serve --config /etc/attest-bridge/bridge.toml --host 0.0.0.0 --port 8080
