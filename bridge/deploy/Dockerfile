FROM python:3.12
# python:3.12 (not -slim): pqcrypto ships C sources; the full image carries a toolchain
# for platforms without a prebuilt wheel. attest-receipts is the published PyPI package;
# attest-bridge installs from the repo checkout (it is NOT on PyPI — unreleased).
#
# Build context is the REPO ROOT, not this directory — the COPY below needs the whole
# bridge/ tree. From the repo root: `docker build -f bridge/deploy/Dockerfile -t attest-bridge .`
COPY bridge /opt/attest-bridge
RUN pip install --no-cache-dir /opt/attest-bridge && chmod +x /opt/attest-bridge/deploy/docker-entrypoint.sh
EXPOSE 8080
# /etc/attest-bridge (config + manifest) and /secrets (keys, 0600) are read-only mounts
# on Docker Compose/Fly.io. docker-entrypoint.sh additionally knows how to materialize
# both from base64 env vars, for targets (Render) with no way to mount a file at a
# fixed path before the first boot — see bridge/docs/deploy.md. Either way, the final
# command it execs is exactly `attest-bridge serve --config /etc/attest-bridge/bridge.toml
# --host 0.0.0.0 --port 8080`.
ENTRYPOINT ["/opt/attest-bridge/deploy/docker-entrypoint.sh"]
