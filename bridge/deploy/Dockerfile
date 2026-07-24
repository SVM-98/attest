FROM python:3.12
# python:3.12 (not -slim): pqcrypto ships C sources; the full image carries a toolchain
# for platforms without a prebuilt wheel. attest-receipts is the published PyPI package;
# attest-bridge installs from the repo checkout (it is NOT on PyPI — unreleased).
#
# Build context is the REPO ROOT, not this directory — the COPY below needs the whole
# bridge/ tree. From the repo root: `docker build -f bridge/deploy/Dockerfile -t attest-bridge .`
COPY bridge /opt/attest-bridge
RUN pip install --no-cache-dir /opt/attest-bridge
EXPOSE 8080
# /etc/attest-bridge (config + manifest, ro) and /secrets (keys, ro, 0600) are mounts.
ENTRYPOINT ["attest-bridge", "serve", "--config", "/etc/attest-bridge/bridge.toml", "--host", "0.0.0.0", "--port", "8080"]
