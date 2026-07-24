"""Shared bridge test fixtures: one hybrid issuer, its manifest, a trust store."""

from __future__ import annotations

import pytest

from attest import keys, manifests, pq
from attest import verify as verify_mod

ISSUER = "merchant.example.com"
KID = f"{ISSUER}/keys/2026-07#hybrid-1"
DISPLAY_NAME = "Example Games Store"
VALID_FROM = "2026-07-01T00:00:00Z"


@pytest.fixture(scope="session")
def hybrid_keys() -> pq.HybridSigningKeys:
    # Deterministic Ed25519 leg (TEST ONLY); ML-DSA generated once per session (cost).
    return pq.HybridSigningKeys(ed=keys.from_seed(bytes([9]) * 32), mldsa=pq.generate())


@pytest.fixture(scope="session")
def key_manifest(hybrid_keys: pq.HybridSigningKeys) -> dict[str, object]:
    entry = manifests.key_entry(
        KID, hybrid_keys.ed.pub, VALID_FROM, pub_ml_dsa_65=hybrid_keys.mldsa.pub
    )
    return manifests.build_key_manifest(ISSUER, 1, VALID_FROM, [entry], hybrid_keys, KID)


@pytest.fixture(scope="session")
def trust_store(key_manifest: dict[str, object]) -> verify_mod.TrustStore:
    return verify_mod.TrustStore(manifests={ISSUER: key_manifest}, provenance={ISSUER: "tls"})
