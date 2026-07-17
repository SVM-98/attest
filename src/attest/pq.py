"""ML-DSA-65 (FIPS 204) primitives for the v0.2 hybrid signature profile.

Runtime backend is pqcrypto (PQClean C). The pure-Python dilithium-py package is
a DEV-ONLY test oracle (deterministic vector generation) and must never be
imported from runtime code.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.sign.ml_dsa_65 import generate_keypair as _pq_generate
from pqcrypto.sign.ml_dsa_65 import sign as _pq_sign
from pqcrypto.sign.ml_dsa_65 import verify as _pq_verify

from attest import keys

ML_DSA_65_ALG = "ML-DSA-65"
ML_DSA_65_PK_LEN = 1952
ML_DSA_65_SK_LEN = 4032
ML_DSA_65_SIG_LEN = 3309


@dataclass(frozen=True)
class MLDSAKeyPair:
    """ML-DSA-65 keypair; sk is secret material (0600 handling at the CLI layer)."""

    sk: bytes
    pub: bytes


@dataclass(frozen=True)
class HybridSigningKeys:
    """Composite v0.2 signing material: one Ed25519 leg, one ML-DSA-65 leg."""

    ed: keys.SigningKeyPair
    mldsa: MLDSAKeyPair


def generate() -> MLDSAKeyPair:
    pub, sk = _pq_generate()
    return MLDSAKeyPair(sk=sk, pub=pub)


def sign(payload_bytes: bytes, kp: MLDSAKeyPair) -> bytes:
    return bytes(_pq_sign(kp.sk, payload_bytes))


def verify_strict(payload_bytes: bytes, sig: bytes, pub: bytes) -> bool:
    """Length-checked, exception-free verification (fail-closed)."""
    if len(sig) != ML_DSA_65_SIG_LEN or len(pub) != ML_DSA_65_PK_LEN:
        return False
    try:
        return bool(_pq_verify(pub, payload_bytes, sig))
    except Exception:  # pqcrypto raises on invalid input; any failure = reject
        return False
