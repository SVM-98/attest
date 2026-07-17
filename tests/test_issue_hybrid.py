"""Tests for hybrid (Ed25519 + ML-DSA-65) receipt issuance (v0.2 profile)."""

from __future__ import annotations

import pytest

from attest import canon, issue, keys, pq
from tests.helpers import make_payload

_KID = "store.example.com/keys/2026-01#hybrid-1"


def _ed_kp() -> keys.SigningKeyPair:
    return keys.from_seed(bytes([7]) * 32)  # TEST ONLY


def _hybrid_kp() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=_ed_kp(), mldsa=pq.generate())


def test_v02_envelope_has_two_ordered_signatures() -> None:
    payload = make_payload(attest_version="0.2")
    hk = _hybrid_kp()
    envelope = issue.issue(payload, hk, _KID)
    sigs = envelope["signatures"]
    assert len(sigs) == 2

    ed_entry, mldsa_entry = sigs
    assert ed_entry == {
        "kid": _KID,
        "alg": "Ed25519",
        "sig": ed_entry["sig"],
    }
    assert mldsa_entry == {
        "kid": _KID,
        "alg": "ML-DSA-65",
        "sig": mldsa_entry["sig"],
    }
    assert ed_entry["kid"] == mldsa_entry["kid"] == _KID

    assert len(keys.b64u_decode(ed_entry["sig"])) == 64
    assert len(keys.b64u_decode(mldsa_entry["sig"])) == pq.ML_DSA_65_SIG_LEN


def test_v02_both_signatures_verify_over_canonical_bytes() -> None:
    payload = make_payload(attest_version="0.2")
    hk = _hybrid_kp()
    envelope = issue.issue(payload, hk, _KID)
    payload_bytes = canon.canonical_bytes(payload)

    ed_entry, mldsa_entry = envelope["signatures"]
    ed_sig = keys.b64u_decode(ed_entry["sig"])
    mldsa_sig = keys.b64u_decode(mldsa_entry["sig"])

    assert keys.verify_strict(payload_bytes, ed_sig, hk.ed.pub)
    assert pq.verify_strict(payload_bytes, mldsa_sig, hk.mldsa.pub)


def test_v02_with_ed_only_key_raises() -> None:
    payload = make_payload(attest_version="0.2")
    with pytest.raises(issue.IssueError) as exc_info:
        issue.issue(payload, _ed_kp(), _KID)
    assert exc_info.value.args[0] == "attest_version 0.2 requires hybrid signing keys"


def test_v01_with_hybrid_key_raises() -> None:
    payload = make_payload(attest_version="0.1")
    with pytest.raises(issue.IssueError) as exc_info:
        issue.issue(payload, _hybrid_kp(), _KID)
    assert exc_info.value.args[0] == "attest_version 0.1 requires an Ed25519-only signing key"


def test_build_payload_rejects_unknown_attest_version() -> None:
    with pytest.raises(issue.IssueError):
        issue.build_payload(
            attest_version="0.3",
            issuer_id="store.example.com",
            display_name="Example Games Store",
            buyer_identifier="user@example.com",
            buyer_identifier_type="email",
            buyer_salt=bytes(range(16)),
            title="Example Game",
            publisher="Example Publisher srl",
            identifiers={"issuer_sku": "EXG-001"},
            artifact_series="store.example.com/works/EXG-001",
            terms_uri="https://store.example.com/attest/license-templates/standard-v1",
            legal_text_sha256="0" * 64,
        )


def test_v01_envelope_unchanged() -> None:
    payload = make_payload(attest_version="0.1")
    kp = _ed_kp()
    envelope = issue.issue(payload, kp, _KID)

    expected_sig = keys.sign(canon.canonical_bytes(payload), kp)
    assert envelope["signatures"] == [
        {
            "kid": _KID,
            "alg": "Ed25519",
            "sig": keys.b64u(expected_sig),
        }
    ]
