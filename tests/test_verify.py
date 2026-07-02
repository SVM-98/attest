"""Tests for opr.verify — layered verification core, §6 steps 0-5.

Security-critical: this module decides whether a receipt's signature is
valid, from which issuer, and whether it is schema-conformant. Tests build
real envelopes via `issue.issue()` for the happy paths, and hand-craft raw
bytes / manually-signed envelopes for the attack scenarios that `issue()`
itself would refuse to produce (e.g. a kid/issuer domain mismatch) — those
are exactly the inputs `verify()` must defend against regardless of how a
non-conforming envelope came to exist.
"""

from __future__ import annotations

import json
from typing import Any

from opr import canon, issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
EVIL_ISSUER = "evil.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
EVIL_KID = f"{EVIL_ISSUER}/keys/test#ed25519-1"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([9]) * 32)
EVIL_KP = keys.from_seed(bytes([10]) * 32)


def _key_manifest(
    issuer: str = ISSUER,
    kid: str = KID,
    kp: keys.SigningKeyPair = KP,
    status: str = "active",
    valid_from: str = "2026-01-01T00:00:00Z",
    valid_to: str | None = None,
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, valid_from, valid_to, status)]
    return manifests.build_key_manifest(issuer, 1, "2026-01-01T00:00:00Z", entries, kp, kid)


def _trust_store(
    manifest: dict[str, Any], issuer: str = ISSUER, provenance: str = "tls"
) -> verify.TrustStore:
    return verify.TrustStore(manifests={issuer: manifest}, provenance={issuer: provenance})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    """Simulate bytes received over the wire — need not be canonical, only valid JSON."""
    return json.dumps(envelope).encode("utf-8")


# --- happy path --------------------------------------------------------------


def test_valid_envelope_is_ok_with_verified_trust() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"
    assert result.trust == "verified"
    assert result.errors == ()
    assert result.ok is True


def test_bundle_provenance_yields_unauthenticated_tofu_trust() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    trust_store = _trust_store(_key_manifest(), provenance="bundle")
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.ok is True
    assert result.trust == "unauthenticated_tofu"


# --- step 0: preconditions (parse once, strictly) -----------------------------


def test_duplicate_key_in_raw_bytes_is_rejected() -> None:
    raw = b'{"payload":{"a":1},"payload":{"a":2},"signatures":[]}'
    result = verify.verify(raw, _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("duplicate object key" in e for e in result.errors)


def test_non_object_envelope_is_rejected() -> None:
    result = verify.verify(b"[]", _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_invalid_json_is_rejected() -> None:
    result = verify.verify(b"not json at all", _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


# --- tampering -----------------------------------------------------------------


def test_tampered_payload_byte_invalidates_signature() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    raw = bytearray(json.dumps(envelope).encode("utf-8"))
    idx = raw.index(b"Example Game")
    raw[idx] = ord("X")  # flip one byte inside a signed string value
    result = verify.verify(bytes(raw), _trust_store(_key_manifest()))
    assert result.signature == "invalid"


# --- step 1: envelope well-formed, signatures length, alg ---------------------


def test_zero_signatures_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"] = []
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_two_signatures_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"] = envelope["signatures"] * 2
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_unsupported_alg_is_rejected_never_selected() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"][0]["alg"] = "RS256"
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("RS256" in e for e in result.errors)


def test_missing_payload_key_is_invalid() -> None:
    result = verify.verify(_to_bytes({"signatures": []}), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


# --- step 2: issuer binding -----------------------------------------------------


def test_issuer_mismatch_signed_by_evil_domain_key() -> None:
    """Design vector 5: a valid manifest for evil.example.com must never validate
    a receipt claiming issuer.id "store.example.com"."""
    trust_store = verify.TrustStore(
        manifests={
            ISSUER: _key_manifest(),
            EVIL_ISSUER: _key_manifest(EVIL_ISSUER, EVIL_KID, EVIL_KP),
        },
        provenance={ISSUER: "tls", EVIL_ISSUER: "tls"},
    )
    payload = make_payload()  # issuer.id == store.example.com
    sig = keys.sign(canon.canonical_bytes(payload), EVIL_KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": EVIL_KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.signature == "invalid"
    assert any("issuer_mismatch" in e for e in result.errors)


def test_unknown_issuer_no_manifest_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    empty_store = verify.TrustStore(manifests={}, provenance={})
    result = verify.verify(_to_bytes(envelope), empty_store)
    assert result.signature == "invalid"
    assert result.errors


# --- step 3: key checks (compromise, retirement, validity window) --------------


def test_compromised_key_is_invalid_regardless_of_issued_at() -> None:
    manifest = _key_manifest(status="compromised", valid_from="2020-01-01T00:00:00Z")
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at well inside the window
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_retired_key_within_validity_is_valid_with_warning() -> None:
    manifest = _key_manifest(
        status="retired", valid_from="2026-01-01T00:00:00Z", valid_to="2026-12-31T00:00:00Z"
    )
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02, inside window
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.ok is True
    assert any("retired" in w for w in result.warnings)


def test_issued_at_outside_validity_window_is_invalid() -> None:
    manifest = _key_manifest(valid_from="2026-01-01T00:00:00Z", valid_to="2026-02-01T00:00:00Z")
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02, after valid_to
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


# --- step 5: schema validation + warnings ---------------------------------------


def test_unknown_top_level_field_is_valid_with_warning() -> None:
    payload = make_payload()
    payload["extension_field"] = "some-value"
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("extension_field" in w for w in result.warnings)


def test_drm_bound_receipt_emits_warning() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14, "drm": "drm-bound"}
    )
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("drm-bound" in w for w in result.warnings)


def test_unknown_end_of_life_value_emits_warning() -> None:
    payload = make_payload(survivability={"end_of_life": "some-future-vocabulary"})
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("end_of_life" in w for w in result.warnings)
