"""Tests for attest.verify — layered verification core, §6 steps 0-5.

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

import pytest

from attest import canon, commitment, issue, keys, manifests, revocation, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
EVIL_ISSUER = "evil.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
EVIL_KID = f"{EVIL_ISSUER}/keys/test#ed25519-1"
COMPROMISED_KID = f"{ISSUER}/keys/test#ed25519-compromised"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([9]) * 32)
EVIL_KP = keys.from_seed(bytes([10]) * 32)
COMPROMISED_KP = keys.from_seed(bytes([15]) * 32)


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


def _manifest_active_plus_compromised() -> dict[str, Any]:
    """Manifest self-signed by the active KID, plus a listed-but-compromised key."""
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(
            COMPROMISED_KID, COMPROMISED_KP.pub, "2026-01-01T00:00:00Z", None, "compromised"
        ),
    ]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


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


def test_missing_signatures_member_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    del envelope["signatures"]
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("signatures" in e for e in result.errors)


def test_unsupported_attest_version_is_invalid() -> None:
    """`attest_version` is gated by verify() itself (step 1), independent of and
    before the jsonschema `const` check in step 5 — hand-sign to bypass
    issue()'s own schema gate and exercise verify()'s own check directly.

    "0.3" (not "0.2" — 0.2 is a supported hybrid version as of this receipt
    format) stands in for an attest_version verify() does not recognize.
    """
    payload = make_payload()
    payload["attest_version"] = "0.3"
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("attest_version" in e for e in result.errors)


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


def test_missing_issuer_id_is_invalid() -> None:
    """`issuer.id` is read directly off the payload before any manifest lookup —
    a payload lacking it must fail closed even though a trusted manifest for
    the "real" issuer exists in the store."""
    payload = make_payload()
    payload["issuer"] = {"display_name": "Example Games Store"}  # no "id"
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("issuer.id" in e for e in result.errors)


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


def test_issued_at_before_valid_from_is_invalid() -> None:
    """The other edge of the validity window: a receipt claiming to have been
    issued before its own signing key's `valid_from` must be rejected too,
    not just the after-`valid_to` case above."""
    manifest = _key_manifest(valid_from="2027-01-01T00:00:00Z")  # after payload's issued_at
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_manifest_entry_missing_valid_from_fails_closed() -> None:
    """A corrupted/hand-edited trust-store manifest entry (missing `valid_from`
    entirely) must never resurrect a receipt into validity — `_within_validity`
    fails closed on the KeyError rather than raising or defaulting to valid."""
    entry = {"kid": KID, "pub": keys.b64u(KP.pub), "valid_to": None, "status": "active"}
    manifest = {"issuer": ISSUER, "keys": [entry]}
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_manifest_entry_missing_pub_fails_closed_with_malformed_key_material() -> None:
    """A trust-store manifest entry missing `pub` must fail closed with a clear
    "malformed key material" error, never crash with an unhandled KeyError."""
    entry = {"kid": KID, "valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "status": "active"}
    manifest = {"issuer": ISSUER, "keys": [entry]}
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"
    assert any("malformed key material" in e for e in result.errors)


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


# --- step 6: revocation-by-class (design §3.1/§6) --------------------------------
#
# revocability=="none" -> a matching, signature-valid record is itself invalid
# (irrevocability guarantee; design vector 16). revocability=="policy" -> a
# matching valid record is always honored (design vector 15). revocability==
# "refund_window" -> a matching valid record is honored only if the record's
# OWN signed revoked_at falls within issued_at + revocation_window_days.


def test_revocation_policy_valid_record_is_revoked() -> None:
    """Design vector 15: revocability:policy + a valid revocation record -> revoked."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "revoked"
    assert result.ok is False


def test_revocation_against_none_class_is_ignored() -> None:
    """Design vector 16: this is the whole irrevocability argument — a valid
    record against a revocability:none receipt is invalid, and the receipt
    stays ok."""
    payload = make_payload()  # revocability: none (base payload default)
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert any("revocability" in w and "none" in w for w in result.warnings)


def test_revocability_none_with_non_matching_record_reports_not_revoked_as_of() -> None:
    """An irrevocable receipt still gets an honest freshness anchor from the
    feed when nothing in it revokes THIS receipt — distinct from the
    "matching record present" vector-16 case above (`valid` stays empty here,
    exercising the "none" class's own not-revoked fallback rather than the
    ignored-record path)."""
    payload = make_payload()  # revocability: none (base default)
    envelope = issue.issue(payload, KP, KID)
    other_record = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[other_record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_revocation_refund_window_inside_window_is_revoked() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14},
        issued_at="2026-07-02T14:30:00Z",
    )
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "revoked"
    assert result.ok is False


def test_revocation_refund_window_outside_window_is_ignored() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14},
        issued_at="2026-07-02T14:30:00Z",
    )
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-08-01T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert any("window" in w for w in result.warnings)


def test_revocation_unsigned_record_is_ignored_with_warning() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    garbage_record = {
        "receipt_id": payload["receipt_id"],
        "status": "revoked",
        "revoked_at": "2026-07-03T00:00:00Z",
        # no "signature" member at all
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[garbage_record]
    )
    # The junk record does not authenticate, so it is the sole record AND yields
    # no freshness anchor -> revocation is unknown (not not_revoked_as_of), and
    # the matching-but-unverified record is ignored with a warning.
    assert result.revocation == "unknown"
    assert result.ok is True
    assert any("failed verification" in w for w in result.warnings)


def test_revocation_view_supplied_no_match_reports_not_revoked_as_of() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    other_record = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[other_record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_empty_revocation_view_reports_unknown() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.revocation == "unknown"


def test_no_revocation_view_reports_unknown() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.revocation == "unknown"


def test_non_list_revocation_view_raises_type_error() -> None:
    """Caller-contract enforcement (security): a lone revocation-record OBJECT
    (the exact shape `revocation.build_record` returns) passed where a list is
    required must fail loud, never be silently iterated as dict keys — which
    would authenticate nothing and pass a genuinely revoked receipt as ok."""
    envelope = issue.issue(make_payload(), KP, KID)
    with pytest.raises(TypeError):
        verify.verify(
            _to_bytes(envelope),
            _trust_store(_key_manifest()),
            revocation_view={"receipt_id": "01J1V5B4M9Z8QWERTY12345678"},  # type: ignore[arg-type]
        )


# --- step 6 hardening: authenticate records before honoring/anchoring them --------


def test_revocation_record_signed_by_compromised_key_is_ignored() -> None:
    """The silent-DoS fix: a record signed by a key the issuer has flagged
    `compromised` (§5) must NOT revoke a policy receipt — it fails
    verification and is ignored with a warning, receipt stays ok."""
    manifest = _manifest_active_plus_compromised()
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)  # receipt signed by the still-active KID
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", COMPROMISED_KP, COMPROMISED_KID
    )
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest), revocation_view=[record])
    assert result.signature == "valid"
    assert result.revocation == "unknown"  # no authenticated record -> no anchor
    assert result.ok is True
    assert any("failed verification" in w for w in result.warnings)


def test_not_revoked_as_of_uses_only_authenticated_records_for_anchor() -> None:
    """T must not be inflatable by injecting unsigned junk with a future
    `revoked_at`: the anchor is the max over signature-verified records only."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    authentic = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    junk = {
        "receipt_id": "01J1V5B4M9Z8QWERTY88888888",
        "status": "revoked",
        "revoked_at": "2099-01-01T00:00:00Z",  # unsigned -> must not anchor T
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[authentic, junk]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_not_revoked_as_of_unknown_when_only_unauthenticated_records() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    junk = {
        "receipt_id": "01J1V5B4M9Z8QWERTY88888888",
        "status": "revoked",
        "revoked_at": "2099-01-01T00:00:00Z",
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[junk]
    )
    assert result.revocation == "unknown"


def test_valid_record_with_non_revoked_status_is_not_a_revocation() -> None:
    """Only status=='revoked' drives revocation. A validly-signed record with a
    different status is not a revocation (but still authenticates the feed, so
    it can anchor T)."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "disputed", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


# --- step 7: buyer binding (design §3.2) ------------------------------------------


def test_binding_salt_disclosure_proven() -> None:
    salt = bytes(range(16))
    identifier, identifier_type = "buyer@example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_salt_disclosure_wrong_salt_is_not_proven() -> None:
    salt = bytes(range(16))
    wrong_salt = bytes(range(16, 32))
    identifier, identifier_type = "buyer@example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=wrong_salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_salt_disclosure_non_ascii_email_proven() -> None:
    """Exercises §3.2 normalize(): NFC + ASCII-only lowercasing on a non-ASCII email."""
    salt = bytes(range(16))
    identifier, identifier_type = "Büyér+Tag@Example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_challenge_disclosure_proven() -> None:
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    payload = make_payload(buyer={"pubkey": keys.b64u(buyer_kp.pub)})
    envelope = issue.issue(payload, KP, KID)
    nonce = bytes(range(16))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_challenge_disclosure_wrong_nonce_is_not_proven() -> None:
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    payload = make_payload(buyer={"pubkey": keys.b64u(buyer_kp.pub)})
    envelope = issue.issue(payload, KP, KID)
    nonce = bytes(range(16))
    wrong_nonce = bytes(range(16, 32))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(wrong_nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_challenge_disclosure_null_pubkey_is_not_proven() -> None:
    payload = make_payload()  # buyer.pubkey defaults to null
    envelope = issue.issue(payload, KP, KID)
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    nonce = bytes(range(16))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_salt_disclosure_without_identifier_fails_closed() -> None:
    """The docstring's canonical malformed-disclosure example: `salt` without
    `identifier` is a partial salt path, so it must fail closed to
    "not_proven" rather than being evaluated (or raising)."""
    payload = make_payload()
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(salt=bytes(16))  # identifier/identifier_type left None
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_no_disclosure_is_not_checked_even_with_revocation_view() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.binding == "not_checked"


# --- steps 6-7 only run on an already-valid signature+schema ---------------------


def test_invalid_signature_receipt_skips_revocation_and_binding() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    raw = bytearray(json.dumps(envelope).encode("utf-8"))
    idx = raw.index(b"Example Game")
    raw[idx] = ord("X")
    disclosure = verify.Disclosure(identifier="x", identifier_type="email", salt=bytes(16))
    result = verify.verify(
        bytes(raw), _trust_store(_key_manifest()), revocation_view=[], disclosure=disclosure
    )
    assert result.signature == "invalid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"


def test_schema_invalid_receipt_skips_revocation_and_binding() -> None:
    payload = make_payload()
    del payload["work"]  # schema-invalid: missing required top-level field
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.signature == "valid"
    assert result.schema == "invalid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"


# --- trust: manifest rotation continuity (design §5) ------------------------------


def test_rotation_continuity_happy_path_keeps_normal_trust() -> None:
    root = _key_manifest()  # v1, sole active key KID/KP
    entries_v2 = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    v2 = manifests.build_key_manifest(ISSUER, 2, "2026-02-01T00:00:00Z", entries_v2, KP, KID)
    trust_store = verify.TrustStore(
        manifests={ISSUER: v2}, provenance={ISSUER: "tls"}, chains={ISSUER: [root, v2]}
    )
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"
    assert result.ok is True


def test_rotation_discontinuous_chain_yields_unverified_rotation() -> None:
    root = _key_manifest()  # v1, sole active key KID/KP
    stranger_kp = keys.from_seed(bytes([12]) * 32)
    stranger_kid = f"{ISSUER}/keys/test#ed25519-9"
    entries_v2 = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(stranger_kid, stranger_kp.pub, "2026-02-01T00:00:00Z", None, "active"),
    ]
    # v2 signed by a key that was never active in v1 -> discontinuous rotation.
    v2 = manifests.build_key_manifest(
        ISSUER, 2, "2026-02-01T00:00:00Z", entries_v2, stranger_kp, stranger_kid
    )
    trust_store = verify.TrustStore(
        manifests={ISSUER: v2}, provenance={ISSUER: "tls"}, chains={ISSUER: [root, v2]}
    )
    envelope = issue.issue(make_payload(), KP, KID)  # still resolves fine against v2's KID entry
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.signature == "valid"
    assert result.trust == "unverified_rotation"


def test_no_chain_recorded_is_backward_compatible() -> None:
    """Task-8 TrustStore construction (no `chains` kwarg) must keep working."""
    trust_store = verify.TrustStore(manifests={ISSUER: _key_manifest()}, provenance={ISSUER: "tls"})
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"
