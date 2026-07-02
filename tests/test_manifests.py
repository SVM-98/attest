"""Tests for opr.manifests — key manifests, artifact manifests, rotation continuity (design §5)."""

from __future__ import annotations

import hashlib
from typing import Any

from opr import keys, manifests

ISSUER = "store.example.com"
SERIES = "store.example.com/works/EXG-001"

# TEST ONLY — fixed seeds, never use in production.
KP1 = keys.from_seed(bytes([4]) * 32)
KP2 = keys.from_seed(bytes([5]) * 32)
KP3 = keys.from_seed(bytes([6]) * 32)

KID1 = f"{ISSUER}/keys/test#ed25519-1"
KID2 = f"{ISSUER}/keys/test#ed25519-2"
KID3 = f"{ISSUER}/keys/test#ed25519-3"

_ARTIFACT_SHA256 = hashlib.sha256(b"opr-test-artifact-manifest-v1").hexdigest()


def _artifact() -> dict[str, Any]:
    return {
        "role": "installer",
        "platform": "windows-x86_64",
        "filename": "example-game-1.0-setup.exe",
        "size_bytes": 734003200,
        "sha256": _ARTIFACT_SHA256,
    }


def _v1_manifest(status: str = "active") -> dict[str, Any]:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, status)]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1)


# --- key_entry -------------------------------------------------------------


def test_key_entry_shape_and_defaults() -> None:
    e = manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z")
    assert e == {
        "kid": KID1,
        "pub": keys.b64u(KP1.pub),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_to": None,
        "status": "active",
    }


# --- find_key ----------------------------------------------------------------


def test_find_key_present_and_missing() -> None:
    m = _v1_manifest()
    assert manifests.find_key(m, KID1) is not None
    assert manifests.find_key(m, "nope") is None


# --- build_key_manifest / verify_key_manifest -------------------------------


def test_build_verify_key_manifest_roundtrip() -> None:
    m = _v1_manifest()
    assert manifests.verify_key_manifest(m)


def test_tampered_key_status_breaks_verification() -> None:
    """Design vector 11: key status flipped after manifest signing -> manifest invalid."""
    m = _v1_manifest()
    m["keys"][0]["status"] = "compromised"
    assert not manifests.verify_key_manifest(m)


def test_tampered_signature_breaks_verification() -> None:
    m = _v1_manifest()
    m["manifest_signature"]["sig"] = keys.b64u(bytes(64))
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_missing_signature_block_false() -> None:
    m = _v1_manifest()
    del m["manifest_signature"]
    assert not manifests.verify_key_manifest(m)


def test_verify_key_manifest_unknown_signer_kid_false() -> None:
    m = _v1_manifest()
    m["manifest_signature"]["kid"] = "someone/else#ed25519-9"
    assert not manifests.verify_key_manifest(m)


# --- check_continuity --------------------------------------------------------


def test_continuity_active_signer_true() -> None:
    trusted = _v1_manifest()
    entries_v2 = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "retired"
        ),
        manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active"),
    ]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    assert manifests.check_continuity(trusted, candidate)


def test_continuity_version_gap_false() -> None:
    trusted = _v1_manifest()
    entries_v3 = [manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 3, "2026-06-01T00:00:00Z", entries_v3, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_signer_absent_from_trusted_false() -> None:
    trusted = _v1_manifest()
    entries_v2 = [manifests.key_entry(KID3, KP3.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP3, KID3
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_signer_retired_in_trusted_false() -> None:
    entries_v1 = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "retired"
        )
    ]
    trusted = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries_v1, KP1, KID1)
    entries_v2 = [manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_candidate_self_tampered_false() -> None:
    trusted = _v1_manifest()
    entries_v2 = [
        manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(KID2, KP2.pub, "2026-06-01T00:00:00Z", None, "active"),
    ]
    candidate = manifests.build_key_manifest(
        ISSUER, 2, "2026-06-01T00:00:00Z", entries_v2, KP1, KID1
    )
    candidate["keys"][1]["status"] = "compromised"  # breaks candidate's own signature
    assert not manifests.check_continuity(trusted, candidate)


def test_continuity_issuer_mismatch_false() -> None:
    trusted = _v1_manifest()
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "active")]
    candidate = manifests.build_key_manifest(
        "evil.example.com", 2, "2026-06-01T00:00:00Z", entries, KP1, KID1
    )
    assert not manifests.check_continuity(trusted, candidate)


# --- build_artifact_manifest / verify_artifact_manifest ---------------------


def test_build_verify_artifact_manifest_roundtrip() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_wrong_issuer_false() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        "other.example.com", SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_tampered_false() -> None:
    key_manifest = _v1_manifest()
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    am["version"] = 2
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_signer_not_active_false() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-01-01T00:00:00Z", None, "retired")]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_before_valid_from_false() -> None:
    entries = [manifests.key_entry(KID1, KP1.pub, "2026-06-01T00:00:00Z", None, "active")]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-06-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-01-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_after_valid_to_false() -> None:
    entries = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "active"
        )
    ]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-03-01T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert not manifests.verify_artifact_manifest(am, key_manifest)


def test_artifact_manifest_released_within_window_true() -> None:
    entries = [
        manifests.key_entry(
            KID1, KP1.pub, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z", "active"
        )
    ]
    key_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP1, KID1
    )
    am = manifests.build_artifact_manifest(
        ISSUER, SERIES, 1, "2026-06-15T00:00:00Z", [_artifact()], KP1, KID1
    )
    assert manifests.verify_artifact_manifest(am, key_manifest)
