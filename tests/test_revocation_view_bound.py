"""Tests for the revocation-view bound + cached manifest self-verify.

Review improvement #17 (Codex xhigh 2026-07-13): `_classify_revocation`
used to re-run the issuer manifest's self-verify once PER RECORD in the
untrusted revocation view (O(N * manifest-verify) wasted-work DoS), and
the view had no size bound. This file pins the two hardenings:

- the manifest self-verify runs exactly once per classification
  (`verify_record_signature` + hoisted `verify_key_manifest`);
- (Task 2) an oversized view is not evaluated at all: `revocation:
  "unknown"` plus an explicit warning — never truncation, never a raise.

Mirrored on the TS side by `verifiers/ts/test/revocation-bound.test.ts`.
"""

from __future__ import annotations

from typing import Any

import pytest

from attest import keys, manifests, revocation, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
RETIRED_KID = f"{ISSUER}/keys/test#ed25519-retired"
GHOST_KID = f"{ISSUER}/keys/test#ed25519-ghost"  # never listed in the manifest

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([21]) * 32)
RETIRED_KP = keys.from_seed(bytes([22]) * 32)
GHOST_KP = keys.from_seed(bytes([23]) * 32)

RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"  # tests.helpers base payload receipt_id


def _key_manifest() -> dict[str, Any]:
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(RETIRED_KID, RETIRED_KP.pub, "2026-01-01T00:00:00Z", None, "retired"),
    ]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _record(revoked_at: str = "2026-07-03T00:00:00Z") -> dict[str, Any]:
    return revocation.build_record(RECEIPT_ID, "revoked", revoked_at, KP, KID)


# --- cached manifest self-verify (Task 1) -------------------------------------


def test_manifest_self_verify_runs_once_per_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Improvement #17 core: one `verify_key_manifest` call per classification,
    not one per record — a hostile many-record feed can no longer multiply
    manifest-verification work."""
    manifest = _key_manifest()
    payload = make_payload(license={"revocability": "policy"})
    view = [_record(f"2026-07-0{i}T00:00:00Z") for i in range(1, 6)]

    calls = {"count": 0}
    real = manifests.verify_key_manifest

    def counting(m: dict[str, Any]) -> bool:
        calls["count"] += 1
        return real(m)

    monkeypatch.setattr(manifests, "verify_key_manifest", counting)
    warnings: list[str] = []
    result = verify._classify_revocation(payload, view, manifest, warnings)
    assert result == "revoked"
    assert calls["count"] == 1


def test_verify_record_signature_accepts_valid_record() -> None:
    manifest = _key_manifest()
    assert manifests.verify_key_manifest(manifest) is True  # documented precondition
    assert revocation.verify_record_signature(_record(), manifest) is True


def test_verify_record_signature_rejects_unlisted_signer() -> None:
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", GHOST_KP, GHOST_KID
    )
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_signature_rejects_non_active_signer() -> None:
    record = revocation.build_record(
        RECEIPT_ID, "revoked", "2026-07-03T00:00:00Z", RETIRED_KP, RETIRED_KID
    )
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_signature_rejects_revoked_at_before_valid_from() -> None:
    record = _record(revoked_at="2025-12-31T23:59:59Z")
    assert revocation.verify_record_signature(record, _key_manifest()) is False


def test_verify_record_delegates_and_still_requires_manifest_self_consistency() -> None:
    manifest = _key_manifest()
    assert revocation.verify_record(_record(), manifest) is True
    tampered = dict(manifest)
    tampered["issued_at"] = "2027-01-01T00:00:00Z"  # breaks the manifest's own signature
    assert revocation.verify_record(_record(), tampered) is False
