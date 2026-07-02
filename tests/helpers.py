"""Shared test payload builder for attest receipt payload tests."""

from __future__ import annotations

import hashlib
from typing import Any

from attest.keys import b64u

# Fixed 32 zero-bytes commitment/pubkey material — deterministic, test-only.
_COMMITMENT = b64u(bytes(32))

_LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-legal-text-v1").hexdigest()
_MIRROR_POLICY_SHA256 = hashlib.sha256(b"attest-test-mirror-policy-v1").hexdigest()
_ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()


def _base_payload() -> dict[str, Any]:
    """The reference example payload (see docs/spec/attest-v0.1.md)."""
    return {
        "attest_version": "0.1",
        "receipt_id": "01J1V5B4M9Z8QWERTY12345678",
        "issued_at": "2026-07-02T14:30:00Z",
        "supersedes": None,
        "issuer": {
            "id": "store.example.com",
            "display_name": "Example Games Store",
        },
        "buyer": {
            "commitment": _COMMITMENT,
            "identifier_type": "issuer-account",
            "pubkey": None,
        },
        "work": {
            "title": "Example Game",
            "publisher": "Example Publisher srl",
            "edition": "Deluxe",
            "identifiers": {"issuer_sku": "EXG-001"},
            "artifact_series": "store.example.com/works/EXG-001",
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": 734003200,
                    "sha256": _ARTIFACT_SHA256,
                }
            ],
        },
        "license": {
            "grant": "perpetual",
            "revocability": "none",
            "transferable": False,
            "drm": "drm-free",
            "terms_uri": "https://store.example.com/attest/license-templates/standard-v1",
            "legal_text_sha256": _LEGAL_TEXT_SHA256,
            "jurisdiction_flags": {"eu_usedsoft_asserted": False},
        },
        "survivability": {
            "redownload_right": True,
            "mirror_policy_uri": "https://store.example.com/attest/mirror-policy-v1",
            "mirror_policy_sha256": _MIRROR_POLICY_SHA256,
            "end_of_life": "artifacts-remain-redownloadable",
            "eol_commitment_uri": None,
            "eol_commitment_sha256": None,
        },
    }


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def make_payload(**overrides: Any) -> dict[str, Any]:
    """Return the §3.1 example payload as a dict, deep-merged with `overrides`.

    Nested dict overrides (e.g. `license={"revocability": "policy"}`) merge into
    the corresponding base dict instead of replacing it wholesale; non-dict
    values (including lists) replace the base value outright.
    """
    return _deep_merge(_base_payload(), overrides)
