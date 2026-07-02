"""Tests for attest.validate — JSON Schema (draft 2020-12) validation of attest payloads."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

from attest import validate

from .helpers import make_payload


def test_valid_example_payload_passes() -> None:
    assert validate.validate_payload(make_payload()) == []


def test_revocability_none_with_drm_bound_fails() -> None:
    payload = make_payload(license={"drm": "drm-bound"})

    errors = validate.validate_payload(payload)

    assert errors


def test_revocability_none_without_artifacts_or_series_fails() -> None:
    payload = make_payload()
    del payload["work"]["artifact_series"]
    payload["work"]["artifacts"] = []

    errors = validate.validate_payload(payload)

    assert errors


def test_refund_window_without_revocation_window_days_fails() -> None:
    payload = make_payload(license={"revocability": "refund_window"})

    errors = validate.validate_payload(payload)

    assert errors
    assert any("revocation_window_days" in e for e in errors)


def test_size_bytes_at_2_pow_53_fails() -> None:
    payload = make_payload()
    payload["work"]["artifacts"][0]["size_bytes"] = 2**53

    errors = validate.validate_payload(payload)

    assert errors
    assert any("size_bytes" in e for e in errors)


def test_packaged_schema_is_byte_identical_to_normative_copy() -> None:
    repo_root = Path(__file__).parent.parent
    normative = repo_root / "docs" / "spec" / "schema" / "attest-receipt.schema.json"
    packaged = importlib.resources.files("attest.schema").joinpath("attest-receipt.schema.json")

    assert packaged.read_bytes() == normative.read_bytes()
