"""Tests for attest.validate — JSON Schema (draft 2020-12) validation of attest payloads."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path

import pytest

from attest import canon, validate

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


def test_attest_version_02_accepted() -> None:
    payload = make_payload(attest_version="0.2")

    assert validate.validate_payload(payload) == []


def test_attest_version_unknown_rejected() -> None:
    payload = make_payload(attest_version="0.3")

    errors = validate.validate_payload(payload)

    assert errors


# --- G1 normative ceilings (attest-versioning.md §5 amendment) --------------


def test_validate_envelope_size_accepts_at_ceiling() -> None:
    assert validate.validate_envelope_size(b"x" * validate.MAX_ENVELOPE_BYTES) == []


def test_validate_envelope_size_rejects_over_ceiling() -> None:
    violations = validate.validate_envelope_size(b"x" * (validate.MAX_ENVELOPE_BYTES + 1))

    assert any(
        "envelope exceeds" in v and str(validate.MAX_ENVELOPE_BYTES) in v for v in violations
    )


# `validate.validate_json_depth` was deleted in the 2026-07-22 fix wave: it
# duplicated `canon.py`'s own parse-time nesting-depth cap byte-for-byte (a
# parsed tree handed to it could never exceed the cap, since `canon.
# loads_strict` already rejects deeper input before a parsed tree exists) —
# see `validate.py`'s `MAX_JSON_DEPTH` docstring for the redundant-check
# deletion rationale. These tests cover the single source of truth directly.


def test_max_json_depth_aliases_canon_max_depth() -> None:
    """`validate.MAX_JSON_DEPTH` is a single-source-of-truth alias of
    `canon.MAX_DEPTH` (256), not a second, independently-defined ceiling —
    the previous `MAX_JSON_DEPTH = 32` duplicated and shrank canon.py's own
    parse-time cap, rejecting two previously-conforming vectors
    (`21-canon-strict/b-depth-255`, `c-depth-256`) in violation of
    attest-versioning.md §2's additive-pattern rule."""
    assert validate.MAX_JSON_DEPTH == canon.MAX_DEPTH == 256


def test_json_nesting_accepted_exactly_at_ceiling() -> None:
    nested: object = "leaf"
    for _ in range(validate.MAX_JSON_DEPTH):
        nested = {"n": nested}

    assert canon.loads_strict(json.dumps(nested).encode("utf-8")) is not None


def test_json_nesting_rejected_one_past_ceiling() -> None:
    nested: object = "leaf"
    for _ in range(validate.MAX_JSON_DEPTH + 1):
        nested = {"n": nested}

    with pytest.raises(canon.CanonError, match="maximum nesting depth exceeded"):
        canon.loads_strict(json.dumps(nested).encode("utf-8"))
