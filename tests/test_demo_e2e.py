"""Integration test for `demo/store_dies.py` — "the store dies, the receipt
survives" (Task 15).

Drives the exact same `run_demo()` the manual demo script calls, inside
pytest's `tmp_path`, and asserts every one of the 8 narrated steps'
outcomes programmatically — not just that the script ran, but that the
outcomes are the honest ones the design promises: an offline, unauthenticated
TOFU verification of a receipt whose issuing store no longer exists, with a
proven buyer-binding and a matching independently-held artifact copy.

Hermetic: `run_demo()` is only ever handed `tmp_path`, touches nothing
outside it (asserted directly below), and makes no network calls.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from demo.store_dies import run_demo

CapSys = pytest.CaptureFixture[str]


def test_store_dies_receipt_survives(tmp_path: Path, capsys: CapSys) -> None:
    outcomes = run_demo(tmp_path)
    narration = capsys.readouterr().out

    # The narration itself mentions the pivotal steps by name.
    assert "Step 5" in narration
    assert "Step 6" in narration
    assert "Step 7" in narration
    assert "Step 8" in narration

    # --- Step 5: the store directory itself is gone -----------------------
    assert outcomes["store_dir_deleted"] is True
    assert not (tmp_path / "store").exists()

    # --- Step 6: offline verify against the bundle alone -------------------
    # ok, unauthenticated-TOFU trust (no live TLS fetch happened at
    # verification time), and an honest "unknown" revocation status (no
    # revocation view was ever supplied — never claim "not revoked", only
    # "we don't know").
    verify_result = outcomes["verify"]
    assert outcomes["verify_exit_code"] == 0
    assert verify_result["ok"] is True
    assert verify_result["signature"] == "valid"
    assert verify_result["schema"] == "valid"
    assert verify_result["trust"] == "unauthenticated_tofu"
    assert verify_result["revocation"] == "unknown"

    # --- Step 7: buyer-binding proof via salt disclosure --------------------
    disclosure_result = outcomes["verify_with_disclosure"]
    assert outcomes["verify_with_disclosure_exit_code"] == 0
    assert disclosure_result["ok"] is True
    assert disclosure_result["binding"] == "proven"

    # --- Step 8: independently-mirrored artifact still matches -------------
    check_result = outcomes["check_artifact"]
    assert outcomes["check_artifact_exit_code"] == 0
    assert check_result["match"] is True
    assert check_result["sha256"]

    # Sanity: a real receipt_id was produced and threaded through every step.
    assert isinstance(outcomes["receipt_id"], str)
    assert outcomes["receipt_id"]

    # Casey's saved salt is real buyer-binding secret material — it must be
    # written owner-only (0600), same as every other secret this codebase
    # writes to disk (mirrors cli._write_secret_text / bundle._write_secret_json).
    salt_path = tmp_path / "buyer" / "receipt.salt"
    assert salt_path.exists()
    assert stat.S_IMODE(salt_path.stat().st_mode) == 0o600


def test_run_demo_touches_nothing_outside_its_own_workspace(tmp_path: Path) -> None:
    """Binding constraint: `run_demo()` must delete only within the
    workspace it is given (the store directory it creates itself) — never
    anything else on disk. A sibling canary directory proves it survives."""
    canary_dir = tmp_path.parent / f"{tmp_path.name}-canary"
    canary_dir.mkdir()
    canary_file = canary_dir / "must-survive.txt"
    canary_file.write_text("untouched", encoding="utf-8")
    try:
        run_demo(tmp_path)
        assert canary_file.read_text(encoding="utf-8") == "untouched"
    finally:
        canary_file.unlink()
        canary_dir.rmdir()


def test_run_demo_returns_a_result_usable_without_capturing_stdout(tmp_path: Path) -> None:
    """The pytest wrapper must be able to assert outcomes programmatically,
    not just eyeball narration text — `run_demo()` returns a plain dict of
    the key outcomes regardless of what got printed."""
    outcomes = run_demo(tmp_path)

    assert outcomes["verify"]["ok"] is True
    assert outcomes["verify_with_disclosure"]["binding"] == "proven"
    assert outcomes["check_artifact"]["match"] is True
