"""CLI tests (the task brief): `check-config` and `retry-failed`.

`check-config` is exercised against a real `bridge.toml` pointing at real T3
key/manifest files (the exact on-disk shapes `attest keygen`/`manifest init`
write) — a passing test here is evidence the whole config -> issuer ->
catalog chain works end to end, not just that `ConfigError` propagates from
a synthetic stand-in.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import cli
from attest_bridge.ledger import Ledger
from conftest import DISPLAY_NAME, ISSUER, KID
from test_bridge_stripe_adapter import make_session_completed_event

from attest import keys, pq

_STRIPE_ENV_VAR = "STRIPE_WEBHOOK_SECRET_T8_CLI_TEST"  # env var NAME, not a secret
_LEGAL_TEXT_SHA256 = "0" * 64

_PRICE_TEST_PRODUCT = f"""
[products.price_TEST]
title = "Stardrift Chronicles"
publisher = "Example Games Store"
artifact_series = "merchant.example.com/works/stardrift-chronicles"
terms_uri = "https://merchant.example.com/attest/license-templates/standard-v1"
legal_text_sha256 = "{_LEGAL_TEXT_SHA256}"
[products.price_TEST.identifiers]
sku = "SDC-STD-001"
"""


def _write_issuer_key_files(tmp_path: Path, hybrid_keys: pq.HybridSigningKeys) -> tuple[Path, Path]:
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed) + "\n", encoding="utf-8")

    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    return seed_path, mldsa_path


def _write_config(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    *,
    products_toml: str = "",
    extra_toml: str = "",
) -> Path:
    seed_path, mldsa_path = _write_issuer_key_files(tmp_path, hybrid_keys)
    manifest_path = tmp_path / "key-manifest.json"
    manifest_path.write_text(json.dumps(key_manifest), encoding="utf-8")
    ledger_path = tmp_path / "ledger.sqlite3"

    config_text = f"""
public_base_url = "https://receipts.example.com"
ledger_path = "{ledger_path}"

[issuer]
id = "{ISSUER}"
display_name = "{DISPLAY_NAME}"
kid = "{KID}"
seed_path = "{seed_path}"
mldsa_key_path = "{mldsa_path}"
manifest_path = "{manifest_path}"

[stripe]
webhook_secret_env = "{_STRIPE_ENV_VAR}"

{products_toml}
{extra_toml}
"""
    config_path = tmp_path / "bridge.toml"
    config_path.write_text(config_text, encoding="utf-8")
    return config_path


# -- check-config ---------------------------------------------------------


def test_check_config_rc_0_on_valid_config_with_real_key_files(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 0
    out = capsys.readouterr().out
    assert ISSUER in out
    assert "price_TEST" in out
    assert "stripe: configured" in out


def test_check_config_rc_2_on_missing_env_var(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(_STRIPE_ENV_VAR, raising=False)
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "config error" in err
    assert _STRIPE_ENV_VAR in err


def test_check_config_rc_2_on_corrupt_key_file(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )
    (tmp_path / "issuer.seed").write_text("not-a-valid-seed", encoding="utf-8")

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 2
    assert "config error" in capsys.readouterr().err


def test_check_config_rejects_product_the_real_receipt_schema_cannot_issue(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    invalid = _PRICE_TEST_PRODUCT.replace(_LEGAL_TEXT_SHA256, "x")

    assert (
        cli.main(
            [
                "check-config",
                "--config",
                str(_write_config(tmp_path, hybrid_keys, key_manifest, products_toml=invalid)),
            ]
        )
        == 2
    )
    assert "price_TEST" in capsys.readouterr().err


# -- retry-failed -----------------------------------------------------------


def test_retry_failed_resolves_dead_letter_after_catalog_gains_the_mapping(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")

    # A dead letter recorded when `price_TEST` had no catalog mapping yet —
    # `raw_json` is the whole raw event, exactly what a real webhook handler
    # would have dead-lettered on UnmappedProduct.
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    event = make_session_completed_event(
        session_id="cs_retry_1", metadata={"attest_product_key": "price_TEST"}
    )
    ledger.add_dead_letter(
        "stripe",
        "cs_retry_1",
        "no product mapping for 'price_TEST'",
        json.dumps(event),
        now="2026-07-24T10:00:00Z",
    )
    assert len(ledger.unresolved_dead_letters()) == 1

    # The merchant fixes the catalog: the config now maps price_TEST.
    config_path = _write_config(
        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
    )

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 0
    assert "undelivered: 0" in capsys.readouterr().out
    assert ledger.unresolved_dead_letters() == []
    stored = ledger.get_receipt("stripe", "cs_retry_1")
    assert stored is not None


def test_retry_failed_leaves_still_unmapped_dead_letter_unresolved(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")

    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = Ledger(ledger_path)
    event = make_session_completed_event(
        session_id="cs_still_unmapped", metadata={"attest_product_key": "price_STILL_UNKNOWN"}
    )
    ledger.add_dead_letter(
        "stripe",
        "cs_still_unmapped",
        "no product mapping for 'price_STILL_UNKNOWN'",
        json.dumps(event),
        now="2026-07-24T10:00:00Z",
    )

    # No products.* added this time -- the mapping is still missing.
    config_path = _write_config(tmp_path, hybrid_keys, key_manifest, products_toml="")

    rc = cli.main(["retry-failed", "--config", str(config_path)])

    assert rc == 1
    assert len(ledger.unresolved_dead_letters()) == 1
    assert ledger.get_receipt("stripe", "cs_still_unmapped") is None


def test_retry_failed_never_issues_an_unpaid_dead_letter_without_event_id(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    event = make_session_completed_event(
        session_id="cs_unpaid_retry",
        payment_status="unpaid",
        metadata={"attest_product_key": "price_TEST"},
    )
    event.pop("id")
    ledger.add_dead_letter(
        "stripe", "cs_unpaid_retry", "missing id", json.dumps(event), now="2026-07-24T10:00:00Z"
    )

    assert (
        cli.main(
            [
                "retry-failed",
                "--config",
                str(
                    _write_config(
                        tmp_path, hybrid_keys, key_manifest, products_toml=_PRICE_TEST_PRODUCT
                    )
                ),
            ]
        )
        == 0
    )
    assert ledger.get_receipt("stripe", "cs_unpaid_retry") is None
    assert ledger.unresolved_dead_letters() == []


def test_retry_failed_reenqueues_itch_dead_letter_without_replaying_purchase(
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_STRIPE_ENV_VAR, "whsec_real_test_secret")
    monkeypatch.setenv("ITCH_API_KEY", "itch-test")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-test")
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    ledger.add_dead_letter(
        "itch",
        None,
        "abandoned",
        json.dumps({"email": "buyer@example.com", "game_id": "123456"}),
        now="2026-07-24T10:00:00Z",
    )
    extra = """
[itch]
api_key_env = "ITCH_API_KEY"
[delivery]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "merchant"
smtp_password_env = "SMTP_PASSWORD"
from_address = "receipts@example.com"
info_url = "https://merchant.example.com/info"
"""
    assert (
        cli.main(
            [
                "retry-failed",
                "--config",
                str(_write_config(tmp_path, hybrid_keys, key_manifest, extra_toml=extra)),
            ]
        )
        == 0
    )
    assert ledger.unresolved_dead_letters() == []
    claims = ledger.due_claims("2100-01-01T00:00:00Z")
    assert [(claim.email, claim.game_id) for claim in claims] == [("buyer@example.com", "123456")]


def test_retry_failed_rc_2_on_config_error(tmp_path: Path) -> None:
    missing_config = tmp_path / "does-not-exist.toml"
    rc = cli.main(["retry-failed", "--config", str(missing_config)])
    assert rc == 2


# -- serve (fail-fast only -- serve_forever() is not exercised here) --------


def test_serve_fails_fast_with_rc_2_on_config_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_config = tmp_path / "does-not-exist.toml"
    rc = cli.main(["serve", "--config", str(missing_config)])
    assert rc == 2
    assert "config error" in capsys.readouterr().err


# -- access-log token redaction (security review) --------------------


def test_redact_tokens_hides_download_tokens() -> None:
    # /r/<download-token> is an unguessable receipt capability, so the
    # default WSGI access log must never write it.
    assert cli._redact_tokens("GET /r/abc123 HTTP/1.1") == "GET /r/<redacted> HTTP/1.1"
    assert cli._redact_tokens("GET /healthz HTTP/1.1") == "GET /healthz HTTP/1.1"


def test_redact_tokens_hides_stripe_session_capability_from_access_log() -> None:
    for key in ("session_id", "session%5Fid"):
        request = f"GET /stripe/receipt?{key}=cs_live_secret HTTP/1.1"
        redacted = cli._redact_tokens(request)
        assert "cs_live_secret" not in redacted
        assert "session_id=<redacted>" in redacted
