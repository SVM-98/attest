"""THE oracle: every receipt the bridge emits must satisfy the real verifier."""

from __future__ import annotations

import json
import smtplib
from typing import Any

import pytest
from attest_bridge.config import DeliveryConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.model import NormalizedPurchase, PurchaseRejected, UnmappedProduct
from conftest import ISSUER

from attest import anchor, cli, keys, transfer
from attest import verify as verify_mod


def _purchase(**overrides: Any) -> NormalizedPurchase:
    base: dict[str, Any] = dict(
        platform="stripe",
        platform_purchase_id="cs_test_0001",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at="2026-07-24T10:00:00Z",
        amount="1999",
        currency="eur",
    )
    base.update(overrides)
    return NormalizedPurchase(**base)


def _envelope_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def test_email_bound_receipt_verifies_offline_ok(core: IssuingCore, trust_store: Any) -> None:
    outcome = core.issue_for(_purchase())
    result = verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store)
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.ok is True
    payload = outcome.envelope["payload"]
    assert payload["attest_version"] == "0.2"
    assert payload["license"]["transferable"] is False
    assert payload["buyer"]["pubkey"] is None


def test_embedded_salt_proves_binding_via_real_verifier(
    core: IssuingCore, trust_store: Any
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_test_0002"))
    salt = keys.b64u_decode(outcome.envelope["delivery"]["salt"])
    assert len(salt) == 16
    disclosure = verify_mod.Disclosure(
        identifier="buyer@example.com", identifier_type="email", salt=salt
    )
    result = verify_mod.verify(
        _envelope_bytes(outcome.envelope), trust_store, disclosure=disclosure
    )
    assert result.binding == "proven"
    # wrong email must NOT prove — the commitment is real, not decorative
    wrong = verify_mod.Disclosure(
        identifier="other@example.com", identifier_type="email", salt=salt
    )
    assert (
        verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store, disclosure=wrong).binding
        == "not_proven"
    )


def test_pubkey_bound_receipt_is_transferable_and_passes_chain_audit(
    core: IssuingCore, trust_store: Any, key_manifest: dict[str, Any]
) -> None:
    buyer_kp = keys.generate()
    outcome = core.issue_for(
        _purchase(platform_purchase_id="cs_test_0003", buyer_pubkey=buyer_kp.pub)
    )
    payload = outcome.envelope["payload"]
    assert payload["license"]["transferable"] is True  # §17.8/D1 invariant
    assert payload["buyer"]["pubkey"] == keys.b64u(buyer_kp.pub)
    assert verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store).ok is True
    audit = transfer.audit_chain(
        [payload],
        [],
        [],
        key_manifest,
        [],
        anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert audit.valid is True
    assert audit.link_status == ()


def test_bridge_receipt_passes_attest_verify_cli(
    core: IssuingCore, key_manifest: dict[str, Any], tmp_path: Any, capsys: Any
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_test_0004"))
    receipt = tmp_path / "receipt.attest"
    receipt.write_text(json.dumps(outcome.envelope), encoding="utf-8")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "manifest.json").write_text(json.dumps(key_manifest), encoding="utf-8")
    rc = cli.main(["verify", str(receipt), "--trust-dir", str(trust_dir)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["ok"] is True


def test_salt_is_fresh_per_receipt(core: IssuingCore) -> None:
    a = core.issue_for(_purchase(platform_purchase_id="cs_a"))
    b = core.issue_for(_purchase(platform_purchase_id="cs_b"))
    assert a.envelope["delivery"]["salt"] != b.envelope["delivery"]["salt"]


def test_duplicate_purchase_returns_stored_receipt_never_reissues(
    core: IssuingCore, ledger: Any
) -> None:
    first = core.issue_for(_purchase(platform_purchase_id="cs_dup"))
    second = core.issue_for(_purchase(platform_purchase_id="cs_dup"))
    assert second.duplicate is True
    assert second.receipt_id == first.receipt_id
    assert second.envelope == first.envelope


def test_unmapped_product_never_issues(core: IssuingCore, ledger: Any) -> None:
    with pytest.raises(UnmappedProduct):
        core.issue_for(_purchase(platform_purchase_id="cs_um", product_key="price_UNKNOWN"))
    assert ledger.get_receipt("stripe", "cs_um") is None


def test_malformed_pubkey_fails_before_signing(core: IssuingCore, ledger: Any) -> None:
    # 31 bytes: survives the DTO only if an adapter mis-decodes; core must still refuse.
    with pytest.raises(PurchaseRejected):
        core.issue_for(_purchase(platform_purchase_id="cs_bad", buyer_pubkey=b"\x01" * 31))
    assert ledger.get_receipt("stripe", "cs_bad") is None


def test_issuer_manifest_is_embedded_for_offline_verification(
    core: IssuingCore, key_manifest: dict[str, Any]
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_manifest"))
    assert outcome.envelope["delivery"]["issuer_manifest"] == key_manifest
    assert outcome.envelope["payload"]["issuer"]["id"] == ISSUER


# -- process(): delivery wiring (Global Constraint 9 — issue+record first) --


def _delivery_config() -> DeliveryConfig:
    return DeliveryConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="merchant",
        smtp_password="hunter2-super-secret",  # noqa: S106 - test fixture, not a real secret
        from_address="receipts@merchant.example.com",
        info_url="https://merchant.example.com/attest/what-is-this",
    )


class _FailingSMTP:
    """Fails at login, every time — no real network, never reaches send_message."""

    def __init__(self, host: str, port: int) -> None:
        pass

    def starttls(self, *, context: Any) -> None:
        pass

    def login(self, username: str, password: str) -> None:
        raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    def send_message(self, message: Any) -> None:  # pragma: no cover
        raise AssertionError("send_message must not be reached after login fails")

    def quit(self) -> None:
        pass

    def __enter__(self) -> _FailingSMTP:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def _make_succeeding_smtp_factory() -> tuple[Any, list[int]]:
    """Returns (factory, calls) — `calls` grows by one per `send_message`."""
    calls: list[int] = []

    class _SucceedingSMTP:
        def __init__(self, host: str, port: int) -> None:
            pass

        def starttls(self, *, context: Any) -> None:
            pass

        def login(self, username: str, password: str) -> None:
            pass

        def send_message(self, message: Any) -> None:
            calls.append(1)

        def quit(self) -> None:
            pass

        def __enter__(self) -> _SucceedingSMTP:
            return self

        def __exit__(self, *exc_info: object) -> None:
            pass

    return _SucceedingSMTP, calls


def test_process_smtp_failure_keeps_receipt_safe_in_ledger_and_it_still_verifies(
    catalog: Any, issuer_identity: Any, ledger: Any, trust_store: Any
) -> None:
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(_delivery_config(), smtp_factory=_FailingSMTP),
    )
    outcome = core.process(_purchase(platform_purchase_id="cs_delivery_fail"))

    # Global Constraint 9: a delivery failure never loses a receipt — it is
    # already durably recorded, retriable, and still a fully valid envelope.
    stored = ledger.get_receipt("stripe", "cs_delivery_fail")
    assert stored is not None
    assert stored.delivered_at is None
    assert stored.delivery_attempts == 1
    assert stored.last_delivery_error is not None
    assert "hunter2-super-secret" not in stored.last_delivery_error

    result = verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store)
    assert result.ok is True


def test_process_does_not_resend_to_an_already_delivered_receipt(
    catalog: Any, issuer_identity: Any, ledger: Any
) -> None:
    factory, calls = _make_succeeding_smtp_factory()
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(_delivery_config(), smtp_factory=factory),
    )
    purchase = _purchase(platform_purchase_id="cs_no_resend")

    first = core.process(purchase)
    second = core.process(purchase)

    assert len(calls) == 1  # the fake's send_message was invoked exactly once
    assert second.duplicate is True
    assert second.receipt_id == first.receipt_id

    stored = ledger.get_receipt("stripe", "cs_no_resend")
    assert stored is not None
    assert stored.delivered_at is not None
    assert stored.delivery_attempts == 0
