"""NormalizedPurchase DTO + buyer-pubkey decoding (fail-before-signing gate #1)."""

from __future__ import annotations

import dataclasses

import pytest
from attest_bridge.model import (
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    rfc3339_from_unix,
)

from attest import keys


def _purchase(**overrides: object) -> NormalizedPurchase:
    base: dict[str, object] = dict(
        platform="stripe",
        platform_purchase_id="cs_test_1",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at="2026-07-24T10:00:00Z",
    )
    base.update(overrides)
    return NormalizedPurchase(**base)  # type: ignore[arg-type]


def test_normalized_purchase_is_frozen() -> None:
    p = _purchase()
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.platform = "itch"  # type: ignore[misc]


def test_decode_buyer_pubkey_none_and_empty_and_whitespace_are_absent() -> None:
    assert decode_buyer_pubkey(None) is None
    assert decode_buyer_pubkey("") is None
    assert decode_buyer_pubkey("   ") is None


def test_decode_buyer_pubkey_valid_roundtrip() -> None:
    raw = bytes(range(32))
    assert decode_buyer_pubkey(keys.b64u(raw)) == raw
    assert decode_buyer_pubkey("  " + keys.b64u(raw) + "\n") == raw  # tolerant of pasted whitespace


@pytest.mark.parametrize("bad", ["not!!b64u", keys.b64u(bytes(31)), keys.b64u(bytes(33)), "AAAA"])
def test_decode_buyer_pubkey_malformed_rejects(bad: str) -> None:
    with pytest.raises(PurchaseRejected):
        decode_buyer_pubkey(bad)


def test_rfc3339_from_unix_matches_attest_format() -> None:
    # Epoch literal independently recomputed (brief's task-1-brief.md literal
    # "2026-07-13T16:53:20Z" did not match `datetime.fromtimestamp(1_784_000_000,
    # UTC)`; per the brief's own instruction, the literal is fixed here, not
    # the function under test).
    assert rfc3339_from_unix(1_784_000_000) == "2026-07-14T03:33:20Z"
