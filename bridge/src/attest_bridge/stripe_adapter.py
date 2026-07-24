"""Stripe adapter: verify the inbound webhook signature (the trust boundary
between a merchant's Stripe account and this bridge), then normalize a
`checkout.session.completed` / `checkout.session.async_payment_succeeded`
event into a platform-agnostic `NormalizedPurchase` (the task brief; Global
Constraint 15 / OI-1 — `the internal implementation plan
bridge.md`).

Signature scheme (Stripe docs, verified 2026-07-24): the `Stripe-Signature`
header is `t=<unix>,v1=<hex>[,v1=...][,v0=...]`. The signed message is
`"{t}." + <raw request body bytes>`, HMAC-SHA256 keyed by the `whsec_`
endpoint secret. Multiple `v1` values are legal during a secret rotation
(Stripe signs with both the old and new secret for a window) — ANY matching
candidate is accepted, compared constant-time (`hmac.compare_digest`, never
`==`). `v0` is Stripe's older signing scheme and is NEVER accepted. The body
is parsed with `json.loads` only AFTER the signature has verified — there is
no code path in this module that returns event data without a verified
signature first.

Replay is explicitly NOT this module's job: the same valid `(body, header)`
pair verifies successfully every time it is presented (Stripe's own webhook
sender retries delivery on non-2xx responses, resending the identical signed
body). Rejecting an actual replay is the Ledger's `(platform, purchase_id)`
event-dedup job (T8), not the signature's — a valid signature only proves
"this body was really signed with the merchant's Stripe secret", never
"this is the first time we've seen it".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from attest_bridge.model import (
    BridgeError,
    ConfigError,
    NormalizedPurchase,
    PurchaseRejected,
    decode_buyer_pubkey,
    rfc3339_from_unix,
)

_DEFAULT_TOLERANCE_SECONDS = 300
_LINE_ITEMS_URL = "https://api.stripe.com/v1/checkout/sessions/{session_id}/line_items"


class StripeSignatureError(BridgeError):
    """The inbound webhook signature failed verification — reject before parsing."""


def verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    *,
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> None:
    """Verify a Stripe `Stripe-Signature` header against the raw `payload` bytes.

    Raises `StripeSignatureError` on any failure: missing/unparseable
    timestamp, no `v1` candidate present at all, a stale timestamp (outside
    `tolerance_seconds`), or no `v1` candidate whose HMAC matches `secret`.
    Does NOT raise on a replayed-but-genuinely-valid signature — see the
    module docstring for why that split is deliberate.
    """
    # An empty secret makes the HMAC forgeable by anyone: the empty-key MAC of
    # any chosen body is trivially computable, so an empty secret can never
    # authenticate a webhook. Refuse to verify against one — defence in depth,
    # since `StripeAdapter.__init__` already rejects an empty secret at
    # construction, but this primitive is a public entry point called directly
    # too (T8, tests).
    if not secret:
        raise StripeSignatureError("refusing to verify against an empty webhook secret")

    t_values: list[str] = []
    v1_candidates: list[str] = []
    for part in sig_header.split(","):
        key, _, value = part.partition("=")
        if key == "t":
            t_values.append(value)
        elif key == "v1":
            v1_candidates.append(value)
        # "v0" (Stripe's older signing scheme) is parsed like any other
        # unrecognized key and intentionally never added to the accepted
        # candidates — it must never be sufficient to pass verification.

    # Fail closed on a malformed timestamp: require EXACTLY ONE `t` (a duplicate
    # `t=abc` appended to a valid header must not be silently skipped while the
    # earlier valid timestamp survives) whose value is a canonical run of ASCII
    # decimal digits. `int()` on its own is too lenient — it also accepts
    # surrounding whitespace, a leading sign, digit-group underscores, and
    # Unicode digits, so `t= 1784000000 ` would otherwise reconstruct the
    # canonical integer and slip past the staleness check.
    if len(t_values) != 1:
        raise StripeSignatureError("Stripe-Signature header must carry exactly one timestamp ('t')")
    ts_raw = t_values[0]
    if not (ts_raw.isascii() and ts_raw.isdigit()):
        raise StripeSignatureError("malformed timestamp ('t') in Stripe-Signature header")
    t = int(ts_raw)

    if not v1_candidates:
        raise StripeSignatureError("no v1 signature present in Stripe-Signature header")

    current = int(time.time()) if now is None else now
    if abs(current - t) > tolerance_seconds:
        raise StripeSignatureError("stale webhook timestamp")

    expected = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    # Constant-time compare against every v1 candidate — never short-circuit
    # on the first mismatch's content, and never use `==` on secret-derived data.
    if not any(hmac.compare_digest(expected, candidate) for candidate in v1_candidates):
        raise StripeSignatureError("signature mismatch")


def _default_http_get(url: str, headers: dict[str, str]) -> bytes:
    """Real network call used when no `http_get` is injected (line-items fallback).

    The line-items URL passed in by `StripeAdapter` is always the hardcoded
    HTTPS template below (`_LINE_ITEMS_URL`), but this still enforces the
    `http_get` contract itself: `urlopen` never runs against anything but an
    `https://` URL, regardless of caller.
    """
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch a non-https URL: {url!r}")
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - URL validated https:// above
    with urllib.request.urlopen(request) as response:  # noqa: S310 - URL validated https:// above
        data: bytes = response.read()
        return data


class StripeAdapter:
    """Stripe `PurchaseSource`: webhook verification + normalize."""

    platform = "stripe"
    HANDLED_EVENT_TYPES = frozenset(
        {"checkout.session.completed", "checkout.session.async_payment_succeeded"}
    )

    def __init__(
        self,
        *,
        webhook_secret: str,
        api_key: str | None,
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
    ) -> None:
        # Fail fast, before serving: an empty (or whitespace-only) webhook
        # secret makes every inbound signature forgeable (see
        # `verify_stripe_signature`). The config layer permits an empty
        # env-var value, so this trust boundary must not rely on it.
        if not webhook_secret.strip():
            raise ConfigError("stripe webhook secret is empty")
        self._webhook_secret = webhook_secret
        self._api_key = api_key
        self._http_get = http_get if http_get is not None else _default_http_get

    def parse_event(
        self, payload: bytes, sig_header: str, *, now: int | None = None
    ) -> dict[str, Any]:
        """Verify the signature, then parse — in that order, always."""
        verify_stripe_signature(payload, sig_header, self._webhook_secret, now=now)
        event: dict[str, Any] = json.loads(payload)
        return event

    def wants(self, event: dict[str, Any]) -> bool:
        """True iff `event` is a handled type for a completed (paid) checkout."""
        if event.get("type") not in self.HANDLED_EVENT_TYPES:
            return False
        session = event.get("data", {}).get("object", {})
        return bool(session.get("payment_status") == "paid")

    def normalize(self, event: dict[str, Any]) -> NormalizedPurchase:
        """Turn a `checkout.session.completed`-shaped event into a `NormalizedPurchase`.

        Raises `PurchaseRejected` for any malformed *purchase* input: missing
        buyer email, no resolvable product key, or a malformed buyer pubkey
        (decoded through `decode_buyer_pubkey`, fail-before-signing).
        """
        session = event["data"]["object"]
        platform_purchase_id = session["id"]

        customer_details = session.get("customer_details") or {}
        email = customer_details.get("email")
        if not email:
            raise PurchaseRejected(
                f"stripe session {platform_purchase_id!r} has no customer_details.email"
            )

        purchased_at = rfc3339_from_unix(event["created"])

        amount_total = session.get("amount_total")
        amount = str(amount_total) if amount_total is not None else None
        currency = session.get("currency")

        metadata = session.get("metadata") or {}
        product_key = metadata.get("attest_product_key") or self._line_items_product_key(
            platform_purchase_id
        )

        # OI-1 precedence: metadata carrier wins over the buyer-typed custom field.
        pubkey_str = metadata.get("attest_buyer_pubkey") or self._custom_field_pubkey(session)
        buyer_pubkey = decode_buyer_pubkey(pubkey_str)

        return NormalizedPurchase(
            platform=self.platform,
            platform_purchase_id=platform_purchase_id,
            buyer_identifier=email,
            identifier_type="email",
            buyer_pubkey=buyer_pubkey,
            product_key=product_key,
            purchased_at=purchased_at,
            amount=amount,
            currency=currency,
        )

    def _line_items_product_key(self, session_id: str) -> str:
        """Fallback when `metadata.attest_product_key` is absent (Global Constraint 15).

        Requires `api_key` (the merchant's Stripe secret key) — with neither
        a metadata key nor an api_key configured there is no way to
        determine what was purchased, and issuing on a guess would violate
        the catalog-resolution contract (`UnmappedProduct` exists precisely
        so nothing is ever issued without a known product).
        """
        if not self._api_key:
            raise PurchaseRejected(
                "no product key: set metadata.attest_product_key or configure stripe.api_key_env"
            )
        url = _LINE_ITEMS_URL.format(session_id=session_id)
        headers = {"Authorization": f"Bearer {self._api_key}"}
        body = self._http_get(url, headers)
        data = json.loads(body)
        items = data.get("data") or []
        if not items:
            raise PurchaseRejected(f"stripe line items for session {session_id!r} are empty")
        price = items[0].get("price") or {}
        price_id = price.get("id")
        if not price_id:
            raise PurchaseRejected(f"stripe line item for session {session_id!r} has no price.id")
        return str(price_id)

    @staticmethod
    def _custom_field_pubkey(session: dict[str, Any]) -> str | None:
        """OI-1 carrier #2: Checkout custom field `key="attest_pubkey"`, `type="text"`."""
        for field in session.get("custom_fields") or []:
            if field.get("key") == "attest_pubkey" and field.get("type") == "text":
                value = (field.get("text") or {}).get("value")
                return value if isinstance(value, str) else None
        return None
