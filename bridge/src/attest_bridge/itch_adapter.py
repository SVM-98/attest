"""itch.io adapter: a claim-queue poller, not a webhook (the task brief;
OI-4, source-verified 2026-07-24 — `the internal implementation plan
webhook-bridge.md`).

itch.io exposes no purchase webhook and no purchase-enumeration/pagination/
cursor endpoint at all: `api.itch.io` offers only `credentials/info`,
`profile`, `profile/games`, `games/{id}/purchases?email=|user_id=`,
`games/{id}/download_keys?...`, `wharf/latest`. So issuance here can never be
push-driven — it is a claim-queue poller: a buyer (via `POST /itch/claim`,
`http.py`) or a merchant CSV backfill (`itch-import`, `cli.py`) enqueues an
(email, game_id) CLAIM in the Ledger; each `ItchPoller.tick` drains DUE claims
by calling `GET /games/{game_id}/purchases?email=...` and treats THE API
RESPONSE AS THE SOLE ISSUANCE AUTHORITY.

This is the load-bearing invariant of this whole module: a claim or a CSV row
NEVER causes issuance on its own — only an itch-API-confirmed purchase does.
The one line that gates every `core.process` call in `ItchPoller.tick` is
inside the `for raw in purchases` loop, where `purchases` is exactly what
`ItchAdapter.fetch_purchases` returned from the LIVE API call for THIS tick —
there is no other code path in this module, in `http.py`'s `/itch/claim`
routes, or in `cli.py`'s `itch-import` that ever calls `core.process`.
Enqueuing a claim only ever inserts a row in the `claims` table; a CSV row
only ever does the same, once per unique email — neither can, by itself,
produce a receipt.

Dedup is on the purchase `id` against the Ledger's `(platform, purchase_id)`
set (`Ledger.get_receipt`), exactly like Stripe's event/purchase dedup — see
`ItchPoller`'s class docstring for the cross-platform concurrency argument.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from attest_bridge.core import IssuingCore
from attest_bridge.ledger import Claim, Ledger
from attest_bridge.model import BridgeError, NormalizedPurchase, PurchaseRejected, UnmappedProduct

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
# itch.io's documented purchase timestamp form (space-separated, implicitly
# UTC, no offset). The ISO-8601/RFC3339 form (with or without an explicit
# offset, including a trailing "Z") is accepted via `datetime.fromisoformat`
# as a fallback — see `_parse_itch_created_at`.
_ITCH_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
# A purchase in either of these states was reversed after the fact: it must
# never be issued, and — per `ItchPoller.tick` — is treated as though it
# doesn't exist at all for retry purposes (the claim stays pending).
_SKIP_STATUSES = frozenset({"refunded", "canceled"})


class ItchApiError(BridgeError):
    """`api.itch.io` returned a non-200 response, or the body was unparseable."""


def _default_http_get(url: str, headers: dict[str, str]) -> bytes:
    """Real network call used when no `http_get` is injected.

    Mirrors `stripe_adapter._default_http_get`: `urlopen` never runs against
    anything but an `https://` URL, regardless of caller. A non-2xx response
    makes `urlopen` raise `urllib.error.HTTPError` (an `OSError` subclass) —
    `ItchAdapter.fetch_purchases` converts that into `ItchApiError`.
    """
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch a non-https URL: {url!r}")
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - URL validated https:// above
    with urllib.request.urlopen(request) as response:  # noqa: S310 - URL validated https:// above
        data: bytes = response.read()
        return data


def _parse_itch_created_at(raw: Any) -> str:
    """Accept itch's documented `"YYYY-MM-DD HH:MM:SS"` form or any ISO-8601
    form (with or without an explicit UTC offset); return RFC3339 `...Z`.

    Anything else is a malformed purchase input — `PurchaseRejected`, never
    signed (mirrors `StripeAdapter.normalize`'s fail-before-signing posture).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PurchaseRejected(f"itch purchase created_at is not a non-empty string: {raw!r}")
    text = raw.strip()
    try:
        parsed = datetime.strptime(text, _ITCH_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise PurchaseRejected(
                f"itch purchase created_at is not a recognized timestamp: {text!r}"
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime(_RFC3339)


class ItchAdapter:
    """itch.io `PurchaseSource`: `fetch_purchases` (the live API call) + `normalize`.

    There is no webhook signature to verify here (see module docstring) — the
    trust boundary is simply "did `api.itch.io` return this purchase for this
    (game_id, email) just now", enforced entirely by `ItchPoller.tick` calling
    `fetch_purchases` and never trusting claim/CSV data alone.
    """

    platform = "itch"

    def __init__(
        self,
        *,
        api_key: str,
        api_base: str = "https://api.itch.io",
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
    ) -> None:
        self._api_key = api_key
        self._api_base = api_base
        self._http_get = http_get if http_get is not None else _default_http_get

    def fetch_purchases(self, game_id: str, email: str) -> list[dict[str, Any]]:
        """`GET {api_base}/games/{game_id}/purchases?email=<urlencoded>`.

        THIS is the sole issuance authority (OI-4): whatever this returns is
        the only thing `ItchPoller.tick` will ever normalize and issue for.
        Any transport failure, non-200 response, or unparseable/malformed
        body becomes `ItchApiError` — never a partial or guessed result.
        """
        url = f"{self._api_base}/games/{game_id}/purchases?email={quote(email, safe='')}"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            body = self._http_get(url, headers)
        except Exception as exc:
            # Covers a non-200 status from the real `_default_http_get`
            # (`urlopen` raises `urllib.error.HTTPError` on any non-2xx
            # response) as well as any other transport failure from an
            # injected `http_get` — both are "the API call failed", which is
            # exactly the condition `ItchPoller.tick` backs off on.
            raise ItchApiError(f"itch purchases request failed: {exc}") from exc
        try:
            data = json.loads(body)
        except (ValueError, RecursionError) as exc:
            # ValueError covers json.JSONDecodeError; RecursionError covers
            # pathologically nested input — both are "bad JSON".
            raise ItchApiError(f"itch purchases response is not valid JSON: {exc}") from exc
        purchases = data.get("purchases") if isinstance(data, dict) else None
        if not isinstance(purchases, list):
            raise ItchApiError("itch purchases response has no 'purchases' list")
        return purchases

    def normalize(self, raw: dict[str, Any], *, email: str) -> NormalizedPurchase:
        """Turn one raw itch purchase dict into a `NormalizedPurchase`.

        `buyer_pubkey` is ALWAYS `None` — design decision 3: itch has no
        metadata/custom-field carrier like Stripe's checkout session, so
        every itch receipt is email-bound only, never transferable. Refund/
        cancel filtering is `ItchPoller.tick`'s job, not this method's — this
        only maps fields, it never decides whether a purchase is issuable.
        """
        purchase_id = str(raw["id"])
        game_id = raw["game_id"]
        purchased_at = _parse_itch_created_at(raw.get("created_at"))
        price = raw.get("price")
        return NormalizedPurchase(
            platform=self.platform,
            platform_purchase_id=purchase_id,
            buyer_identifier=email,
            identifier_type="email",
            buyer_pubkey=None,
            product_key=f"itch_{game_id}",
            purchased_at=purchased_at,
            amount=str(price) if price is not None else None,
            currency=raw.get("currency"),
        )


class ItchPoller:
    """Drains DUE claims once per `tick`, calling the live itch API as the
    sole issuance authority for each one (OI-4 — see module docstring).

    Concurrency (why there is no lock in this class, unlike `http.py`'s
    webhook critical section): this poller is the ONLY code path that ever
    processes `platform="itch"` purchases — there is no itch webhook, so
    nothing else can race it for an itch purchase id. Stripe's webhook lock
    (`http.py`'s `make_app`) protects `platform="stripe"` exclusively; the
    two platforms are disjoint in the Ledger's `(platform, purchase_id)` key
    space, so a tick and a concurrent Stripe webhook delivery can never
    contend for the same row, and sharing the webhook lock with the poller
    would be pointless (they never touch overlapping state). `run_forever`
    drives this class from exactly one daemon thread (`cli.py`'s `serve`),
    so within a single tick, two claims for the same (email, game) that
    surface the same purchase id are handled sequentially: the first
    iteration issues and durably records the receipt (the Ledger's
    `(platform, purchase_id)` PRIMARY KEY makes that record durable, T4), and
    the second claim's iteration sees `ledger.get_receipt` already populated
    and completes without re-issuing. The Ledger's own per-statement lock
    keeps every individual read/write atomic regardless of thread count.
    """

    def __init__(
        self,
        *,
        adapter: ItchAdapter,
        ledger: Ledger,
        core: IssuingCore,
        max_attempts: int = 10,
        backoff_base_seconds: int = 60,
    ) -> None:
        self._adapter = adapter
        self._ledger = ledger
        self._core = core
        self._max_attempts = max_attempts
        self._backoff_base_seconds = backoff_base_seconds

    def tick(self, *, now: datetime) -> None:
        """Drain every claim due at `now` (synchronous, fully testable).

        Pinned per the task brief — see the module/class docstrings for why
        the live API call is the only thing that can ever lead to
        `core.process` being invoked.
        """
        now_rfc3339 = now.strftime(_RFC3339)
        for claim in self._ledger.due_claims(now_rfc3339):
            try:
                purchases = self._adapter.fetch_purchases(claim.game_id, claim.email)
            except ItchApiError:
                self._defer_or_exhaust(claim, now)
                continue

            completed = False
            download_token: str | None = None
            for raw in purchases:
                if raw.get("status") in _SKIP_STATUSES:
                    continue
                purchase_id = str(raw["id"])
                stored = self._ledger.get_receipt("itch", purchase_id)
                if stored is None:
                    try:
                        normalized = self._adapter.normalize(raw, email=claim.email)
                        self._core.process(normalized)
                    except (PurchaseRejected, UnmappedProduct) as exc:
                        # The purchase provably existed on the API (OI-4 is
                        # satisfied) even though it can't be normalized or
                        # mapped to a catalog entry: dead-letter for operator
                        # triage, but the claim still completes below —
                        # never left pending forever for something the API
                        # already confirmed happened.
                        self._ledger.add_dead_letter(
                            "itch", purchase_id, str(exc), json.dumps(raw), now=now_rfc3339
                        )
                    else:
                        stored = self._ledger.get_receipt("itch", purchase_id)
                completed = True
                if stored is not None and download_token is None:
                    download_token = stored.download_token

            if not completed:
                # No actionable purchase this tick — either the API returned
                # zero purchases, or every one it returned was refunded/
                # canceled. Either way nothing confirms the claim yet: the
                # buyer may be claiming before the purchase settles (or
                # before a refund reverses), so retry exactly like an API
                # miss rather than stranding the claim pending forever.
                self._defer_or_exhaust(claim, now)
                continue

            self._ledger.complete_claim(claim.token, result_download_token=download_token)

    def _defer_or_exhaust(self, claim: Claim, now: datetime) -> None:
        if claim.attempts >= self._max_attempts:
            self._ledger.exhaust_claim(claim.token)
            return
        delay_seconds = self._backoff_base_seconds * (2**claim.attempts)
        next_attempt_at = (now + timedelta(seconds=delay_seconds)).strftime(_RFC3339)
        self._ledger.defer_claim(claim.token, next_attempt_at=next_attempt_at)

    def run_forever(self, stop: threading.Event, interval_seconds: int) -> None:
        """Tick once, then wait `interval_seconds` (or until `stop` fires),
        forever. `stop.wait` doubles as the sleep and the shutdown signal."""
        while not stop.is_set():
            self.tick(now=datetime.now(UTC))
            stop.wait(interval_seconds)
