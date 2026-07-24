"""Delivery: merchant SMTP send of a signed receipt, or a zero-config
download-link fallback.

Contract (task-6-brief.md, Global Constraint 9 — `docs/superpowers/plans/
2026-07-24-p2.1-webhook-bridge.md`): by the time `Delivery.send` is ever
called, `IssuingCore.process` has already issued and durably recorded the
receipt in the Ledger — a delivery failure never loses it. So `send` NEVER
raises: any `smtplib`/`ssl`/`OSError` from the network becomes a
`DeliveryResult("failed", <safe detail>)`, never an exception the caller must
catch. `config is None` (no `[delivery]` section configured) means the
download link IS the delivery — `send` returns `skipped_no_smtp` and
`smtp_factory` is never invoked.

Transport policy (Global Constraint 10 — a salt-bearing envelope is a
secret, TLS-only in transit): `smtp_port == 465` selects `smtplib.SMTP_SSL`
(encrypted from the first byte); any other port selects `smtplib.SMTP` and
this module ALWAYS calls `starttls(context=ssl.create_default_context())`
before login/send — plaintext SMTP is refused outright, there is no code
path that sends over a cleartext channel. `smtp_factory` injection (defaults
to the real dispatch above) is what makes this testable without a network.

`DeliveryResult.detail` never carries the envelope, the salt, or
`smtp_password` — only a hardcoded failure label (see `_safe_detail`) plus an
exact-int SMTP reply code. It is derived from a trusted type table, never from
the exception's own text or metadata, so no server-returned response or
submitted message can leak into the caller or the Ledger's
`last_delivery_error`.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from attest_bridge.config import DeliveryConfig
from attest_bridge.ledger import Ledger

_SMTP_SSL_PORT = 465
MAX_DELIVERY_ATTEMPTS = 10
DELIVERY_SWEEP_SECONDS = 300
_SWEEP_LOCK = threading.Lock()

SMTPFactory = Callable[[str, int], smtplib.SMTP]


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    status: str  # "sent" | "skipped_no_smtp" | "failed"
    detail: str | None


def _default_smtp_factory(host: str, port: int) -> smtplib.SMTP:
    if port == _SMTP_SSL_PORT:
        return smtplib.SMTP_SSL(host, port, context=ssl.create_default_context())
    return smtplib.SMTP(host, port)


_GENERIC_FAILURE = "delivery failed"

# Hardcoded (type -> label) table, most-specific first. `_safe_detail` returns
# ONLY a literal from this table (optionally plus an exact-int SMTP code) —
# never anything derived from the exception object's own __name__/__str__/
# __format__, which a hostile exception class or metaclass could control to
# raise or echo server-returned secret text.
_FAILURE_LABELS: tuple[tuple[type[BaseException], str], ...] = (
    (smtplib.SMTPAuthenticationError, "smtp auth failed"),
    (smtplib.SMTPServerDisconnected, "smtp server disconnected"),
    (smtplib.SMTPResponseException, "smtp error"),
    (smtplib.SMTPException, "smtp error"),
    (ssl.SSLError, "tls error"),
    (ConnectionRefusedError, "connection refused"),
    (TimeoutError, "timeout"),
    (OSError, "network error"),
    (ValueError, "invalid message"),
    (TypeError, "invalid message"),
)


def _safe_detail(exc: Exception) -> str:
    """A delivery-failure summary safe to surface and persist.

    Runs from send()'s except handler, so it must NEVER raise and NEVER surface
    attacker-controlled content. It returns only a hardcoded label chosen by
    isinstance-matching `exc` against a fixed table of trusted stdlib types,
    optionally suffixed with an EXACT built-in `int` SMTP code — never
    `str(exc)`, and never the exception's own `__name__`/`__str__`/`__format__`
    (a hostile class or metaclass could make those raise or echo a
    server-returned response carrying `smtp_password` or envelope content). Any
    surprise falls back to the generic constant.
    """
    try:
        label = _GENERIC_FAILURE
        for known, known_label in _FAILURE_LABELS:
            if isinstance(exc, known):
                label = known_label
                break
        code = getattr(exc, "smtp_code", None)
        if type(code) is int:
            return f"{label} (SMTP code {code})"
        return label
    except Exception:
        return _GENERIC_FAILURE


def _build_message(
    *,
    config: DeliveryConfig,
    to_email: str,
    receipt_id: str,
    work_title: str,
    envelope: dict[str, Any],
    download_url: str,
    info_url: str | None,
) -> EmailMessage:
    effective_info_url = info_url if info_url is not None else config.info_url

    message = EmailMessage()
    message["Subject"] = f"Your receipt for {work_title}"
    message["From"] = config.from_address
    message["To"] = to_email
    message.set_content(
        "\n".join(
            [
                f"Your receipt for {work_title} is ready.",
                "",
                f"Download it here: {download_url}",
                "",
                f"What is this file? {effective_info_url}",
            ]
        )
    )
    message.add_attachment(
        json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8"),
        maintype="application",
        subtype="json",
        filename=f"receipt-{receipt_id}.attest",
    )
    return message


class Delivery:
    """Merchant SMTP delivery, TLS-only, with a zero-config download-link fallback."""

    def __init__(
        self,
        config: DeliveryConfig | None,
        smtp_factory: SMTPFactory | None = None,
    ) -> None:
        self._config = config
        self._smtp_factory: SMTPFactory = (
            smtp_factory if smtp_factory is not None else _default_smtp_factory
        )

    @property
    def configured(self) -> bool:
        """Whether SMTP delivery is configured for this process."""
        return self._config is not None

    def send(
        self,
        *,
        to_email: str,
        receipt_id: str,
        work_title: str,
        envelope: dict[str, Any],
        download_url: str,
        info_url: str | None,
    ) -> DeliveryResult:
        """Send the receipt by email, or report `skipped_no_smtp` in zero-config mode.

        NEVER raises: the receipt is already safe in the Ledger by the time
        this is called (Global Constraint 9), so any transport failure is
        reported as a `DeliveryResult`, not an exception.
        """
        config = self._config
        if config is None:
            return DeliveryResult(status="skipped_no_smtp", detail=None)

        # NEVER-RAISE contract (load-bearing): the receipt is already durably
        # recorded before this runs (Global Constraint 9), so EVERY failure —
        # message construction (a header-injecting title/address -> ValueError,
        # a non-serializable envelope -> TypeError), the SMTP factory, TLS,
        # login, or send, INCLUDING exceptions outside SMTPException/OSError —
        # is converted to a failed result, never propagated. `except Exception`
        # is deliberate; BaseException (KeyboardInterrupt/SystemExit) still
        # propagates.
        try:
            message = _build_message(
                config=config,
                to_email=to_email,
                receipt_id=receipt_id,
                work_title=work_title,
                envelope=envelope,
                download_url=download_url,
                info_url=info_url,
            )
            smtp = self._smtp_factory(config.smtp_host, config.smtp_port)
            with smtp:
                if config.smtp_port != _SMTP_SSL_PORT:
                    # Mandatory STARTTLS on every non-465 port: no cleartext
                    # channel ever carries the salt-bearing envelope.
                    smtp.starttls(context=ssl.create_default_context())
                smtp.login(config.smtp_username, config.smtp_password)
                smtp.send_message(message)
        except Exception as exc:
            return DeliveryResult(status="failed", detail=_safe_detail(exc))
        return DeliveryResult(status="sent", detail=None)


def sweep_undelivered(
    *, ledger: Ledger, delivery: Delivery, public_base_url: str
) -> tuple[int, int]:
    """Retry undelivered receipts without letting one row abort the sweep.

    Delivery is at-least-once: a crash after SMTP accepts a message but before
    `mark_delivered` can resend the same stored envelope. It is never
    re-issued, and rows at the attempt cap remain operator-visible. Sweeps are
    serialized only within this process; across processes delivery can overlap
    and the attempt cap is therefore a per-process bound, not a global one.
    """
    delivered = 0
    failed_or_skipped = 0
    if isinstance(delivery, Delivery) and not delivery.configured:
        return delivered, failed_or_skipped
    with _SWEEP_LOCK:
        for candidate in ledger.undelivered():
            # The snapshot selects candidates only. State deciding whether to
            # send must be current so overlapping in-process callers cannot
            # send a row that another sweep already delivered or capped.
            stored = ledger.get_receipt(candidate.platform, candidate.purchase_id)
            if (
                stored is None
                or stored.delivered_at is not None
                or stored.delivery_attempts >= MAX_DELIVERY_ATTEMPTS
            ):
                continue
            try:
                envelope = json.loads(stored.envelope_json)
                payload = envelope.get("payload")
                work = payload.get("work") if isinstance(payload, dict) else None
                title = work.get("title") if isinstance(work, dict) else None
                if not isinstance(title, str):
                    raise ValueError("stored receipt has no work title")
                result = delivery.send(
                    to_email=stored.buyer_email,
                    receipt_id=stored.receipt_id,
                    work_title=title,
                    envelope=envelope,
                    download_url=f"{public_base_url}/r/{stored.download_token}",
                    info_url=None,
                )
                if result.status == "sent":
                    from datetime import UTC, datetime

                    ledger.mark_delivered(
                        stored.platform,
                        stored.purchase_id,
                        at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    )
                    delivered += 1
                elif result.status == "failed":
                    ledger.record_delivery_failure(
                        stored.platform,
                        stored.purchase_id,
                        result.detail if result.detail is not None else "delivery failed",
                    )
                    failed_or_skipped += 1
                else:
                    failed_or_skipped += 1
            except Exception:
                try:
                    ledger.record_delivery_failure(
                        stored.platform, stored.purchase_id, "delivery sweep failed"
                    )
                except Exception:
                    failed_or_skipped += 1
                    continue
                failed_or_skipped += 1
    return delivered, failed_or_skipped
