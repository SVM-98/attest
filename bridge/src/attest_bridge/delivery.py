"""Delivery: merchant SMTP send of a signed receipt, or a zero-config
download-link fallback.

Contract (the task brief, Global Constraint 9 — `docs/plans/
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
`smtp_password` — only a sanitized summary (the exception CATEGORY and, for an
SMTP response error, its numeric reply code). It never includes `str(exc)`,
whose text can echo a server-returned response or the submitted message and so
could carry a secret back to the caller and into the Ledger's
`last_delivery_error`.
"""

from __future__ import annotations

import json
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from attest_bridge.config import DeliveryConfig

_SMTP_SSL_PORT = 465

SMTPFactory = Callable[[str, int], smtplib.SMTP]


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    status: str  # "sent" | "skipped_no_smtp" | "failed"
    detail: str | None


def _default_smtp_factory(host: str, port: int) -> smtplib.SMTP:
    if port == _SMTP_SSL_PORT:
        return smtplib.SMTP_SSL(host, port, context=ssl.create_default_context())
    return smtplib.SMTP(host, port)


def _safe_detail(exc: Exception) -> str:
    """A delivery-failure summary safe to surface and persist.

    Only the exception category and, for an SMTP response error, its numeric
    reply code (a fixed protocol integer). NEVER `str(exc)`: on smtplib/ssl
    errors that text can echo a server-returned response or the message this
    module submitted, so it could carry `smtp_password` or envelope content
    back to the caller and into the Ledger.
    """
    category = type(exc).__name__
    code = getattr(exc, "smtp_code", None)
    if isinstance(code, int):
        return f"{category} (SMTP code {code})"
    return category


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
