"""Delivery: merchant SMTP send + zero-config download-link fallback.

No real network: `_FakeSMTP` is injected via `smtp_factory` and records every
call the transport policy makes (`starttls`/`login`/`send_message`/`quit`),
including the context-manager protocol `Delivery.send` relies on.
"""

from __future__ import annotations

import json
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import pytest
from attest_bridge.config import DeliveryConfig
from attest_bridge.delivery import Delivery, DeliveryResult

_ENVELOPE: dict[str, Any] = {
    "payload": {"receipt_id": "r_test_0001", "work": {"title": "Stardrift Chronicles"}},
    "delivery": {"salt": "not-a-real-secret-but-treat-it-like-one"},
    "signatures": {"ed25519": "deadbeef"},
}


class _FakeSMTP:
    """Records starttls/login/send_message/quit calls; supports `with`."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.starttls_calls: list[ssl.SSLContext | None] = []
        self.login_calls: list[tuple[str, str]] = []
        self.sent_messages: list[EmailMessage] = []
        self.quit_called = False

    def starttls(self, *, context: ssl.SSLContext | None = None) -> None:
        self.starttls_calls.append(context)

    def login(self, username: str, password: str) -> None:
        self.login_calls.append((username, password))

    def send_message(self, message: EmailMessage) -> None:
        self.sent_messages.append(message)

    def quit(self) -> None:
        self.quit_called = True

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.quit()


class _RaisingSMTP(_FakeSMTP):
    """A fake whose login raises, to exercise the never-raise contract."""

    def __init__(self, host: str, port: int, exc: Exception) -> None:
        super().__init__(host, port)
        self._exc = exc

    def login(self, username: str, password: str) -> None:
        raise self._exc


class _RaisingSmtpCode(smtplib.SMTPException):
    """An SMTP exception whose `smtp_code` accessor itself raises — _safe_detail
    must not let that new exception escape send()."""

    @property
    def smtp_code(self) -> int:
        raise RuntimeError("hostile accessor")


class _HostileInt(int):
    """An int subclass whose formatting emits attacker-controlled text — must
    never reach the sanitized detail (only an EXACT built-in int is formatted)."""

    def __format__(self, spec: str) -> str:
        return "HOSTILE-FORMAT-LEAK"

    def __str__(self) -> str:
        return "HOSTILE-FORMAT-LEAK"


class _HostileCodeException(smtplib.SMTPException):
    smtp_code = _HostileInt(535)


class _HostileNameException(smtplib.SMTPException):
    """Its class __name__ is set to attacker-controlled text below — the
    sanitized detail must come from the trusted type table, not __name__."""


_HostileNameException.__name__ = "HOSTILE-NAME-LEAK"


def _config(*, port: int = 587) -> DeliveryConfig:
    return DeliveryConfig(
        smtp_host="smtp.example.com",
        smtp_port=port,
        smtp_username="merchant",
        smtp_password="hunter2-super-secret",  # noqa: S106 - test fixture, not a real secret
        from_address="receipts@merchant.example.com",
        info_url="https://merchant.example.com/attest/what-is-this",
    )


def _fake_factory(store: list[_FakeSMTP]) -> Any:
    def factory(host: str, port: int) -> _FakeSMTP:
        fake = _FakeSMTP(host, port)
        store.append(fake)
        return fake

    return factory


def _send(
    config: DeliveryConfig,
    factory: Any,
    *,
    info_url: str | None = None,
    envelope: dict[str, Any] | None = None,
) -> DeliveryResult:
    delivery = Delivery(config, smtp_factory=factory)
    return delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=envelope if envelope is not None else _ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=info_url,
    )


# -- message shape --------------------------------------------------------


def test_send_sets_subject_from_and_to() -> None:
    fakes: list[_FakeSMTP] = []
    result = _send(_config(), _fake_factory(fakes))
    assert result.status == "sent"
    message = fakes[0].sent_messages[0]
    assert message["Subject"] == "Your receipt for Stardrift Chronicles"
    assert message["From"] == "receipts@merchant.example.com"
    assert message["To"] == "buyer@example.com"


def test_send_attachment_filename_and_json_content_roundtrips_envelope() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes))
    message = fakes[0].sent_messages[0]
    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment.get_filename() == "receipt-r_test_0001.attest"
    assert attachment.get_content_type() == "application/json"
    payload_bytes = attachment.get_content()
    if isinstance(payload_bytes, str):
        payload_bytes = payload_bytes.encode("utf-8")
    assert json.loads(payload_bytes) == _ENVELOPE
    # exact serialization the brief pins: indent=2, sorted keys.
    assert payload_bytes.decode("utf-8") == json.dumps(_ENVELOPE, indent=2, sort_keys=True)


def test_send_body_contains_download_url_and_configured_info_url() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes), info_url=None)
    message = fakes[0].sent_messages[0]
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()
    assert "https://receipts.example.com/r/tok_abc123" in text
    assert "https://merchant.example.com/attest/what-is-this" in text


def test_send_body_uses_explicit_info_url_override_when_given() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes), info_url="https://override.example.com/info")
    message = fakes[0].sent_messages[0]
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()
    assert "https://override.example.com/info" in text
    assert "https://merchant.example.com/attest/what-is-this" not in text


def test_send_never_puts_the_smtp_password_in_the_outgoing_message() -> None:
    # The envelope (and its embedded salt) legitimately IS the attachment —
    # that is delivery working as designed (Global Constraint 10: the buyer
    # needs their own salt to verify offline). `smtp_password` is the one
    # secret here that must never reach the wire in the message itself.
    fakes: list[_FakeSMTP] = []
    config = _config()
    _send(config, _fake_factory(fakes))
    raw = bytes(fakes[0].sent_messages[0]).decode("utf-8", errors="replace")
    assert config.smtp_password not in raw


# -- transport policy: TLS-only, mandatory STARTTLS on non-465 ------------


def test_starttls_is_called_with_ssl_context_on_port_587() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(port=587), _fake_factory(fakes))
    fake = fakes[0]
    assert len(fake.starttls_calls) == 1
    assert isinstance(fake.starttls_calls[0], ssl.SSLContext)


def test_no_starttls_call_on_port_465_ssl_path() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(port=465), _fake_factory(fakes))
    fake = fakes[0]
    assert fake.starttls_calls == []


def test_login_and_send_message_and_quit_are_called() -> None:
    fakes: list[_FakeSMTP] = []
    config = _config()
    _send(config, _fake_factory(fakes))
    fake = fakes[0]
    assert fake.login_calls == [(config.smtp_username, config.smtp_password)]
    assert len(fake.sent_messages) == 1
    assert fake.quit_called is True


def test_default_factory_uses_smtp_ssl_for_port_465(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []

    class _RecordingSSL(_FakeSMTP):
        def __init__(self, host: str, port: int, *, context: ssl.SSLContext) -> None:
            super().__init__(host, port)
            calls.append((host, port))
            assert isinstance(context, ssl.SSLContext)

    def _boom_smtp(host: str, port: int) -> _FakeSMTP:
        raise AssertionError("smtplib.SMTP must not be used for port 465")

    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSSL)
    monkeypatch.setattr(smtplib, "SMTP", _boom_smtp)
    delivery = Delivery(_config(port=465))  # no smtp_factory injected -> default factory
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result.status == "sent"
    assert calls == [("smtp.example.com", 465)]


def test_default_factory_uses_smtp_with_starttls_for_non_465_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    class _RecordingSMTP(_FakeSMTP):
        def __init__(self, host: str, port: int) -> None:
            super().__init__(host, port)
            calls.append((host, port))

    def _boom_ssl(host: str, port: int, *, context: ssl.SSLContext) -> _FakeSMTP:
        raise AssertionError("smtplib.SMTP_SSL must not be used for a non-465 port")

    monkeypatch.setattr(smtplib, "SMTP", _RecordingSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _boom_ssl)
    delivery = Delivery(_config(port=587))
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result.status == "sent"
    assert calls == [("smtp.example.com", 587)]


# -- never-raise contract --------------------------------------------------


def test_smtp_exception_from_login_becomes_failed_result_not_a_raise() -> None:
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, smtplib.SMTPAuthenticationError(535, b"bad creds"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "smtp auth failed (SMTP code 535)"


def test_os_error_from_login_becomes_failed_result_not_a_raise() -> None:
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, ConnectionRefusedError("connection refused"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "connection refused"


def test_failed_detail_never_contains_the_smtp_password_or_envelope_content() -> None:
    config = _config()
    # Simulate a server/transport whose exception TEXT echoes the submitted
    # password and message content — the sanitized detail must exclude both
    # (only the exception category + numeric SMTP code are safe to surface).
    leaky = smtplib.SMTPException(
        f"535 auth failed: password {config.smtp_password} "
        "body=not-a-real-secret-but-treat-it-like-one"
    )

    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, leaky)

    result = _send(config, factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert config.smtp_password not in result.detail
    assert "not-a-real-secret-but-treat-it-like-one" not in result.detail
    assert result.detail == "smtp error"  # hardcoded label, no server text


def test_factory_raising_on_connect_becomes_failed_result() -> None:
    def factory(host: str, port: int) -> _FakeSMTP:
        raise OSError("no route to host")

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "network error"


def test_non_smtp_transport_exception_becomes_failed_result_not_a_raise() -> None:
    # A transport failure outside SMTPException/OSError (e.g. RuntimeError) must
    # still be converted, not escape — the narrow (SMTPException, OSError) catch
    # was insufficient for the load-bearing never-raise contract.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, RuntimeError("unexpected transport state"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "delivery failed"


def test_message_construction_failure_becomes_failed_result_not_a_raise() -> None:
    # _build_message runs INSIDE the guarded block: a non-serializable envelope
    # (json.dumps -> TypeError) must become a failed result, and the transport
    # is never reached.
    fakes: list[_FakeSMTP] = []
    result = _send(_config(), _fake_factory(fakes), envelope={"bad": object()})
    assert result.status == "failed"
    assert result.detail == "invalid message"
    assert fakes == []


def test_safe_detail_hostile_smtp_code_accessor_never_escapes() -> None:
    # A hostile exception whose smtp_code property raises must not turn into a
    # raise out of send() — _safe_detail falls back to a constant.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _RaisingSmtpCode("auth failed"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "delivery failed"


def test_safe_detail_hostile_int_subclass_code_is_not_formatted() -> None:
    # An int-subclass smtp_code with attacker-controlled formatting must never
    # reach the detail: only an EXACT built-in int is formatted, so this falls
    # back to the bare category.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _HostileCodeException("auth failed"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert "HOSTILE-FORMAT-LEAK" not in result.detail
    assert result.detail == "smtp error"  # hardcoded label; subclass code rejected


def test_safe_detail_hostile_class_name_metadata_is_not_surfaced() -> None:
    # A class whose __name__ is attacker-controlled text must not reach the
    # detail: the label comes from a trusted type table via isinstance, never
    # from type(exc).__name__.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _HostileNameException("boom"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert "HOSTILE-NAME-LEAK" not in result.detail
    assert result.detail == "smtp error"


# -- zero-config fallback ---------------------------------------------------


def test_config_none_returns_skipped_no_smtp_and_never_calls_factory() -> None:
    factory_calls: list[tuple[str, int]] = []

    def factory(host: str, port: int) -> _FakeSMTP:
        factory_calls.append((host, port))
        return _FakeSMTP(host, port)

    delivery = Delivery(None, smtp_factory=factory)
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result == DeliveryResult(status="skipped_no_smtp", detail=None)
    assert factory_calls == []
