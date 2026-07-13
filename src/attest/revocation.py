"""Revocation records — issuer-signed, revocability-class-scoped (design §3.1/§6/§8).

Minimal by design (§8): a record carries only `receipt_id`, `status`,
`revoked_at`, and the issuer's signature over the rest — signed exactly like
receipts and manifests (Ed25519 over `canon.canonical_bytes(record)` with
the `signature` member itself excluded from the signed body).

This module only builds records and checks a record's own signature
self-consistency against an issuer's key manifest. It has no opinion on
whether a given record is *effective* against a given receipt — that is a
function of the receipt's `license.revocability` class (none/refund_window/
policy), which needs both the record and the receipt payload in hand, so it
lives in `verify.py` (§6 step 6), the one module that has both.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from attest import canon, keys, manifests

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def build_record(
    receipt_id: str,
    status: str,
    revoked_at: str,
    signing_kp: keys.SigningKeyPair,
    kid: str,
) -> dict[str, Any]:
    """Build an issuer-signed revocation record `{receipt_id, status, revoked_at, signature}`."""
    record: dict[str, Any] = {
        "receipt_id": receipt_id,
        "status": status,
        "revoked_at": revoked_at,
    }
    sig = keys.sign(canon.canonical_bytes(record), signing_kp)
    record["signature"] = {"kid": kid, "sig": keys.b64u(sig)}
    return record


def verify_record_signature(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify `record`'s own signature against an ALREADY self-verified `key_manifest`.

    Exactly `verify_record` minus the `manifests.verify_key_manifest`
    self-consistency check: the signer key must be **active** in
    `key_manifest`, with its `[valid_from, valid_to]` window covering the
    record's own signed `revoked_at`, and the signature must verify against
    that key's `pub`. Fails closed on every malformed/wrong-typed/unsigned/
    out-of-window input — never raises.

    PRECONDITION: the caller has already established
    `manifests.verify_key_manifest(key_manifest)` is True. Callers checking
    many records against ONE manifest hoist that call out of their loop —
    one manifest self-verify per classification, not per record (review
    improvement #17). To verify a single record, use `verify_record`,
    which composes both halves.
    """
    sig_block = record.get("signature")
    if not isinstance(sig_block, dict):
        return False
    entry = manifests.find_key(key_manifest, sig_block.get("kid", ""))
    if entry is None or entry.get("status") != _ACTIVE:
        return False
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        revoked_at = _parse_date(record["revoked_at"])
        if revoked_at < _parse_date(entry["valid_from"]):
            return False
        valid_to = entry.get("valid_to")
        if valid_to is not None and revoked_at > _parse_date(valid_to):
            return False
        return keys.verify_strict(
            canon.canonical_bytes(body),
            keys.b64u_decode(sig_block["sig"]),
            keys.b64u_decode(entry["pub"]),
        )
    except (KeyError, ValueError, TypeError):
        return False


def verify_record(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify against `key_manifest`, mirroring `manifests.verify_artifact_manifest`
    exactly: the signer key must be **active** in a self-consistent
    `key_manifest`, with its `[valid_from, valid_to]` window covering the
    record's own signed `revoked_at`, and the signature must verify.

    A revocation record is a NEW side-document issued at revoke-time, so §5's
    lifecycle rules bite: a `compromised` key's signatures are ALL invalid,
    and a `retired` key can no longer sign new documents — both are rejected
    (only `status == "active"` passes). The window is checked against the
    record's own signed `revoked_at`, never the local clock, using the same
    date-parse + fail-closed handling as `verify_artifact_manifest` / §6 step 3.

    Defense-in-depth: `key_manifest` itself must be self-consistent, so a
    fabricated key manifest paired with a matching fabricated record signature
    cannot verify. Fails closed on every malformed/wrong-typed/unsigned/
    out-of-window input — never raises (Task 6's fix, extended by the Task 9
    hardening review). Composes `manifests.verify_key_manifest` +
    `verify_record_signature`; loop-over-records callers hoist the former.
    """
    return manifests.verify_key_manifest(key_manifest) and verify_record_signature(
        record, key_manifest
    )
