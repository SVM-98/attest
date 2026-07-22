"""Revocation records — issuer-signed, revocability-class-scoped (design §3.1/§6/§8).

Minimal by design (§8): a record carries only `receipt_id`, `status`,
`revoked_at`, and the issuer's signature over the rest — signed exactly like
receipts and manifests (Ed25519 over `canon.canonical_bytes(record)` with
the `signature` member itself excluded from the signed body). A hybrid
signer (v0.2 profile, `pq.HybridSigningKeys`) adds a second `sig_ml_dsa_65`
leg over the same bytes, AND-verified fail-closed exactly like key and
artifact manifests — see `manifests.sign_signature_block`/
`verify_signature_block`.

This module only builds records and checks a record's own signature
self-consistency against an issuer's key manifest. It has no opinion on
whether a given record is *effective* against a given receipt — that is a
function of the receipt's `license.revocability` class (none/refund_window/
policy), which needs both the record and the receipt payload in hand, so it
lives in `verify.py` (§6 step 6), the one module that has both.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from attest import canon, keys, manifests, pq

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def build_record(
    receipt_id: str,
    status: str,
    revoked_at: str,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
) -> dict[str, Any]:
    """Build an issuer-signed revocation record `{receipt_id, status, revoked_at, signature}`.

    `signing_kp` mirrors `manifests.build_key_manifest`: a `pq.HybridSigningKeys`
    produces a `signature` block with both the Ed25519 `sig` leg and the
    `sig_ml_dsa_65` leg (see `manifests.sign_signature_block`); a plain
    `keys.SigningKeyPair` keeps the v0.1 Ed25519-only shape unchanged.
    """
    record: dict[str, Any] = {
        "receipt_id": receipt_id,
        "status": status,
        "revoked_at": revoked_at,
    }
    record["signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(record), signing_kp, kid
    )
    return record


def record_hash(record: dict[str, Any]) -> str:
    """`SHA-256(JCS(record))`, rendered as 64 lowercase hex characters — the
    ENTIRE signed record dict, INCLUDING its `signature` member (unlike the
    body-only bytes `verify_record_signature` hashes to check the signature
    itself).

    This is what a `revocation-record` transparency-log entry commits to
    (v0.2 §8, G5): the SAME `canon.canonical_bytes` this module already uses
    to build and verify a record's signature — one canonical form, reused,
    never a second one invented for the log. `tlog.encode_entry` validates
    the resulting hex string's shape; this function does no shape validation
    of its own, mirroring how `manifests.py`/`verify.py` compute a
    `manifest_sha256`/`core_sha256` from trusted, already-built material.
    """
    return hashlib.sha256(canon.canonical_bytes(record)).hexdigest()


def verify_record_signature(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify `record`'s own signature against an ALREADY self-verified `key_manifest`.

    Exactly `verify_record` minus the `manifests.verify_key_manifest`
    self-consistency check: the signer key must be **active** in
    `key_manifest`, with its `[valid_from, valid_to]` window covering the
    record's own signed `revoked_at`, and the signature must verify against
    that key's `pub`. Fails closed on every malformed/wrong-typed/unsigned/
    out-of-window input — never raises.

    AND rule (v0.2, mirrors `manifests.verify_key_manifest`): if the signer's
    `key_manifest` entry is hybrid (carries `pub_ml_dsa_65`), `signature` MUST
    also carry a valid `sig_ml_dsa_65` leg over the same signed bytes, or
    verification fails closed; an Ed25519-only entry with a stray
    `sig_ml_dsa_65` leg likewise fails closed (see
    `manifests.verify_signature_block`). Ed25519-only signers keep v0.1
    behavior byte-for-byte.

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
        return manifests.verify_signature_block(canon.canonical_bytes(body), sig_block, entry)
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
