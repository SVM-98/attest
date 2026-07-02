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

from typing import Any

from opr import canon, keys, manifests


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


def verify_record(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Self-consistency: `record`'s signature verifies against a key listed in
    `key_manifest`, mirroring `manifests.verify_key_manifest`'s pattern.

    Defense-in-depth like `manifests.verify_artifact_manifest`: `key_manifest`
    itself must be self-consistent, so a fabricated key manifest paired with a
    matching fabricated record signature cannot verify. Fails closed on every
    malformed/wrong-typed/unsigned input (Task 6's fix) — never raises.

    Deliberately does not gate on the signing key's `status` (active vs
    retired/compromised) — same as `verify_key_manifest`'s bare
    self-consistency check, not `verify_artifact_manifest`'s extra active+
    validity-window gate. See task-9-report.md for the reasoning and the
    resulting caveat.
    """
    if not manifests.verify_key_manifest(key_manifest):
        return False
    sig_block = record.get("signature")
    if not isinstance(sig_block, dict):
        return False
    entry = manifests.find_key(key_manifest, sig_block.get("kid", ""))
    if entry is None:
        return False
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        return keys.verify_strict(
            canon.canonical_bytes(body),
            keys.b64u_decode(sig_block["sig"]),
            keys.b64u_decode(entry["pub"]),
        )
    except (KeyError, ValueError, TypeError):
        return False
