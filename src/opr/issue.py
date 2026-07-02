"""Receipt issuance: assemble a payload, sign it, wrap it in an envelope (§3).

`issue()` is the "mint a receipt" path. `build_payload()` is a convenience
assembler for the §3.1 payload shape; callers may also hand-build a payload
dict and pass it straight to `issue()`. `receipt_hash()` is the §4 receipt
hash used for bundles/dedup.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from opr import canon, commitment, keys, ulid, validate

_ALG = "Ed25519"  # hard-coded — never selected from any field, see §3


class IssueError(ValueError):
    """Payload/kid combination cannot be issued as a receipt.

    `violations` carries the schema errors from `validate.validate_payload`
    when the failure was a schema violation; empty otherwise.
    """

    def __init__(self, message: str, violations: list[str] | None = None) -> None:
        super().__init__(message)
        self.violations = violations if violations is not None else []


def issue(
    payload: dict[str, Any],
    signing_kp: keys.SigningKeyPair,
    kid: str,
    *,
    salt: bytes | None = None,
    manifest_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign `payload` and return a receipt envelope.

    Order of checks (per spec): schema validity, then kid-domain match
    against `payload["issuer"]["id"]`. Only then is anything signed.
    """
    violations = validate.validate_payload(payload)
    if violations:
        raise IssueError("payload failed schema validation: " + "; ".join(violations), violations)

    issuer_id = payload["issuer"]["id"]
    kid_domain = kid.split("/")[0]
    if kid_domain != issuer_id:
        raise IssueError(
            f"kid domain {kid_domain!r} does not match payload issuer.id {issuer_id!r}"
        )

    payload_bytes = canon.canonical_bytes(payload)
    sig = keys.sign(payload_bytes, signing_kp)

    envelope: dict[str, Any] = {
        "payload": payload,
        "signatures": [{"kid": kid, "alg": _ALG, "sig": keys.b64u(sig)}],
    }

    delivery: dict[str, Any] = {}
    if salt is not None:
        delivery["salt"] = keys.b64u(salt)
    if manifest_snapshot is not None:
        delivery["issuer_manifest"] = manifest_snapshot
    if delivery:
        envelope["delivery"] = delivery

    return envelope


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payload(
    *,
    issuer_id: str,
    display_name: str,
    buyer_identifier: str,
    buyer_identifier_type: str,
    buyer_salt: bytes,
    title: str,
    publisher: str,
    identifiers: dict[str, str],
    artifact_series: str,
    terms_uri: str,
    legal_text_sha256: str,
    buyer_pubkey: bytes | None = None,
    edition: str | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    grant: str = "perpetual",
    revocability: str = "none",
    revocation_window_days: int | None = None,
    transferable: bool = False,
    drm: str = "drm-free",
    jurisdiction_flags: dict[str, bool] | None = None,
    redownload_right: bool = True,
    mirror_policy_uri: str | None = None,
    mirror_policy_sha256: str | None = None,
    end_of_life: str = "artifacts-remain-redownloadable",
    eol_commitment_uri: str | None = None,
    eol_commitment_sha256: str | None = None,
    issued_at: str | None = None,
    supersedes: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Assemble a §3.1 payload.

    Defaults are chosen so that, with only the required kwargs supplied, the
    result is a schema-valid `revocability: "none"` receipt: `drm-free`,
    `redownload_right: true`, and `artifact_series` (required, no default)
    together satisfy that class's conditional requirements. Optional string
    fields with no null in their schema type (`edition`, `mirror_policy_uri`,
    `mirror_policy_sha256`, `revocation_window_days`, `jurisdiction_flags`)
    are omitted entirely when not supplied, rather than set to `None`.
    """
    commitment_bytes = commitment.compute(buyer_identifier, buyer_identifier_type, buyer_salt)
    buyer: dict[str, Any] = {
        "commitment": keys.b64u(commitment_bytes),
        "identifier_type": buyer_identifier_type,
        "pubkey": keys.b64u(buyer_pubkey) if buyer_pubkey is not None else None,
    }

    work: dict[str, Any] = {
        "title": title,
        "publisher": publisher,
        "identifiers": identifiers,
        "artifact_series": artifact_series,
    }
    if edition is not None:
        work["edition"] = edition
    if artifacts is not None:
        work["artifacts"] = artifacts

    license_fields: dict[str, Any] = {
        "grant": grant,
        "revocability": revocability,
        "transferable": transferable,
        "drm": drm,
        "terms_uri": terms_uri,
        "legal_text_sha256": legal_text_sha256,
    }
    if revocation_window_days is not None:
        license_fields["revocation_window_days"] = revocation_window_days
    if jurisdiction_flags is not None:
        license_fields["jurisdiction_flags"] = jurisdiction_flags

    survivability: dict[str, Any] = {
        "redownload_right": redownload_right,
        "end_of_life": end_of_life,
        "eol_commitment_uri": eol_commitment_uri,
        "eol_commitment_sha256": eol_commitment_sha256,
    }
    if mirror_policy_uri is not None:
        survivability["mirror_policy_uri"] = mirror_policy_uri
    if mirror_policy_sha256 is not None:
        survivability["mirror_policy_sha256"] = mirror_policy_sha256

    return {
        "opr_version": "0.1",
        "receipt_id": receipt_id if receipt_id is not None else ulid.generate(),
        "issued_at": issued_at if issued_at is not None else _now_iso(),
        "supersedes": supersedes,
        "issuer": {"id": issuer_id, "display_name": display_name},
        "buyer": buyer,
        "work": work,
        "license": license_fields,
        "survivability": survivability,
    }


def receipt_hash(payload: dict[str, Any]) -> str:
    """`SHA-256(JCS(payload))` lowercase hex (§4) — never a hash of the envelope."""
    return hashlib.sha256(canon.canonical_bytes(payload)).hexdigest()
