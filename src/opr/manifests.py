"""Issuer key manifests and artifact manifests — key lifecycle and rotation continuity (design §5).

Manifest signing input is defined exactly like receipts: Ed25519 over
`JCS(manifest)` with the `manifest_signature` member removed — every key's
`kid`, `pub`, `valid_from`, `valid_to`, `status` sits inside the signed
object, so nothing about a key's lifecycle is tamperable without breaking
the signature.

Scope: this module verifies *self-consistency* (a manifest's own signature
against its own listed keys) and the *rotation-continuity* predicate between
two already-self-consistent manifests. It does not decide whether a manifest
is itself trusted (TOFU bootstrap, `unverified_rotation` labeling) — that
trust-store logic belongs to `verify.py`. Likewise, fail-closed `compromised`
handling against *receipts* (a compromised key invalidates all its past
signatures regardless of `issued_at`) is `verify.py`'s concern; here a
`compromised`/`retired` key is simply not `active`, which is sufficient to
model key lifecycle honestly at the manifest level.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from opr import canon, keys

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _signable(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "manifest_signature"}
    return canon.canonical_bytes(body)


def key_entry(
    kid: str,
    pub: bytes,
    valid_from: str,
    valid_to: str | None = None,
    status: str = _ACTIVE,
) -> dict[str, Any]:
    """Build one `keys[]` entry. `pub` is raw 32-byte Ed25519 public key bytes."""
    return {
        "kid": kid,
        "pub": keys.b64u(pub),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "status": status,
    }


def find_key(manifest: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the `keys[]` entry with the given `kid`, or None if absent."""
    entries: list[dict[str, Any]] = manifest.get("keys", [])
    for entry in entries:
        if entry.get("kid") == kid:
            return entry
    return None


def build_key_manifest(
    issuer: str,
    manifest_version: int,
    issued_at: str,
    key_entries: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair,
    signing_kid: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "issuer": issuer,
        "manifest_version": manifest_version,
        "issued_at": issued_at,
        "keys": key_entries,
    }
    sig = keys.sign(_signable(manifest), signing_kp)
    manifest["manifest_signature"] = {"kid": signing_kid, "sig": keys.b64u(sig)}
    return manifest


def verify_key_manifest(manifest: dict[str, Any]) -> bool:
    """Self-consistency: signature verifies with a key listed in the manifest itself."""
    sig_block = manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    entry = find_key(manifest, sig_block.get("kid", ""))
    if entry is None:
        return False
    try:
        return keys.verify_strict(
            _signable(manifest), keys.b64u_decode(sig_block["sig"]), keys.b64u_decode(entry["pub"])
        )
    except (KeyError, ValueError):
        return False


def check_continuity(trusted: dict[str, Any], candidate: dict[str, Any]) -> bool:
    """True iff `candidate` (version `trusted`+1) was signed by a key `active` in `trusted`.

    Both manifests must be self-consistent and share `issuer`. Version gaps
    (N -> N+2 direct) are discontinuous by construction: only a direct
    successor is accepted here, so bridging a gap requires validating every
    intermediate manifest via repeated calls.
    """
    if not verify_key_manifest(trusted) or not verify_key_manifest(candidate):
        return False
    if trusted.get("issuer") != candidate.get("issuer"):
        return False
    try:
        if candidate["manifest_version"] != trusted["manifest_version"] + 1:
            return False
        signer_kid = candidate["manifest_signature"]["kid"]
    except (KeyError, TypeError):
        return False
    signer_entry = find_key(trusted, signer_kid)
    return signer_entry is not None and signer_entry.get("status") == _ACTIVE


def build_artifact_manifest(
    issuer: str,
    series: str,
    version: int,
    released_at: str,
    artifacts: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair,
    signing_kid: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "issuer": issuer,
        "series": series,
        "version": version,
        "released_at": released_at,
        "artifacts": artifacts,
    }
    sig = keys.sign(_signable(manifest), signing_kp)
    manifest["manifest_signature"] = {"kid": signing_kid, "sig": keys.b64u(sig)}
    return manifest


def verify_artifact_manifest(manifest: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify against `key_manifest`: signer must be `active` there, with `released_at`
    covered by the signer key's `[valid_from, valid_to]` window, and issuers must match."""
    sig_block = manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    if manifest.get("issuer") != key_manifest.get("issuer"):
        return False
    entry = find_key(key_manifest, sig_block.get("kid", ""))
    if entry is None or entry.get("status") != _ACTIVE:
        return False
    try:
        released_at = _parse_date(manifest["released_at"])
        if released_at < _parse_date(entry["valid_from"]):
            return False
        valid_to = entry.get("valid_to")
        if valid_to is not None and released_at > _parse_date(valid_to):
            return False
        return keys.verify_strict(
            _signable(manifest), keys.b64u_decode(sig_block["sig"]), keys.b64u_decode(entry["pub"])
        )
    except (KeyError, ValueError):
        return False
