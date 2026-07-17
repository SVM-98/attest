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

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from attest import canon, keys, pq

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"
_RETIRED = "retired"
_COMPROMISED = "compromised"


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _within_window(issued_at: object, entry: dict[str, Any]) -> bool:
    """Fail-closed: `issued_at` (a str) falls within the key entry's
    [valid_from, valid_to] window. Any malformed/missing bound → False."""
    if not isinstance(issued_at, str):
        return False
    try:
        issued = _parse_date(issued_at)
        valid_from = _parse_date(entry["valid_from"])
    except (KeyError, TypeError, ValueError):
        return False
    if issued < valid_from:
        return False
    valid_to = entry.get("valid_to")
    if valid_to is None:
        return True
    try:
        return issued <= _parse_date(valid_to)
    except (TypeError, ValueError):
        return False


def _signable(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "manifest_signature"}
    return canon.canonical_bytes(body)


def key_entry(
    kid: str,
    pub: bytes,
    valid_from: str,
    valid_to: str | None = None,
    status: str = _ACTIVE,
    pub_ml_dsa_65: bytes | None = None,
) -> dict[str, Any]:
    """Build one `keys[]` entry. `pub` is raw 32-byte Ed25519 public key bytes.

    Passing `pub_ml_dsa_65` (raw ML-DSA-65 public key bytes) marks the entry
    hybrid: a manifest signed by this key must carry both signature legs
    (see `build_key_manifest`/`verify_key_manifest`).
    """
    entry: dict[str, Any] = {
        "kid": kid,
        "pub": keys.b64u(pub),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "status": status,
    }
    if pub_ml_dsa_65 is not None:
        entry["pub_ml_dsa_65"] = keys.b64u(pub_ml_dsa_65)
    return entry


def find_key(manifest: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the `keys[]` entry with the given `kid`, or None if absent."""
    entries = manifest.get("keys", [])
    if not isinstance(entries, list):
        return None
    for entry in entries:
        # Tolerate a malformed keys[] member (e.g. `keys: [null]`) instead of
        # crashing the caller's verification (2026-07-13 review, finding 11).
        if isinstance(entry, dict) and entry.get("kid") == kid:
            return entry
    return None


def _sign_manifest(
    manifest: dict[str, Any],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
) -> dict[str, Any]:
    """Build the `manifest_signature` block for `manifest` (mutates nothing —
    the caller inserts the returned block).

    Hybrid signing keys (`pq.HybridSigningKeys`) add a second `sig_ml_dsa_65`
    leg over the same signable bytes as the Ed25519 `sig` leg.
    """
    payload = _signable(manifest)
    if isinstance(signing_kp, pq.HybridSigningKeys):
        ed_sig = keys.sign(payload, signing_kp.ed)
        mldsa_sig = pq.sign(payload, signing_kp.mldsa)
        return {
            "kid": signing_kid,
            "sig": keys.b64u(ed_sig),
            "sig_ml_dsa_65": keys.b64u(mldsa_sig),
        }
    sig = keys.sign(payload, signing_kp)
    return {"kid": signing_kid, "sig": keys.b64u(sig)}


def _verify_signature_block(
    payload: bytes, sig_block: dict[str, Any], entry: dict[str, Any]
) -> bool:
    """AND rule: `entry` hybrid (carries `pub_ml_dsa_65`) requires BOTH legs
    present and valid; non-hybrid requires the Ed25519 leg valid and
    `sig_ml_dsa_65` ABSENT. Any other combination fails closed. Never raises —
    decode/type errors on untrusted input are treated as verification failure.
    """
    is_hybrid_entry = "pub_ml_dsa_65" in entry
    has_mldsa_leg = "sig_ml_dsa_65" in sig_block
    if is_hybrid_entry != has_mldsa_leg:
        return False
    try:
        ed_ok = keys.verify_strict(
            payload, keys.b64u_decode(sig_block["sig"]), keys.b64u_decode(entry["pub"])
        )
        if not is_hybrid_entry:
            return ed_ok
        mldsa_ok = pq.verify_strict(
            payload,
            keys.b64u_decode(sig_block["sig_ml_dsa_65"]),
            keys.b64u_decode(entry["pub_ml_dsa_65"]),
        )
        return ed_ok and mldsa_ok
    except (KeyError, ValueError, TypeError):
        # Manifests arrive from untrusted sources with no schema gate here; fail
        # closed on wrong-typed fields (e.g. non-str sig/pub -> TypeError) too.
        return False


def build_key_manifest(
    issuer: str,
    manifest_version: int,
    issued_at: str,
    key_entries: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "issuer": issuer,
        "manifest_version": manifest_version,
        "issued_at": issued_at,
        "keys": key_entries,
    }
    manifest["manifest_signature"] = _sign_manifest(manifest, signing_kp, signing_kid)
    return manifest


def verify_key_manifest(manifest: dict[str, Any]) -> bool:
    """Self-consistency: signature verifies with a key listed in the manifest itself."""
    sig_block = manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    entry = find_key(manifest, sig_block.get("kid", ""))
    if entry is None:
        return False
    return _verify_signature_block(_signable(manifest), sig_block, entry)


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
    if signer_entry is None or signer_entry.get("status") != _ACTIVE:
        return False
    # The signer key must also cover the candidate's issuance in its validity
    # window (consistency with verify_artifact_manifest) (2026-07-13 review,
    # finding 12).
    if not _within_window(candidate.get("issued_at"), signer_entry):
        return False
    # Bind continuity to the key TRUSTED vouches for: the candidate's signature
    # must verify under the pub `trusted` holds for signer_kid, NOT the pub the
    # candidate lists for it. Otherwise an attacker reuses a trusted kid, swaps in
    # its own pub, self-signs, and passes — continuity becomes cryptographically
    # hollow (2026-07-13 review, finding 1).
    return _verify_signature_block(
        _signable(candidate), candidate["manifest_signature"], signer_entry
    )


def rotate_key_manifest(
    existing: dict[str, Any],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
    issued_at: str,
    new_entry: dict[str, Any] | None = None,
    retire_kids: Iterable[str] = (),
    compromise_kids: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the next key-manifest version: apply status changes to existing
    keys, optionally append `new_entry`, bump `manifest_version`, re-sign with
    `signing_kp`/`signing_kid`.

    `retired` is planned end-of-use (past signatures stay valid, verify.py only
    warns); `compromised` is an incident (verify.py fails closed, invalidating
    every past signature by that key). Callers pick the one whose consequence
    they mean.

    Fail-closed guards (all raise `ValueError`):
    - at least one change must be requested (a new key or a status change);
    - no kid may be both retired and compromised;
    - `signing_kid` may not be compromised — you cannot sign the recovery
      manifest with the very key you are declaring compromised (the attacker
      holds it too); sign with a different, still-active key;
    - every kid to retire/compromise must exist in `existing["keys"]` — a
      typo'd kid is an error, never a silent no-op;
    - `new_entry`'s kid must not already exist in `existing["keys"]` — reusing
      a kid would append a second `keys[]` entry sharing it, a silent no-op
      for the operator since `find_key` returns the first (old-status) match.

    The caller's `existing` manifest is never mutated (keys are copied).
    """
    retire = set(retire_kids)
    compromise = set(compromise_kids)

    if new_entry is None and not retire and not compromise:
        raise ValueError("rotation must change something: a new key or a status change")

    overlap = retire & compromise
    if overlap:
        raise ValueError(f"kid(s) marked both retired and compromised: {sorted(overlap)}")

    if signing_kid in compromise:
        raise ValueError(
            f"signing kid {signing_kid!r} cannot be in the compromised set — sign the "
            "recovery manifest with a different, still-active key"
        )

    existing_keys: list[dict[str, Any]] = existing["keys"]
    existing_kids = {entry.get("kid") for entry in existing_keys}
    unknown = (retire | compromise) - existing_kids
    if unknown:
        raise ValueError(f"cannot change status of unknown kid(s): {sorted(unknown)}")

    if new_entry is not None and new_entry.get("kid") in existing_kids:
        raise ValueError(
            f"new key kid {new_entry.get('kid')!r} already exists in the manifest — use "
            "--retire-kid/--compromise-kid to change an existing key's status, not --new-kid"
        )

    updated: list[dict[str, Any]] = []
    for entry in existing_keys:
        entry = dict(entry)  # copy — never mutate the caller's manifest
        kid = entry.get("kid")
        if kid in compromise:
            entry["status"] = _COMPROMISED
        elif kid in retire:
            entry["status"] = _RETIRED
        updated.append(entry)
    if new_entry is not None:
        updated.append(new_entry)

    new_version = existing["manifest_version"] + 1
    return build_key_manifest(
        existing["issuer"], new_version, issued_at, updated, signing_kp, signing_kid
    )


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
    covered by the signer key's `[valid_from, valid_to]` window, and issuers must match.

    Defense-in-depth: the `key_manifest` must itself be self-consistent
    (`verify_key_manifest`) so an attacker-fabricated key manifest paired with a
    matching attacker-signed artifact manifest cannot verify. This does not
    preempt the trust-store/TOFU/continuity decisions that live in verify.py —
    a genuinely trusted key manifest always self-verifies, so the happy path is
    unaffected.
    """
    if not verify_key_manifest(key_manifest):
        return False
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
    except (KeyError, ValueError, TypeError):
        # Fail closed on wrong-typed fields (e.g. non-str released_at -> TypeError).
        return False
