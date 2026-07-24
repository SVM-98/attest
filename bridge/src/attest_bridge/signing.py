"""Startup loader for the merchant's hybrid signing key + key manifest — fail-fast.

Contract (task-3-brief.md): load the Ed25519 + ML-DSA-65 signing key material an
`IssuerConfig` points at, in the exact on-disk shapes `attest keygen` writes, then
cross-check the loaded key material against its own key manifest. Every failure —
missing/unreadable file, malformed seed/ML-DSA material, a self-inconsistent
manifest, a kid absent from the manifest, or a manifest entry whose declared pub
does not match the loaded key — is caught HERE, at startup, never at the first
webhook's signature. Key material is never logged, re-written, or returned except
inside `pq.HybridSigningKeys`; error messages name the file path and/or kid, never
decoded key bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attest import keys, manifests, pq
from attest_bridge.config import IssuerConfig
from attest_bridge.model import ConfigError


@dataclass(frozen=True, slots=True)
class IssuerIdentity:
    issuer_id: str
    display_name: str
    kid: str
    # repr=False on both fields: SigningKeyPair.seed / MLDSAKeyPair.sk are secret,
    # and manifest_snapshot carries (public but byte-encoded) key material — neither
    # belongs in repr()/"%r" output. field(repr=False) sets no default, so these
    # stay required positional fields.
    signing_keys: pq.HybridSigningKeys = field(repr=False)
    manifest_snapshot: dict[str, Any] = field(repr=False)


def _load_seed(path: Path) -> keys.SigningKeyPair:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read seed file {path}: {exc}") from exc
    try:
        return keys.from_seed(keys.b64u_decode(text))
    except ValueError as exc:
        raise ConfigError(f"seed file {path} is malformed: {exc}") from exc


def _load_mldsa(path: Path) -> pq.MLDSAKeyPair:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read ML-DSA-65 key file {path}: {exc}") from exc
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # ValueError covers json.JSONDecodeError AND plain ValueError (a JSON
        # integer beyond CPython's int-string conversion limit); RecursionError
        # covers pathologically nested input. Every corruption -> ConfigError.
        raise ConfigError(f"ML-DSA-65 key file {path} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict) or obj.get("alg") != pq.ML_DSA_65_ALG:
        raise ConfigError(
            f"ML-DSA-65 key file {path} has wrong alg (expected {pq.ML_DSA_65_ALG!r})"
        )
    try:
        sk = keys.b64u_decode(obj["sk"])
        pub = keys.b64u_decode(obj["pub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"ML-DSA-65 key file {path} has malformed sk/pub fields") from exc
    if len(sk) != pq.ML_DSA_65_SK_LEN or len(pub) != pq.ML_DSA_65_PK_LEN:
        raise ConfigError(f"ML-DSA-65 key file {path} has wrong-length key material")
    return pq.MLDSAKeyPair(sk=sk, pub=pub)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read key manifest {path}: {exc}") from exc
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # See _load_mldsa: ValueError also covers the overlong-integer ValueError,
        # RecursionError covers pathological nesting. Every corruption -> ConfigError.
        raise ConfigError(f"key manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ConfigError(f"key manifest {path} must be a JSON object")
    return obj


def load_issuer(config: IssuerConfig) -> IssuerIdentity:
    """Load and cross-check the issuer's hybrid signing key + key manifest.

    Raises `ConfigError` fail-fast on any corruption in the contract (see
    module docstring) — this is meant to run once at startup so a
    mis-configured key/manifest pair is caught before the first webhook.
    """
    ed = _load_seed(config.seed_path)
    mldsa = _load_mldsa(config.mldsa_key_path)
    manifest = _load_manifest(config.manifest_path)

    try:
        manifest_ok = manifests.verify_key_manifest(manifest)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        # A parseable-but-malformed manifest makes verification RAISE rather than
        # return False (e.g. a float, forbidden by the attest-JCS profile, reaches
        # canonicalization -> canon.CanonError, a ValueError; deep nesting ->
        # RecursionError). Normalize to the pinned fail-closed contract: every
        # corruption -> ConfigError.
        raise ConfigError(
            f"key manifest {config.manifest_path} could not be verified: {exc}"
        ) from exc
    if not manifest_ok:
        raise ConfigError(
            f"key manifest {config.manifest_path} failed self-consistency verification"
        )

    entry = manifests.find_key(manifest, config.kid)
    if entry is None:
        raise ConfigError(f"kid {config.kid!r} not found in key manifest {config.manifest_path}")

    try:
        manifest_ed_pub = keys.b64u_decode(entry["pub"])
        manifest_mldsa_pub = keys.b64u_decode(entry["pub_ml_dsa_65"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(
            f"key manifest entry for kid {config.kid!r} in {config.manifest_path} is malformed"
        ) from exc

    if manifest_ed_pub != ed.pub:
        raise ConfigError(
            f"key/manifest mismatch for kid {config.kid!r}: the manifest's Ed25519 pub does "
            f"not match the key loaded from {config.seed_path}"
        )
    if manifest_mldsa_pub != mldsa.pub:
        raise ConfigError(
            f"key/manifest mismatch for kid {config.kid!r}: the manifest's ML-DSA-65 pub does "
            f"not match the key loaded from {config.mldsa_key_path}"
        )

    return IssuerIdentity(
        issuer_id=config.id,
        display_name=config.display_name,
        kid=config.kid,
        signing_keys=pq.HybridSigningKeys(ed=ed, mldsa=mldsa),
        manifest_snapshot=manifest,
    )
