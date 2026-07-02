"""Receipt verification core — §6 steps 0-5 (the security heart of OPR).

Decides whether a receipt's signature is valid, from which issuer, and
whether it is schema-conformant. Steps 6-7 (revocation, disclosure/binding
proof) are Task 9's concern; this module always reports `revocation:
"unknown"` and `binding: "not_checked"` — a caller passing `revocation_view`
or `disclosure` gets those stubbed values today, never a silent wrong
answer.

Pipeline invariant: `canon.loads_strict` parses the raw envelope bytes
exactly once (step 0); every later step operates on that single parsed
object, never on the raw bytes or on any re-serialization of it. `alg` is
read from the signature block only to reject anything that is not the
literal string "Ed25519" — it is never used to select a verification
algorithm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from opr import canon, keys, manifests, validate

_ALG = "Ed25519"  # hard-coded — never selected from any field, mirrors issue.py
_SUPPORTED_OPR_VERSIONS = frozenset({"0.1"})
_KNOWN_EOL_VALUES = frozenset({"artifacts-remain-redownloadable", "escrow", "none"})
_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"

_STATUS_COMPROMISED = "compromised"
_STATUS_RETIRED = "retired"

_PROVENANCE_TLS = "tls"

_TRUST_VERIFIED = "verified"
_TRUST_TOFU = "unauthenticated_tofu"

_SIG_VALID = "valid"
_SIG_INVALID = "invalid"
_SCHEMA_VALID = "valid"
_SCHEMA_INVALID = "invalid"
_SCHEMA_NOT_CHECKED = "not_checked"
_REVOCATION_UNKNOWN = "unknown"
_BINDING_NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class TrustStore:
    """The verifier's local trust material (design §5: offline verification
    works from a local trust store of key manifests)."""

    manifests: dict[str, dict[str, Any]]  # issuer_id -> key manifest
    provenance: dict[str, str]  # issuer_id -> "tls" | "bundle"


@dataclass(frozen=True)
class VerificationResult:
    """Layered, never boolean (design §6): each dimension of trust is reported
    independently so a caller can degrade gracefully instead of getting a
    single opaque true/false."""

    signature: str  # "valid" | "invalid"
    schema: str  # "valid" | "invalid" | "not_checked"
    revocation: str  # "unknown" in this task (§6 step 6 is Task 9)
    binding: str  # "not_checked" in this task (§6 step 7 is Task 9)
    trust: str  # "verified" | "unauthenticated_tofu" (unverified_rotation is Task 9)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.signature == _SIG_VALID and self.schema == _SCHEMA_VALID and not self.errors


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _within_validity(issued_at: str, entry: dict[str, Any]) -> bool:
    """Fail closed on any malformed/missing date — an unparseable window
    never resurrects a receipt into validity."""
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


def _content_warnings(payload: dict[str, Any]) -> list[str]:
    """Non-fatal, payload-content warnings — independent of the crypto pipeline.

    Unknown top-level fields are compared against the schema's top-level
    `properties` keys only (top level is enough for v0.1, per brief).
    """
    found: list[str] = []

    known_top_level = set(validate.SCHEMA.get("properties", {}))
    for key in payload:
        if key not in known_top_level:
            found.append(f"unknown payload field: {key!r}")

    license_block = payload.get("license")
    if isinstance(license_block, dict) and license_block.get("drm") == "drm-bound":
        found.append("license.drm is drm-bound (design vector 18)")

    survivability = payload.get("survivability")
    if isinstance(survivability, dict):
        eol = survivability.get("end_of_life")
        if eol not in _KNOWN_EOL_VALUES:
            found.append(f"unknown survivability.end_of_life value: {eol!r}")

    return found


def verify(
    envelope_bytes: bytes,
    trust_store: TrustStore,
    revocation_view: object | None = None,
    disclosure: object | None = None,
) -> VerificationResult:
    """§6 steps 0-5. `revocation_view`/`disclosure` are accepted for interface
    stability but not consulted yet (Task 9: §6 steps 6-7)."""
    del revocation_view, disclosure

    errors: list[str] = []
    warnings: list[str] = []
    # Conservative default: never claim "verified" trust until we've resolved
    # a manifest whose provenance is actually "tls".
    trust = _TRUST_TOFU

    def _invalid(message: str, *, schema: str = _SCHEMA_NOT_CHECKED) -> VerificationResult:
        errors.append(message)
        return VerificationResult(
            signature=_SIG_INVALID,
            schema=schema,
            revocation=_REVOCATION_UNKNOWN,
            binding=_BINDING_NOT_CHECKED,
            trust=trust,
            warnings=tuple(warnings),
            errors=tuple(errors),
        )

    # --- Step 0: preconditions — parse once, strictly. All later steps and
    # all downstream consumers operate on this single parsed object, never
    # on the raw bytes (kills sign-vs-parse splits).
    try:
        parsed = canon.loads_strict(envelope_bytes)
    except canon.CanonError as exc:
        return _invalid(str(exc))

    if not isinstance(parsed, dict):
        return _invalid("envelope is not a JSON object")
    envelope: dict[str, Any] = parsed

    payload_obj = envelope.get("payload")
    if not isinstance(payload_obj, dict):
        return _invalid("envelope missing object member 'payload'")
    payload: dict[str, Any] = payload_obj

    signatures_obj = envelope.get("signatures")
    if not isinstance(signatures_obj, list):
        return _invalid("envelope missing array member 'signatures'")

    # Resolve trust as soon as we can identify the claimed issuer, even if a
    # later step rejects the receipt — a failed verification still reports
    # the trust level of the manifest that was consulted (or the safe
    # default if none could be identified/resolved).
    issuer_block = payload.get("issuer")
    issuer_id = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    if isinstance(issuer_id, str):
        provenance = trust_store.provenance.get(issuer_id)
        trust = _TRUST_VERIFIED if provenance == _PROVENANCE_TLS else _TRUST_TOFU

    # --- Step 1: envelope well-formed; opr_version supported; signatures
    # length == 1; alg == "Ed25519" (read only to reject, never to select).
    opr_version = payload.get("opr_version")
    if opr_version not in _SUPPORTED_OPR_VERSIONS:
        return _invalid(f"unsupported opr_version: {opr_version!r}")

    if len(signatures_obj) != 1:
        return _invalid(f"signatures must contain exactly one entry, got {len(signatures_obj)}")

    sig_block = signatures_obj[0]
    if not isinstance(sig_block, dict):
        return _invalid("malformed signature block")

    kid = sig_block.get("kid")
    alg = sig_block.get("alg")
    sig_b64 = sig_block.get("sig")
    if not isinstance(kid, str) or not isinstance(sig_b64, str):
        return _invalid("malformed signature block: 'kid'/'sig' must be strings")

    if alg != _ALG:
        return _invalid(f"unsupported signature algorithm: {alg!r}")

    # --- Step 2: issuer binding — resolve the key ONLY from the manifest of
    # payload.issuer.id; kid's DNS-domain prefix and the manifest's own
    # `issuer` field must both equal it, or reject (issuer_mismatch). This
    # kills cross-issuer impersonation: a valid manifest for evil.example.com
    # can never validate a receipt claiming issuer.id "store.example.com".
    if not isinstance(issuer_id, str):
        return _invalid("malformed payload: missing issuer.id")

    manifest = trust_store.manifests.get(issuer_id)
    if manifest is None:
        return _invalid(f"no trusted manifest for issuer {issuer_id!r}")

    if kid.split("/")[0] != issuer_id or manifest.get("issuer") != issuer_id:
        return _invalid("issuer_mismatch: kid domain does not match payload issuer.id")

    # --- Step 3: key checks — present, not compromised (fail-closed
    # regardless of issued_at), issued_at within the key's validity window.
    entry = manifests.find_key(manifest, kid)
    if entry is None:
        return _invalid(f"no key {kid!r} in issuer manifest")

    status = entry.get("status")
    if status == _STATUS_COMPROMISED:
        return _invalid(f"key {kid} is compromised")

    issued_at = payload.get("issued_at")
    if not isinstance(issued_at, str) or not _within_validity(issued_at, entry):
        return _invalid(f"issued_at {issued_at!r} outside key validity window")

    if status == _STATUS_RETIRED:
        warnings.append(f"key {kid} is retired")

    # --- Step 4: Ed25519.verify(JCS(payload), sig, pub) under the pinned
    # ruleset. canon.canonical_bytes(payload) is the only signature input.
    try:
        pub = keys.b64u_decode(entry["pub"])
        sig = keys.b64u_decode(sig_b64)
    except (KeyError, TypeError, ValueError) as exc:
        return _invalid(f"malformed key material: {exc}")

    try:
        signature_ok = keys.verify_strict(canon.canonical_bytes(payload), sig, pub)
    except ValueError as exc:
        return _invalid(f"malformed signature material: {exc}")

    if not signature_ok:
        return _invalid("signature verification failed")

    # --- Step 5: schema validation of the parsed payload from step 0.
    violations = validate.validate_payload(payload)
    schema_result = _SCHEMA_VALID if not violations else _SCHEMA_INVALID
    errors.extend(violations)

    warnings.extend(_content_warnings(payload))

    return VerificationResult(
        signature=_SIG_VALID,
        schema=schema_result,
        revocation=_REVOCATION_UNKNOWN,
        binding=_BINDING_NOT_CHECKED,
        trust=trust,
        warnings=tuple(warnings),
        errors=tuple(errors),
    )
