"""Receipt verification core — §6 steps 0-7 (the security heart of attest).

Decides whether a receipt's signature is valid, from which issuer, whether
it is schema-conformant, whether it has been effectively revoked, and
whether a buyer-binding disclosure proves the receipt belongs to a given
identifier/keyholder.

Pipeline invariant: `canon.loads_strict` parses the raw envelope bytes
exactly once (step 0); every later step operates on that single parsed
object, never on the raw bytes or on any re-serialization of it. `alg` is
read from the signature block only to reject anything that is not the
literal string "Ed25519" — it is never used to select a verification
algorithm.

Steps 6 (revocation) and 7 (binding) only run once the receipt already has
a valid signature AND a valid schema (§6: "on the parsed object from step
0" pipeline continues only on success) — an already-invalid receipt never
gets a revocation/binding verdict computed against it; both dimensions stay
at their safe stub values (`revocation: "unknown"`, `binding:
"not_checked"`) exactly like the rest of an invalid result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from attest import canon, commitment, keys, manifests, revocation, validate

_ALG = "Ed25519"  # hard-coded — never selected from any field, mirrors issue.py
_SUPPORTED_ATTEST_VERSIONS = frozenset({"0.1"})
_KNOWN_EOL_VALUES = frozenset({"artifacts-remain-redownloadable", "escrow", "none"})
_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"

_STATUS_ACTIVE = "active"
_STATUS_COMPROMISED = "compromised"
_STATUS_RETIRED = "retired"

_PROVENANCE_TLS = "tls"

_TRUST_VERIFIED = "verified"
_TRUST_TOFU = "unauthenticated_tofu"
_TRUST_UNVERIFIED_ROTATION = "unverified_rotation"

_SIG_VALID = "valid"
_SIG_INVALID = "invalid"
_SCHEMA_VALID = "valid"
_SCHEMA_INVALID = "invalid"
_SCHEMA_NOT_CHECKED = "not_checked"

_REVOCATION_UNKNOWN = "unknown"
_REVOCATION_REVOKED = "revoked"
_REVOCATION_INVALID_IGNORED = "invalid_revocation_ignored"
_REVOCATION_NOT_REVOKED_PREFIX = "not_revoked_as_of:"

_REVOCABILITY_NONE = "none"
_REVOCABILITY_REFUND_WINDOW = "refund_window"
_REVOCABILITY_POLICY = "policy"

_RECORD_STATUS_REVOKED = "revoked"

_BINDING_PROVEN = "proven"
_BINDING_NOT_PROVEN = "not_proven"
_BINDING_NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class TrustStore:
    """The verifier's local trust material (design §5: offline verification
    works from a local trust store of key manifests).

    `chains` is optional and backward-compatible (default empty): when
    present, `chains[issuer_id]` is the ordered manifest-version history the
    verifier holds for that issuer, oldest first, ending with the same
    manifest as `manifests[issuer_id]` — the one actually used to resolve
    signing keys in steps 2-4. `verify()` walks consecutive pairs with
    `manifests.check_continuity`; any break marks the issuer's active
    manifest as reached via a discontinuous rotation (design §5: "version
    gaps are bridgeable only by validating every intermediate manifest in
    sequence... if intermediates are unavailable, the manifest counts as
    discontinuous"), which forces `trust: "unverified_rotation"` regardless
    of provenance. An issuer absent from `chains`, or a chain with fewer
    than 2 entries, has nothing to validate and behaves exactly like a
    Task-8 `TrustStore` (no `chains` kwarg at all).
    """

    manifests: dict[str, dict[str, Any]]  # issuer_id -> key manifest
    provenance: dict[str, str]  # issuer_id -> "tls" | "bundle"
    chains: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass(frozen=True)
class Disclosure:
    """§3.2 buyer-binding disclosure — exactly one path is meant to be populated.

    Salt path: `identifier` + `identifier_type` + `salt` recompute the
    commitment and compare it against `payload.buyer.commitment`. Challenge
    path: `challenge = (nonce, sig)` verifies an Ed25519 challenge-response
    transcript against `payload.buyer.pubkey`.

    The salt path takes precedence: if all three salt fields are populated,
    `verify()` evaluates it (returning `proven`/`not_proven`) even when a
    `challenge` is also supplied — a fully-specified salt disclosure is a
    legitimate proof, so a stray extra field never downgrades it. A partial
    path (e.g. `salt` without `identifier`, or neither path complete) is a
    malformed disclosure and fails closed to `binding: "not_proven"` rather
    than raising — never trust an under-specified proof.
    """

    identifier: str | None = None
    identifier_type: str | None = None
    salt: bytes | None = None
    challenge: tuple[bytes, bytes] | None = None  # (nonce, sig)


@dataclass(frozen=True)
class VerificationResult:
    """Layered, never boolean (design §6): each dimension of trust is reported
    independently so a caller can degrade gracefully instead of getting a
    single opaque true/false."""

    signature: str  # "valid" | "invalid"
    schema: str  # "valid" | "invalid" | "not_checked"
    revocation: (
        str  # "unknown" | "not_revoked_as_of:<T>" | "revoked" | "invalid_revocation_ignored"
    )
    binding: str  # "proven" | "not_proven" | "not_checked"
    trust: str  # "verified" | "unauthenticated_tofu" | "unverified_rotation"
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """Design §3.1/§6: an effective revocation record makes a receipt not
        `ok` ("Effective record ⇒ revocation='revoked' (receipt not ok)").
        `invalid_revocation_ignored` and `unknown`/`not_revoked_as_of:<T>` do
        NOT affect `ok` — an ignored-by-class or unverified revocation record
        must never degrade a receipt's validity (that would defeat the
        revocability:none irrevocability guarantee, design vector 16)."""
        return (
            self.signature == _SIG_VALID
            and self.schema == _SCHEMA_VALID
            and self.revocation != _REVOCATION_REVOKED
            and not self.errors
        )


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


def _chain_continuous(chain: list[dict[str, Any]]) -> bool:
    """True iff every consecutive pair in `chain` passes `manifests.check_continuity`.

    A chain of fewer than 2 entries has nothing to validate (no recorded
    history, or a single trusted root with no successor yet) and is treated
    as continuous — this is what keeps a `TrustStore` with no `chains` entry
    for an issuer behaving exactly like Task 8.
    """
    if len(chain) < 2:
        return True
    return all(manifests.check_continuity(chain[i], chain[i + 1]) for i in range(len(chain) - 1))


def _parse_iso(value: object) -> datetime | None:
    """Fail-closed ISO-8601 parse for revocation timestamps — `None` on any
    non-str or unparseable input, never raises. `datetime.fromisoformat`
    handles the `Z` suffix directly on Python 3.12."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _max_revoked_at(view: list[dict[str, Any]]) -> str | None:
    """Freshness anchor for `not_revoked_as_of:<T>`: the maximum `revoked_at`
    across the records passed in — which callers MUST have already filtered to
    signature-authenticated records only (`revocation.verify_record` True).
    Restricting to authenticated records is a security fix: otherwise an
    attacker could inject an unsigned record with a far-future `revoked_at`
    and inflate the reported freshness of the verifier's revocation feed. T
    describes how current the verifier's *authenticated* revocation data is,
    not this one receipt's history (design decision: §6 does not define T
    itself). Malformed entries (non-dict, missing/unparseable `revoked_at`)
    are skipped, never crash; naive/aware datetime mixes that can't be
    compared are likewise skipped rather than raising.
    """
    best_dt: datetime | None = None
    best_raw: str | None = None
    for record in view:
        if not isinstance(record, dict):
            continue
        parsed = _parse_iso(record.get("revoked_at"))
        if parsed is None:
            continue
        raw = record["revoked_at"]
        if best_dt is None:
            best_dt, best_raw = parsed, raw
            continue
        try:
            newer = parsed > best_dt
        except TypeError:
            continue  # incomparable naive/aware mix — skip, never crash
        if newer:
            best_dt, best_raw = parsed, raw
    return best_raw


def _not_revoked_or_unknown(view: list[dict[str, Any]]) -> str:
    anchor = _max_revoked_at(view)
    return _REVOCATION_UNKNOWN if anchor is None else f"{_REVOCATION_NOT_REVOKED_PREFIX}{anchor}"


def _refund_window_end(payload: dict[str, Any]) -> datetime | None:
    license_block = payload.get("license")
    window_days = (
        license_block.get("revocation_window_days") if isinstance(license_block, dict) else None
    )
    if not isinstance(window_days, int) or isinstance(window_days, bool):
        return None
    issued = _parse_iso(payload.get("issued_at"))
    if issued is None:
        return None
    return issued + timedelta(days=window_days)


def _within_refund_window(record: dict[str, Any], window_end: datetime | None) -> bool:
    if window_end is None:
        return False
    revoked_at = _parse_iso(record.get("revoked_at"))
    if revoked_at is None:
        return False
    try:
        return revoked_at <= window_end
    except TypeError:
        return False  # incomparable naive/aware mix — fail closed, never effective


def _classify_revocation(
    payload: dict[str, Any],
    revocation_view: list[dict[str, Any]] | None,
    issuer_manifest: dict[str, Any],
    warnings: list[str],
) -> str:
    """§6 step 6 / §3.1: revocation-by-class.

    A record is a candidate revocation for THIS receipt only if it (a)
    matches the payload's `receipt_id`, (b) authenticates against
    `issuer_manifest` (`revocation.verify_record`: active, in-window,
    correctly signed — the §5 hardening), and (c) carries
    `status == "revoked"` (any other status is not a revocation statement).
    A matching record that fails authentication is ignored with a warning
    (turning a would-be silent DoS into a visible ignore). What an effective
    record then *means* depends on `license.revocability`:

    - "none": ANY effective record is itself invalid — this is the
      irrevocability guarantee (design vector 16). The receipt stays `ok`.
    - "policy": any effective record is honored as-is (terms govern; the
      verifier cannot evaluate them, so a signed record is trusted).
    - "refund_window": an effective record is honored only if its own signed
      `revoked_at` falls within `issued_at + revocation_window_days` —
      evaluated against the record's own signed time, never local clock.

    The `not_revoked_as_of:<T>` freshness anchor is computed over ALL
    authenticated records in the view (any receipt_id), not the raw view —
    so unsigned junk can neither revoke nor inflate T. With no authenticated
    records at all, T has no trustworthy value and the result is `unknown`.
    """
    if not revocation_view:  # None or empty: no data, no freshness anchor either way
        return _REVOCATION_UNKNOWN

    receipt_id = payload.get("receipt_id")
    license_block = payload.get("license")
    revocability = license_block.get("revocability") if isinstance(license_block, dict) else None

    # Authenticated records (any receipt_id) drive the freshness anchor; only
    # signature-verified records may set T (§5 hardening).
    authenticated_ids: set[int] = set()
    authenticated: list[dict[str, Any]] = []
    for record in revocation_view:
        if isinstance(record, dict) and revocation.verify_record(record, issuer_manifest):
            authenticated.append(record)
            authenticated_ids.add(id(record))
    not_revoked = _not_revoked_or_unknown(authenticated)

    # Effective revocations for THIS receipt: matching receipt_id, authenticated,
    # and status == "revoked". Matching-but-unauthenticated records are warned.
    valid: list[dict[str, Any]] = []
    for record in revocation_view:
        if not isinstance(record, dict) or record.get("receipt_id") != receipt_id:
            continue
        if id(record) not in authenticated_ids:
            warnings.append(f"revocation record for {receipt_id!r} failed verification, ignored")
            continue
        if record.get("status") == _RECORD_STATUS_REVOKED:
            valid.append(record)

    if revocability == _REVOCABILITY_NONE:
        if valid:
            warnings.append(
                "revocation record ignored: license.revocability is 'none' (irrevocable)"
            )
            return _REVOCATION_INVALID_IGNORED
        return not_revoked

    if revocability == _REVOCABILITY_POLICY:
        if valid:
            return _REVOCATION_REVOKED
        return not_revoked

    if revocability == _REVOCABILITY_REFUND_WINDOW:
        window_end = _refund_window_end(payload)
        effective = [r for r in valid if _within_refund_window(r, window_end)]
        if effective:
            return _REVOCATION_REVOKED
        if valid:  # matched and verified, but every one fell outside the window
            warnings.append(f"revocation record for {receipt_id!r} outside refund window, ignored")
            return _REVOCATION_INVALID_IGNORED
        return not_revoked

    # Unknown/malformed revocability: schema validation (step 5, already run
    # before this is ever called) should reject this payload outright — fail
    # closed by never honoring a match under an unrecognized class.
    return not_revoked


def _check_binding_salt(
    buyer: dict[str, Any], identifier: str, identifier_type: str, salt: bytes
) -> str:
    expected = buyer.get("commitment")
    if not isinstance(expected, str):
        return _BINDING_NOT_PROVEN
    try:
        computed = commitment.compute(identifier, identifier_type, salt)
    except ValueError:
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if keys.b64u(computed) == expected else _BINDING_NOT_PROVEN


def _check_binding_challenge(
    payload: dict[str, Any], buyer: dict[str, Any], nonce: bytes, sig: bytes
) -> str:
    pubkey_b64 = buyer.get("pubkey")
    receipt_id = payload.get("receipt_id")
    if not isinstance(pubkey_b64, str) or not isinstance(receipt_id, str):
        return _BINDING_NOT_PROVEN
    try:
        pub = keys.b64u_decode(pubkey_b64)
        proven = commitment.verify_challenge(receipt_id, nonce, sig, pub)
    except (ValueError, TypeError):
        return _BINDING_NOT_PROVEN
    return _BINDING_PROVEN if proven else _BINDING_NOT_PROVEN


def _classify_binding(payload: dict[str, Any], disclosure: Disclosure) -> str:
    """§6 step 7 / §3.2: recompute the commitment (salt path) or verify a
    challenge-response transcript (pubkey path). A malformed/partial
    disclosure (neither path fully populated) fails closed to "not_proven"."""
    buyer = payload.get("buyer")
    if not isinstance(buyer, dict):
        return _BINDING_NOT_PROVEN

    if (
        disclosure.salt is not None
        and disclosure.identifier is not None
        and disclosure.identifier_type is not None
    ):
        return _check_binding_salt(
            buyer, disclosure.identifier, disclosure.identifier_type, disclosure.salt
        )
    if disclosure.challenge is not None:
        nonce, sig = disclosure.challenge
        return _check_binding_challenge(payload, buyer, nonce, sig)
    return _BINDING_NOT_PROVEN


def verify(
    envelope_bytes: bytes,
    trust_store: TrustStore,
    revocation_view: list[dict[str, Any]] | None = None,
    disclosure: Disclosure | None = None,
) -> VerificationResult:
    """§6 steps 0-7."""
    # Caller-contract enforcement (security): a non-list `revocation_view`
    # must fail loud. If a lone record OBJECT slipped through here,
    # `_classify_revocation` would iterate its string keys, authenticate
    # nothing, and report `revocation: "unknown"` / `ok: true` for a receipt
    # genuinely revoked under `policy`/`refund_window` — a silent pass on a
    # security check. `None` (no view) stays valid.
    if revocation_view is not None and not isinstance(revocation_view, list):
        raise TypeError("revocation_view must be a list of records or None")

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
    # default if none could be identified/resolved). A discontinuous
    # manifest chain (design §5) overrides provenance-based trust entirely:
    # verifiers MUST NOT auto-accept a rotation they can't chain to a root.
    issuer_block = payload.get("issuer")
    issuer_id = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    if isinstance(issuer_id, str):
        provenance = trust_store.provenance.get(issuer_id)
        trust = _TRUST_VERIFIED if provenance == _PROVENANCE_TLS else _TRUST_TOFU
        chain = trust_store.chains.get(issuer_id)
        if chain and not _chain_continuous(chain):
            trust = _TRUST_UNVERIFIED_ROTATION

    # --- Step 1: envelope well-formed; attest_version supported; signatures
    # length == 1; alg == "Ed25519" (read only to reject, never to select).
    attest_version = payload.get("attest_version")
    if attest_version not in _SUPPORTED_ATTEST_VERSIONS:
        return _invalid(f"unsupported attest_version: {attest_version!r}")

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
    if status not in (_STATUS_ACTIVE, _STATUS_RETIRED):
        # Fail closed on missing/unknown status instead of validating like an
        # active key (2026-07-13 review, finding 4).
        return _invalid(f"key {kid} has unusable status {status!r}")

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

    # --- Steps 6-7: revocation-by-class and buyer binding. Only evaluated
    # once signature (guaranteed above) AND schema are both valid — see
    # module docstring.
    if schema_result == _SCHEMA_VALID:
        revocation_result = _classify_revocation(payload, revocation_view, manifest, warnings)
        binding_result = (
            _classify_binding(payload, disclosure)
            if disclosure is not None
            else _BINDING_NOT_CHECKED
        )
    else:
        revocation_result = _REVOCATION_UNKNOWN
        binding_result = _BINDING_NOT_CHECKED

    return VerificationResult(
        signature=_SIG_VALID,
        schema=schema_result,
        revocation=revocation_result,
        binding=binding_result,
        trust=trust,
        warnings=tuple(warnings),
        errors=tuple(errors),
    )
