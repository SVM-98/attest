"""Transfer records — issuer-mediated transfer, holder-authorized (v0.2 §17).

A transfer record is an issuer-signed side-document, structurally analogous
to a revocation record (`revocation.py`): it carries a closed set of fields,
including an OUTGOING holder's Ed25519 authorization (over a domain-separated
preimage, `authorization_message`) and the ISSUER's own signature over
`canon.canonical_bytes(record)` with `signature` removed — signed exactly
like every other v0.2 side-document (hybrid AND-rule via
`manifests.sign_signature_block`/`verify_signature_block`, §13).

This module only builds records, checks a holder's authorization signature
in isolation, checks a record's own issuer-signature self-consistency
against an issuer's key manifest, and evaluates whether a record has proven
`logged` (or better) standing in the issuer's transparency log. It has no
opinion on the full transfer semantics — old-receipt extinguishment,
double-assignment, `not_transferable_before`, chain-of-title — which need the
old AND new receipts in hand and belong to `verify.py` (§17.2-§17.8), the one
module that has both.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from attest import anchor, canon, keys, manifests, pq, tlog
from attest import transparency as transparency_module

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"
_RECEIPT_ID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_TRANSFER_RECORD_MEMBERS = frozenset(
    {
        "receipt_id",
        "new_receipt_id",
        "new_holder_pubkey",
        "transferred_at",
        "holder_authorization",
        "signature",
    }
)

# Fixed literal (v0.2 §17.1, verbatim) — the domain-separation label for the
# holder-authorization preimage. Never changes without a protocol version bump.
LABEL_TRANSFER_AUTHORIZATION = b"Attest-transfer-authorization-v1"

# Fixed literal (v0.2 §8/§17.1) — the fourth transparency-log entry type.
_LOG_ENTRY_TYPE = "transfer-record"

# Ed25519 signature: 64 raw bytes, base64url-no-pad encodes to exactly 86
# characters (ceil(64/3)*4 - 2 stripped padding chars). `holder_authorization`
# carries exactly one member, `sig`, at exactly this length — anything else
# is a malformed shape, checked before any cryptographic work.
_HOLDER_AUTH_SIG_B64U_LEN = 86

# Same literal VALUE as `verify._MAX_TRANSPARENCY_EVIDENCE_LEN` (this module
# cannot import `verify` — that would be an import cycle, since `verify.py`
# imports `transfer.py`). Bounds the untrusted evidence bundle's
# canonicalized size before it is ever parsed.
_MAX_TRANSFER_EVIDENCE_LEN = 10_000_000

# Same literal VALUE as `verify._ANCHORED_BEFORE_PREFIX` — `transparency.
# TransparencyResult.transparency` renders this dynamically, never as a
# fixed enum member (see `transparency.py`'s module docstring).
_ANCHORED_BEFORE_PREFIX = "anchored_before:"


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _strict_b64u_decode(value: object, expected_length: int) -> bytes | None:
    """Return canonical base64url `value` iff it decodes to `expected_length` bytes."""
    if not isinstance(value, str):
        return None
    try:
        decoded = keys.b64u_decode(value)
    except (TypeError, ValueError):
        return None
    if len(decoded) != expected_length or keys.b64u(decoded) != value:
        return None
    return decoded


def _valid_utc_timestamp(value: object) -> bool:
    """Whether `value` has the signed UTC wire shape used by side-documents."""
    if not isinstance(value, str):
        return False
    try:
        return _parse_date(value).strftime(_DATE_FMT) == value
    except ValueError:
        return False


def authorization_message(receipt_id: str, new_holder_pubkey: str, transferred_at: str) -> bytes:
    """The domain-separated holder-authorization preimage (v0.2 §17.1, normative,
    verbatim):

    `UTF8("Attest-transfer-authorization-v1") || 0x00 || UTF8(receipt_id) ||
    0x00 || UTF8(new_holder_pubkey) || 0x00 || UTF8(transferred_at)`

    Each component is its wire TEXT form encoded as UTF-8 (not decoded/
    re-encoded) — `receipt_id`/`transferred_at` as the literal strings
    carried in the record, `new_holder_pubkey` as its base64url text —
    mirroring v0.1 §8.2's `receipt_id`-encoding discipline exactly. Binding
    all three together makes the authorization non-replayable against a
    different old receipt, a different incoming key, or a different signed
    time.
    """
    return (
        LABEL_TRANSFER_AUTHORIZATION
        + b"\x00"
        + receipt_id.encode()
        + b"\x00"
        + new_holder_pubkey.encode()
        + b"\x00"
        + transferred_at.encode()
    )


def sign_authorization(
    receipt_id: str,
    new_holder_pubkey: str,
    transferred_at: str,
    holder_kp: keys.SigningKeyPair,
) -> bytes:
    """The OUTGOING holder's raw 64-byte Ed25519 signature over
    `authorization_message(...)`. `holder_kp` is the OLD receipt's own
    `buyer.pubkey` keypair — the holder is not an issuer-manifest signer, so
    there is no `kid` here, unlike every issuer-signed side-document."""
    return keys.sign(
        authorization_message(receipt_id, new_holder_pubkey, transferred_at), holder_kp
    )


def build_record(
    receipt_id: str,
    new_receipt_id: str,
    new_holder_pubkey: str,
    transferred_at: str,
    holder_authorization_sig: bytes,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
) -> dict[str, Any]:
    """Build an issuer-signed transfer record (v0.2 §17.1), six fields:
    `receipt_id`, `new_receipt_id`, `new_holder_pubkey`, `transferred_at`,
    `holder_authorization` (`{"sig"}`, the OUTGOING holder's raw signature
    from `sign_authorization`, base64url-encoded), and `signature`.

    `signing_kp` mirrors `manifests.build_key_manifest`/`revocation.build_record`:
    a `pq.HybridSigningKeys` produces a `signature` block with both the
    Ed25519 `sig` leg and the `sig_ml_dsa_65` leg (see
    `manifests.sign_signature_block`); a plain `keys.SigningKeyPair` keeps
    the Ed25519-only shape.
    """
    record: dict[str, Any] = {
        "receipt_id": receipt_id,
        "new_receipt_id": new_receipt_id,
        "new_holder_pubkey": new_holder_pubkey,
        "transferred_at": transferred_at,
        "holder_authorization": {"sig": keys.b64u(holder_authorization_sig)},
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

    This is what a `transfer-record` transparency-log entry commits to
    (v0.2 §8/§17.1): the SAME `canon.canonical_bytes` this module already
    uses to build and verify a record's signature — one canonical form,
    reused, never a second one invented for the log. Mirrors
    `revocation.record_hash` exactly.
    """
    return hashlib.sha256(canon.canonical_bytes(record)).hexdigest()


def _valid_holder_authorization_shape(value: object) -> bool:
    """`holder_authorization` must be a dict with exactly one member, `sig`,
    whose value is a well-formed base64url string decoding to exactly a
    64-byte Ed25519 signature. Fails closed on every other shape (missing
    member, extra member, non-dict, non-base64url, wrong-length) — never
    raises."""
    if not isinstance(value, dict) or set(value) != {"sig"}:
        return False
    sig = value.get("sig")
    return (
        isinstance(sig, str)
        and len(sig) == _HOLDER_AUTH_SIG_B64U_LEN
        and _strict_b64u_decode(sig, 64) is not None
    )


def verify_record_signature(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify `record`'s own signature against an ALREADY self-verified `key_manifest`.

    Exactly `verify_record` minus the `manifests.verify_key_manifest`
    self-consistency check: the signer key must be **active** in
    `key_manifest`, with its `[valid_from, valid_to]` window covering the
    record's own signed `transferred_at`, and the signature must verify
    against that key's `pub` — mirrors `revocation.verify_record_signature`
    line-for-line. PLUS a shape-check unique to transfer records:
    `holder_authorization` must be `_valid_holder_authorization_shape` (v0.2
    §17.1's closed six-field object) — a record whose issuer signature
    happens to verify over a malformed `holder_authorization` value (any
    string canonicalizes fine, so the outer signature alone cannot catch
    this) is still rejected. Fails closed on every malformed/wrong-typed/
    unsigned/out-of-window input — never raises.

    AND rule (v0.2 §13, mirrors `manifests.verify_key_manifest`): if the
    signer's `key_manifest` entry is hybrid (carries `pub_ml_dsa_65`),
    `signature` MUST also carry a valid `sig_ml_dsa_65` leg over the same
    signed bytes, or verification fails closed; an Ed25519-only entry with a
    stray `sig_ml_dsa_65` leg likewise fails closed (see
    `manifests.verify_signature_block`). Ed25519-only signers keep v0.1-style
    behavior byte-for-byte.

    PRECONDITION: the caller has already established
    `manifests.verify_key_manifest(key_manifest)` is True. Callers checking
    many records against ONE manifest hoist that call out of their loop —
    one manifest self-verify per classification, not per record (mirrors
    `revocation.verify_record_signature`'s own hoisting note). To verify a
    single record, use `verify_record`, which composes both halves.
    """
    try:
        if not isinstance(record, dict) or set(record) != _TRANSFER_RECORD_MEMBERS:
            return False
        receipt_id = record["receipt_id"]
        new_receipt_id = record["new_receipt_id"]
        new_holder_pubkey = record["new_holder_pubkey"]
        transferred_at_value = record["transferred_at"]
        if (
            not isinstance(receipt_id, str)
            or _RECEIPT_ID_RE.fullmatch(receipt_id) is None
            or not isinstance(new_receipt_id, str)
            or _RECEIPT_ID_RE.fullmatch(new_receipt_id) is None
            or _strict_b64u_decode(new_holder_pubkey, 32) is None
            or not _valid_utc_timestamp(transferred_at_value)
            or not _valid_holder_authorization_shape(record["holder_authorization"])
        ):
            return False
        sig_block = record["signature"]
        if not isinstance(sig_block, dict):
            return False
        entry = manifests.find_key(key_manifest, sig_block.get("kid", ""))
        if entry is None or entry.get("status") != _ACTIVE:
            return False
        body = {key: value for key, value in record.items() if key != "signature"}
        transferred_at = _parse_date(record["transferred_at"])
        if transferred_at < _parse_date(entry["valid_from"]):
            return False
        valid_to = entry.get("valid_to")
        if valid_to is not None and transferred_at > _parse_date(valid_to):
            return False
        return manifests.verify_signature_block(canon.canonical_bytes(body), sig_block, entry)
    except (AttributeError, KeyError, TypeError, ValueError, canon.CanonError):
        return False


def verify_record(record: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify against `key_manifest`, mirroring `revocation.verify_record`
    exactly: the signer key must be **active** in a self-consistent
    `key_manifest`, with its `[valid_from, valid_to]` window covering the
    record's own signed `transferred_at`, and the signature must verify.

    Defense-in-depth: `key_manifest` itself must be self-consistent, so a
    fabricated key manifest paired with a matching fabricated record
    signature cannot verify. Fails closed on every malformed/wrong-typed/
    unsigned/out-of-window input — never raises. Composes
    `manifests.verify_key_manifest` + `verify_record_signature`;
    loop-over-records callers hoist the former.
    """
    try:
        return manifests.verify_key_manifest(key_manifest) and verify_record_signature(
            record, key_manifest
        )
    except (AttributeError, KeyError, TypeError, ValueError, canon.CanonError):
        return False


def verify_authorization(record: dict[str, Any], holder_pubkey_b64u: str) -> bool:
    """Verify the OUTGOING holder's own authorization signature in isolation
    from the issuer's signature: does `record["holder_authorization"]["sig"]`
    verify over `authorization_message(...)` (rebuilt from the record's own
    `receipt_id`/`new_holder_pubkey`/`transferred_at`) against
    `holder_pubkey_b64u` — the OLD receipt's own `buyer.pubkey`, read by the
    caller, never by this function.

    Fails closed (never raises) on every malformed input: a missing or
    wrong-typed field, a non-b64u pubkey/signature, or a genuinely wrong
    signature all return `False`.
    """
    try:
        receipt_id = record["receipt_id"]
        new_holder_pubkey = record["new_holder_pubkey"]
        transferred_at = record["transferred_at"]
        if not (
            isinstance(receipt_id, str)
            and isinstance(new_holder_pubkey, str)
            and isinstance(transferred_at, str)
        ):
            return False
        sig_block = record["holder_authorization"]
        if not _valid_holder_authorization_shape(sig_block):
            return False
        sig = _strict_b64u_decode(sig_block["sig"], 64)
        if sig is None:
            return False
        holder_pub = keys.b64u_decode(holder_pubkey_b64u)
        message = authorization_message(receipt_id, new_holder_pubkey, transferred_at)
        return keys.verify_strict(message, sig, holder_pub)
    except (KeyError, ValueError, TypeError):
        return False


def _resolve_log_origin(log_keys: list[tlog.LogKey]) -> str:
    """The single pinned origin shared by every entry in `log_keys` — TRUSTED
    verifier configuration, never derived from untrusted evidence. Mirrors
    `verify._resolve_log_origin` exactly (duplicated locally: this module
    cannot import `verify`, which itself imports `transfer`). Malformed or
    disagreeing/empty origins are a caller/config bug and raise
    `TransparencyError`.
    """
    validated = transparency_module._validate_log_keys(log_keys)
    origins = {key.origin for key in validated}
    if len(origins) != 1:
        raise transparency_module.TransparencyError(
            f"log_keys must be a non-empty list sharing a single origin, got {sorted(origins)!r}"
        )
    return next(iter(origins))


def record_logged_standing(
    record: dict[str, Any],
    evidence: dict[str, Any] | None,
    issuer_id: str,
    log_keys: list[tlog.LogKey],
    anchor_policy: anchor.AnchorPolicy,
    warnings: list[str] | None = None,
) -> int | None:
    """The record's own proven `leaf_index` iff `evidence` proves its
    `transfer-record` log entry reached `logged` standing or better
    (`"logged"` or `"anchored_before:..."`), else `None` — mirrors
    `verify._revocation_deadline_satisfied`'s untrusted-evidence confinement
    exactly (§17.2's log-required honoring, D2, needs the same evidence
    handling G5 already established for revocation records).

    `evidence` is untrusted: canonicalized and re-parsed once via
    `canon.dumps`/`json.loads` (bounded by `_MAX_TRANSFER_EVIDENCE_LEN`, the
    SAME literal value as `verify._MAX_TRANSPARENCY_EVIDENCE_LEN`) so every
    later phase sees one ordinary JSON object, never a stateful/hostile
    mapping. `record`/`issuer_id` feed the EXPECTED entry
    `{"type": "transfer-record", "issuer": issuer_id, "record_sha256":
    record_hash(record)}`, computed locally and never read off `evidence` —
    a malformed `record` or `issuer_id` degrades to `None` (this is
    payload-adjacent data, not trusted config), exactly like
    `verify._validated_transparency_entry`'s fail-closed pattern.

    `log_keys`/`anchor_policy` ARE the trusted, verifier-config side of the
    call: malformed ones raise `TransparencyError` (a config bug), the same
    discipline as G5. Every warning the shared evaluator returns is appended
    to `warnings` (dedup against identical strings already present) when
    `warnings` is provided, regardless of whether standing is ultimately
    reached — mirrors `_revocation_deadline_satisfied`'s own
    `warnings.extend`.
    """
    if evidence is None:
        return None

    origin = _resolve_log_origin(log_keys)
    transparency_module._validate_policy(anchor_policy)

    try:
        # verify()'s untrusted-evidence boundary, mirroring
        # `_evaluate_transparency_claim`/`_revocation_deadline_satisfied`:
        # canonicalize and parse once so every following phase sees one
        # ordinary JSON object, never a stateful mapping/value supplied by
        # the caller.
        serialized_evidence = canon.dumps(evidence)
        if len(serialized_evidence) > _MAX_TRANSFER_EVIDENCE_LEN:
            return None
        materialized_evidence = json.loads(serialized_evidence)
        if not isinstance(materialized_evidence, dict):
            return None
    # Adversarial-boundary confinement (never BaseException): a hostile
    # `evidence` mapping's `__eq__`/`__getitem__` must not escape as a bare
    # exception, mirroring `_revocation_deadline_satisfied`.
    except Exception:
        return None

    try:
        record_sha256 = record_hash(record)
    except (TypeError, canon.CanonError):
        return None

    candidate_entry = {
        "type": _LOG_ENTRY_TYPE,
        "issuer": issuer_id,
        "record_sha256": record_sha256,
    }
    try:
        tlog.encode_entry(candidate_entry)
    except tlog.TlogError:
        return None

    result = transparency_module.evaluate_transparency(
        materialized_evidence,
        log_keys=log_keys,
        expected_origin=origin,
        policy=anchor_policy,
        expected_entry=candidate_entry,
    )
    if warnings is not None:
        for warning in result.warnings:
            if warning not in warnings:
                warnings.append(warning)

    reached_standing = (
        result.transparency == transparency_module.TRANSPARENCY_LOGGED
        or result.transparency.startswith(_ANCHORED_BEFORE_PREFIX)
    )
    if not reached_standing:
        return None

    leaf_index = materialized_evidence.get("leaf_index")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0:
        return None
    return leaf_index
