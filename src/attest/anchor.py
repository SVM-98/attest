"""OpenTimestamps-style Bitcoin block-header anchoring — Stage 2 (design
doc "transparency/corroboration layer", CRQC-horizon gating).

Scope: this module lets a verifier check that a `tlog.Checkpoint` was
timestamped into a Bitcoin block header pinned in its own trust store
(`AnchorPolicy`), and gate on whether that anchor lands early enough to
still count as post-quantum-surviving evidence once a future
cryptographically-relevant quantum computer (CRQC) horizon is reached.

- `verify_anchor` walks each proof in an untrusted anchor-evidence bundle:
  an `ots` proof replays a small hash op-chain (`sha256`/`append`/`prepend`)
  starting from `SHA256(checkpoint.note_bytes)` and checks it lands on a
  Bitcoin merkle root pinned, by header hash, in `policy.pinned_headers`; an
  `rfc3161` proof is accepted only as opaque classical corroboration (never
  parsed) and can never set an anchor time. This function NEVER raises on
  malformed evidence — `evidence` arrives from an untrusted bundle, so any
  shape violation (wrong types, missing fields, bad hex, unknown ops, an
  oversized proof/op list) degrades to a warning and that proof simply
  contributes nothing, rather than aborting verification of the rest of the
  bundle or leaking a bare Python exception.
- `checkpoint` and `policy` are the trusted, verifier-config side of the
  call (mirrors `tlog.verify_checkpoint`'s `log_key`/`expected_origin`
  arguments): a non-`tlog.Checkpoint` `checkpoint` or a malformed `AnchorPolicy`
  raises `AnchorError` instead, since that signals a caller bug, not
  adversarial input.
- `passes_horizon` is a pure function of `(verdict, policy)`: `AnchorError`
  only on a malformed `policy`, never on `verdict` content (even a
  hand-built `AnchorVerdict` with wrong field types degrades to `False`
  rather than raising).

Hex fields throughout are validated lowercase-only and, where the schema
fixes a length (a 32-byte SHA-256 digest, 64 hex chars), exactly that
length, BEFORE any `bytes.fromhex` call — `bytes.fromhex` itself happily
accepts uppercase and would silently normalize an out-of-schema encoding.
List and hex-operand sizes on untrusted evidence are capped (see the
`_MAX_*` constants below) so a hostile bundle cannot force unbounded work.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from attest import tlog

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^[0-9a-f]*$")

# Caps bounding attacker-controlled work while walking untrusted evidence.
# A real corroboration bundle carries a handful of proofs and a handful of
# ops per OTS attestation; these are generous headroom over that, not tuned
# limits — see tlog.py's `_MAX_NOTE_SIGNATURES` for the same rationale.
_MAX_PROOFS_PER_EVIDENCE = 64
_MAX_OPS_PER_PROOF = 64
_MAX_OP_HEX_LEN = 2048  # hex chars (1024 bytes) per append/prepend operand

_KNOWN_OTS_OPS = frozenset({"sha256", "append", "prepend"})

_RFC3161_WARNING = (
    "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight"
)


class AnchorError(ValueError):
    """A trusted anchor-verifier argument (`AnchorPolicy` or `checkpoint`) is malformed.

    Never raised for malformed `evidence` — that boundary reports through
    `AnchorVerdict.warnings` instead, see `verify_anchor`.
    """


@dataclass(frozen=True)
class PinnedHeader:
    """A Bitcoin block header pinned out-of-band into the verifier's trust
    store — never taken from the untrusted evidence bundle itself."""

    header_hash: str
    merkle_root: str
    time: int


@dataclass(frozen=True)
class AnchorPolicy:
    """The verifier's anchor trust store and CRQC cutoff.

    `pinned_headers` is keyed by `header_hash` (each value's own
    `header_hash` field must match its key — see `_validate_policy`).
    `crqc_horizon` is a unix-seconds cutoff; `None` means no cutoff is
    configured (every PQ-anchored checkpoint passes).
    """

    pinned_headers: dict[str, PinnedHeader]
    crqc_horizon: int | None


@dataclass(frozen=True)
class AnchorVerdict:
    """The outcome of `verify_anchor` over one evidence bundle.

    `anchored_before` is the minimum pinned header time over verified `ots`
    (PQ-surviving) proofs only — `rfc3161` proofs never set it, even when
    `anchored` is `True` from `rfc3161` corroboration alone.
    """

    anchored: bool
    anchored_before: int | None
    pq_surviving: bool
    warnings: list[str]


def _trunc(value: object, limit: int = 80) -> str:
    """Bound an untrusted value's repr before it goes into a warning message
    — evidence is attacker-controlled, and warnings must not become an
    amplification vector for a hostile-sized field."""
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _validate_policy(policy: object) -> AnchorPolicy:
    """Validate every `AnchorPolicy` field before it's trusted. Raises
    `AnchorError` — `policy` is assembled by the verifier's own config, not
    adversarial evidence, so a malformed policy is a caller bug to surface
    loudly, not degrade gracefully."""
    if not isinstance(policy, AnchorPolicy):
        raise AnchorError(f"policy must be an AnchorPolicy, got {type(policy).__name__}")
    if not isinstance(policy.pinned_headers, dict):
        raise AnchorError("policy.pinned_headers must be a dict")
    for header_hash, header in policy.pinned_headers.items():
        if not isinstance(header_hash, str) or not _HEX64_RE.fullmatch(header_hash):
            raise AnchorError(f"pinned_headers key must be 64 lowercase hex chars: {header_hash!r}")
        if not isinstance(header, PinnedHeader):
            raise AnchorError(f"pinned_headers[{header_hash!r}] must be a PinnedHeader")
        if not isinstance(header.header_hash, str) or not _HEX64_RE.fullmatch(header.header_hash):
            raise AnchorError(
                f"PinnedHeader.header_hash must be 64 lowercase hex chars: {header.header_hash!r}"
            )
        if header.header_hash != header_hash:
            raise AnchorError(
                f"pinned_headers key {header_hash!r} != "
                f"PinnedHeader.header_hash {header.header_hash!r}"
            )
        if not isinstance(header.merkle_root, str) or not _HEX64_RE.fullmatch(header.merkle_root):
            raise AnchorError(
                f"PinnedHeader.merkle_root must be 64 lowercase hex chars: {header.merkle_root!r}"
            )
        if not isinstance(header.time, int) or isinstance(header.time, bool) or header.time <= 0:
            raise AnchorError(f"PinnedHeader.time must be a positive int: {header.time!r}")
    if policy.crqc_horizon is not None and (
        not isinstance(policy.crqc_horizon, int) or isinstance(policy.crqc_horizon, bool)
    ):
        raise AnchorError(f"policy.crqc_horizon must be an int or None: {policy.crqc_horizon!r}")
    return policy


def _hex64(value: object) -> bytes | None:
    """Decode a strict 64-char lowercase-hex (32-byte SHA-256) field, or
    `None` if `value` doesn't have exactly that shape. Charset/length are
    checked BEFORE `bytes.fromhex`, which accepts uppercase on its own."""
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        return None
    return bytes.fromhex(value)


def _op_hex(value: object) -> bytes | None:
    """Decode a bounded, even-length, lowercase-hex op operand, or `None`."""
    if (
        not isinstance(value, str)
        or len(value) > _MAX_OP_HEX_LEN
        or len(value) % 2 != 0
        or not _HEX_RE.fullmatch(value)
    ):
        return None
    return bytes.fromhex(value)


def _verify_ots_proof(
    proof: dict[str, Any], accumulator_start: bytes, policy: AnchorPolicy
) -> tuple[bool, int, str | None]:
    """Evaluate one `ots` proof: replay its op-chain from `accumulator_start`
    and cross-check the result against a header pinned in `policy`.

    Returns `(verified, header_time, warning)`. `header_time` is only
    meaningful when `verified` is `True` (it's the PINNED header's own
    time, not the proof's untrusted claim — the two are required to match
    before `verified` can be `True` at all, see the final check below).
    `warning` names the failure reason and is `None` only when `verified`
    is `True`.
    """
    ops = proof.get("ops")
    if not isinstance(ops, list):
        return False, 0, "ots proof 'ops' must be a list"
    if len(ops) > _MAX_OPS_PER_PROOF:
        return False, 0, f"ots proof has more than {_MAX_OPS_PER_PROOF} ops"

    root_bytes = _hex64(proof.get("header_merkle_root"))
    if root_bytes is None:
        return False, 0, "ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    header_hash = proof.get("header_hash")
    if not isinstance(header_hash, str) or not _HEX64_RE.fullmatch(header_hash):
        return False, 0, "ots proof 'header_hash' must be 64 lowercase hex chars"
    header_time = proof.get("header_time")
    if not isinstance(header_time, int) or isinstance(header_time, bool) or header_time <= 0:
        return False, 0, "ots proof 'header_time' must be a positive int"

    accumulator = accumulator_start
    for op in ops:
        if not isinstance(op, list) or not op or not isinstance(op[0], str):
            return False, 0, "ots op must be a non-empty list with a string opcode"
        opcode = op[0]
        if opcode not in _KNOWN_OTS_OPS:
            return False, 0, f"unknown ots op {_trunc(opcode)}"
        if opcode == "sha256":
            if len(op) != 1:
                return False, 0, "ots 'sha256' op takes no operand"
            accumulator = hashlib.sha256(accumulator).digest()
        else:
            if len(op) != 2:
                return False, 0, f"ots {opcode!r} op needs exactly one hex operand"
            operand = _op_hex(op[1])
            if operand is None:
                return (
                    False,
                    0,
                    f"ots {opcode!r} operand must be bounded, even-length lowercase hex",
                )
            accumulator = accumulator + operand if opcode == "append" else operand + accumulator

    if not hmac.compare_digest(accumulator, root_bytes):
        return False, 0, "ots op-chain result does not match header_merkle_root"

    pinned = policy.pinned_headers.get(header_hash)
    if pinned is None:
        return False, 0, "header_hash is not in policy.pinned_headers"
    if pinned.merkle_root != proof.get("header_merkle_root") or pinned.time != header_time:
        return False, 0, "pinned header merkle_root/time does not match proof"

    return True, pinned.time, None


def verify_anchor(
    evidence: dict[str, Any], checkpoint: tlog.Checkpoint, policy: AnchorPolicy
) -> AnchorVerdict:
    """Verify an anchor-evidence bundle against `checkpoint` and `policy`.

    `evidence` is untrusted (comes from wherever the bundle was fetched) and
    this function NEVER raises because of it: any malformation — not a
    dict, `proofs` not a list, an oversized proof/op list, a non-dict proof,
    bad hex, an unknown op, a header not pinned — degrades to an
    `AnchorVerdict(anchored=False, ...)` with a warning naming the problem,
    and per-proof malformations simply drop that one proof rather than
    aborting the whole bundle (forward-compat: an unrecognized `kind` must
    not brick an old verifier reading a bundle produced by a newer one).

    `checkpoint` and `policy` are the trusted, verifier-config side: a
    non-`tlog.Checkpoint` `checkpoint` or a malformed `policy` raises
    `AnchorError` instead of degrading, since that's a caller bug.
    """
    if not isinstance(checkpoint, tlog.Checkpoint):
        raise AnchorError(f"checkpoint must be a tlog.Checkpoint, got {type(checkpoint).__name__}")
    policy = _validate_policy(policy)

    warnings: list[str] = []
    if not isinstance(evidence, dict):
        warnings.append(f"evidence must be an object, got {type(evidence).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    proofs = evidence.get("proofs")
    if not isinstance(proofs, list):
        warnings.append(f"evidence.proofs must be a list, got {type(proofs).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    if len(proofs) > _MAX_PROOFS_PER_EVIDENCE:
        warnings.append(f"evidence.proofs exceeds max length {_MAX_PROOFS_PER_EVIDENCE}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    accumulator_start = hashlib.sha256(checkpoint.note_bytes).digest()
    anchored = False
    pq_surviving = False
    anchored_before: int | None = None

    for i, proof in enumerate(proofs):
        if not isinstance(proof, dict):
            warnings.append(f"proof[{i}]: must be an object, got {type(proof).__name__}")
            continue
        kind = proof.get("kind")
        if kind == "ots":
            verified, header_time, warning = _verify_ots_proof(proof, accumulator_start, policy)
            if warning is not None:
                warnings.append(f"proof[{i}]: {warning}")
            if verified:
                anchored = True
                pq_surviving = True
                if anchored_before is None or header_time < anchored_before:
                    anchored_before = header_time
        elif kind == "rfc3161":
            token_b64 = proof.get("token_b64")
            if not isinstance(token_b64, str):
                warnings.append(
                    f"proof[{i}]: rfc3161 token_b64 must be a str, got {type(token_b64).__name__}"
                )
                continue
            anchored = True
            warnings.append(_RFC3161_WARNING)
        else:
            warnings.append(f"proof[{i}]: unknown proof kind {_trunc(kind)}, ignored")

    return AnchorVerdict(
        anchored=anchored,
        anchored_before=anchored_before,
        pq_surviving=pq_surviving,
        warnings=warnings,
    )


def passes_horizon(verdict: AnchorVerdict, policy: AnchorPolicy) -> bool:
    """True iff `policy.crqc_horizon is None`, or `verdict` is a PQ-surviving
    anchor whose time is strictly before the horizon.

    Pure function of `(verdict, policy)`: raises `AnchorError` only on a
    malformed `policy` (trusted, verifier-config side). Never raises on
    `verdict` — even a hand-built `AnchorVerdict` with wrong field types
    degrades to `False` rather than raising, since `verdict` carries no
    caller-config trust boundary of its own to enforce here.
    """
    policy = _validate_policy(policy)
    if policy.crqc_horizon is None:
        return True
    if not isinstance(verdict, AnchorVerdict):
        return False
    anchored_before = verdict.anchored_before
    if not isinstance(anchored_before, int) or isinstance(anchored_before, bool):
        return False
    return bool(verdict.pq_surviving) and anchored_before < policy.crqc_horizon
