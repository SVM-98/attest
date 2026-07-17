"""RFC 6962 Merkle tree verification primitives and closed transparency-log
entry schemas — Stage 2 (design §2.1.1/§2.1.2).

Scope: this module is the foundation every later Stage-2 task builds on. It
provides:

- Leaf/interior node hashing (`leaf_hash`, `node_hash`) per RFC 6962 §2.1.
- Verification of an inclusion proof (`verify_inclusion`, §2.1.1) and a
  consistency proof (`verify_consistency`, §2.1.2) against an untrusted
  proof list — both fail closed on any malformed input, never raise.
- Builder-side tree construction (`build_tree`, `inclusion_proof`,
  `consistency_proof`) used by `gen_vectors` and the CLI to produce the
  proofs the verify functions above consume. These operate on trusted,
  well-formed input and raise `ValueError` on invalid arguments (index out
  of range, unsorted sizes) rather than failing closed — there is no
  untrusted-input boundary here.
- `encode_entry`, which validates a log entry against the two CLOSED entry
  schemas below and returns its canonical (attest-JCS) bytes — the exact
  bytes that get leaf-hashed into the log.

Verification here NEVER trusts caller-declared shapes: proof elements are
type/length-checked before use, and comparisons use `hmac.compare_digest`
throughout (constant-time; malformed proofs are not a valid channel to leak
timing on legitimate log state).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from attest import canon

_HASH_LEN = 32  # SHA-256 digest length in bytes
_LEAF_PREFIX = b"\x00"  # RFC 6962 §2.1: MTH({d(0)}) = SHA-256(0x00 || d(0))
_NODE_PREFIX = b"\x01"  # RFC 6962 §2.1: MTH(D[n]) = SHA-256(0x01 || left || right)

_TYPE_KEY_MANIFEST = "key-manifest"
_TYPE_RECEIPT = "receipt"
_KEY_MANIFEST_FIELDS = frozenset({"type", "issuer", "manifest_version", "manifest_sha256"})
_RECEIPT_FIELDS = frozenset({"type", "issuer", "core_sha256"})

# Same lowercase-DNS shape as the receipt schema's `issuer.id` pattern
# (src/attest/schema/attest-receipt.schema.json) — kept in sync by hand,
# this module has no schema-file dependency.
_ISSUER_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class TlogError(ValueError):
    """A log entry does not conform to one of the closed entry schemas."""


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 §2.1 leaf hash: `SHA-256(0x00 || data)`."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1 interior node hash: `SHA-256(0x01 || left || right)`."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than `n` (RFC 6962 calls this `k`).

    Callers only invoke this for `n >= 2`, where the result is always well
    defined (`k` in `[1, n)`).
    """
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# --------------------------------------------------------------------------
# Builder side: construction (trusted input, O(n log n)).
# --------------------------------------------------------------------------


def build_tree(leaves: list[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle Tree Hash (MTH) of `leaves`.

    `MTH({}) = SHA-256()` (hash of the empty string — no leaf prefix byte;
    this is the sole exception to the leaf/node hashing scheme, defined
    directly by RFC 6962 §2.1). `MTH({d0}) = leaf_hash(d0)`. For `n > 1`,
    split at `k = largest power of two < n` and combine the two subtree
    roots with `node_hash`.
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return node_hash(build_tree(leaves[:k]), build_tree(leaves[k:]))


def _path(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 §2.1.1 `PATH(m, D[n])`, ordered leaf-adjacent-first.

    `PATH(m, {d0}) = {}`. For `n > 1`, split at `k`; if `m < k` recurse into
    the left subtree and append the right subtree's root, else recurse into
    the right subtree (re-based index `m - k`) and append the left
    subtree's root. Recursion runs before the append, so the proof is
    built bottom (near the leaf) to top (near the root) — the order
    `verify_inclusion` expects.
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return [*_path(leaves[:k], m), build_tree(leaves[k:])]
    return [*_path(leaves[k:], m - k), build_tree(leaves[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Build the RFC 6962 §2.1.1 audit path for `leaves[index]`."""
    n = len(leaves)
    if not isinstance(index, int) or index < 0 or index >= n:
        raise ValueError(f"index {index!r} out of range for {n} leaves")
    return _path(leaves, index)


def _subproof(leaves: list[bytes], m: int, b: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 `SUBPROOF(m, D[n], b)`.

    `b` is true only on the initial call: once the recursion has taken the
    "right subtree" branch, the boundary between old/new tree no longer
    passes through the root of what remains, so the base case must emit an
    explicit subtree hash instead of an empty proof.
    """
    n = len(leaves)
    if m == n:
        return [] if b else [build_tree(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return [*_subproof(leaves[:k], m, b), build_tree(leaves[k:])]
    return [*_subproof(leaves[k:], m - k, False), build_tree(leaves[:k])]


def consistency_proof(leaves: list[bytes], size1: int) -> list[bytes]:
    """Build the RFC 6962 §2.1.2 consistency proof between the size-`size1`
    prefix of `leaves` and `leaves` itself (size `len(leaves)`).

    `size1 == 0` (consistency against the empty tree) is vacuous — RFC 6962
    defines no proof in that case, so this returns `[]` directly rather
    than recursing (the general `SUBPROOF` recursion is only defined for
    `1 <= m <= n`).
    """
    n = len(leaves)
    if not isinstance(size1, int) or size1 < 0 or size1 > n:
        raise ValueError(f"size1={size1!r} out of range for {n} leaves")
    if size1 == 0:
        return []
    return _subproof(leaves, size1, True)


# --------------------------------------------------------------------------
# Verification side: untrusted proof input, fail-closed, never raises.
# --------------------------------------------------------------------------


def _valid_proof_shape(proof: object) -> bool:
    return isinstance(proof, list) and all(
        isinstance(p, bytes) and len(p) == _HASH_LEN for p in proof
    )


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """RFC 6962 §2.1.1 inclusion proof verification, iterative.

    Fail-closed: any malformed argument (wrong types, out-of-range index,
    wrongly-shaped proof elements, too-short/too-long proof) returns
    `False` rather than raising — `leaf`/`index`/`proof`/`root` all arrive
    from an untrusted log server.
    """
    if not isinstance(leaf, bytes) or not isinstance(root, bytes):
        return False
    if not isinstance(index, int) or isinstance(index, bool):
        return False
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        return False
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False
    if not _valid_proof_shape(proof):
        return False

    fn, sn = index, tree_size - 1
    computed = leaf
    for sibling in proof:
        if sn == 0:
            return False  # proof has more elements than the path to the root
        if fn % 2 == 1 or fn == sn:
            computed = node_hash(sibling, computed)
            # `fn` was the lone (unpaired) rightmost node at this level: climb
            # without consuming further proof elements until it either
            # becomes a right child (a real sibling exists) or reaches root.
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            computed = node_hash(computed, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and hmac.compare_digest(computed, root)


def verify_consistency(
    size1: int, root1: bytes, size2: int, root2: bytes, proof: list[bytes]
) -> bool:
    """RFC 6962 §2.1.2 consistency proof verification, iterative.

    Fail-closed: any malformed argument returns `False` rather than
    raising.
    """
    if not isinstance(size1, int) or isinstance(size1, bool):
        return False
    if not isinstance(size2, int) or isinstance(size2, bool):
        return False
    if not isinstance(root1, bytes) or not isinstance(root2, bytes):
        return False
    if size1 < 0 or size2 < 0 or size1 > size2:
        return False
    if not _valid_proof_shape(proof):
        return False

    if size1 == size2:
        return len(proof) == 0 and hmac.compare_digest(root1, root2)
    if size1 == 0:
        return len(proof) == 0

    node, last_node = size1 - 1, size2 - 1
    idx = 0
    n_proof = len(proof)

    while node % 2 == 1:
        node //= 2
        last_node //= 2

    if node > 0:
        if idx >= n_proof:
            return False
        new_hash = proof[idx]
        old_hash = proof[idx]
        idx += 1
    else:
        new_hash = root1
        old_hash = root1

    while node > 0:
        if node % 2 == 1:
            if idx >= n_proof:
                return False
            sibling = proof[idx]
            idx += 1
            new_hash = node_hash(sibling, new_hash)
            old_hash = node_hash(sibling, old_hash)
        elif node < last_node:
            if idx >= n_proof:
                return False
            sibling = proof[idx]
            idx += 1
            new_hash = node_hash(new_hash, sibling)
        node //= 2
        last_node //= 2

    if not hmac.compare_digest(old_hash, root1):
        return False

    while last_node > 0:
        if idx >= n_proof:
            return False
        sibling = proof[idx]
        idx += 1
        new_hash = node_hash(new_hash, sibling)
        last_node //= 2

    if idx != n_proof:
        return False  # unconsumed proof elements

    return hmac.compare_digest(new_hash, root2)


# --------------------------------------------------------------------------
# Closed log-entry schemas.
# --------------------------------------------------------------------------


def _require_fields(entry: dict[str, Any], expected: frozenset[str]) -> None:
    actual = frozenset(entry.keys())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise TlogError(f"entry field mismatch: missing={missing} extra={extra}")


def _require_issuer(entry: dict[str, Any]) -> None:
    issuer = entry.get("issuer")
    if not isinstance(issuer, str) or not _ISSUER_RE.match(issuer):
        raise TlogError(f"issuer must be a lowercase DNS name: {issuer!r}")


def _require_hex64(entry: dict[str, Any], field: str) -> None:
    value = entry.get(field)
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise TlogError(f"{field} must be 64 lowercase hex characters: {value!r}")


def _require_manifest_version(entry: dict[str, Any]) -> None:
    version = entry.get("manifest_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise TlogError(f"manifest_version must be an int >= 1: {version!r}")


def encode_entry(entry: dict[str, Any]) -> bytes:
    """Validate `entry` against a CLOSED schema and return its canonical
    (attest-JCS) bytes — the exact bytes that get leaf-hashed into the log.

    Two entry types, exactly these members each (extras rejected):

    - `key-manifest`: `{"type", "issuer", "manifest_version", "manifest_sha256"}`,
      where `manifest_sha256 = SHA-256(JCS(manifest))` (lowercase hex).
    - `receipt`: `{"type", "issuer", "core_sha256"}`, where `core_sha256` is
      the Task 5 signed-receipt-core hash (lowercase hex). `issuer` here is
      a NON-authenticated hint only — a convenience for log browsing/
      filtering, never a trust anchor; the receipt's own signature is what
      binds it to an issuer.

    Raises `TlogError` on an unknown `type`, a missing/extra member, or a
    member with the wrong value shape.
    """
    if not isinstance(entry, dict):
        raise TlogError(f"entry must be an object, got {type(entry).__name__}")

    entry_type = entry.get("type")
    if entry_type == _TYPE_KEY_MANIFEST:
        _require_fields(entry, _KEY_MANIFEST_FIELDS)
        _require_issuer(entry)
        _require_manifest_version(entry)
        _require_hex64(entry, "manifest_sha256")
    elif entry_type == _TYPE_RECEIPT:
        _require_fields(entry, _RECEIPT_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "core_sha256")
    else:
        raise TlogError(f"unknown entry type: {entry_type!r}")

    return canon.dumps(entry).encode("utf-8")
