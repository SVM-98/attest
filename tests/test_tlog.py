"""RFC 6962 Merkle tree primitives + closed transparency-log entry schemas.

Known-answer tests (KATs) for the empty/1-leaf/2-leaf/3-leaf/7-leaf roots are
hand-pinned `bytes.fromhex` literals, derived by hand from the RFC 6962
§2.1 construction (shown in the comments below) — never computed through
`attest.tlog` itself. Consistency proofs are checked via round-trip properties
against the module's own builder/verify pair, which is the only practical way
to exercise every size pair; the KATs pin the hashing scheme itself.
"""

from __future__ import annotations

import base64
import hashlib
from typing import cast

import pytest

from attest import keys, pq, tlog

LEAVES = [bytes([i]) for i in range(7)]  # b"\x00", b"\x01", ... b"\x06"


# --------------------------------------------------------------------------
# Known-answer tests, hand-computed from RFC 6962 §2.1:
#   leaf_hash(d)    = SHA-256(0x00 || d)
#   node_hash(l, r) = SHA-256(0x01 || l || r)
#   MTH({})         = SHA-256("")                              (no prefix byte)
#   MTH({d0})       = leaf_hash(d0)
#   MTH(D[n])       = node_hash(MTH(D[0:k]), MTH(D[k:n])), k = largest pow2 < n
# --------------------------------------------------------------------------


def test_empty_tree_root_is_sha256_of_empty_string() -> None:
    # MTH({}) = SHA-256() per RFC 6962 §2.1, no leaf/node prefix byte at all.
    expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert tlog.build_tree([]) == expected


def test_one_leaf_tree_root_is_leaf_hash() -> None:
    # MTH({d0}) = leaf_hash(d0) = SHA-256(0x00 || d0), d0 = b"\x00".
    # Hand construction: sha256(b"\x00\x00").
    expected = bytes.fromhex("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7")
    assert tlog.build_tree(LEAVES[:1]) == expected


def test_two_leaf_tree_root() -> None:
    # k = largest pow2 < 2 = 1. MTH([d0,d1]) = node_hash(leaf_hash(d0), leaf_hash(d1)).
    # Hand construction: h0 = sha256(0x00||d0), h1 = sha256(0x00||d1),
    #                     root = sha256(0x01 || h0 || h1).
    expected = bytes.fromhex("a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a")
    assert tlog.build_tree(LEAVES[:2]) == expected


def test_three_leaf_tree_root() -> None:
    # k = largest pow2 < 3 = 2. MTH([d0,d1,d2]) = node_hash(MTH([d0,d1]), MTH([d2])).
    # Hand construction: h0,h1 as above, h2 = sha256(0x00||d2),
    #                     left = sha256(0x01||h0||h1), root = sha256(0x01||left||h2).
    expected = bytes.fromhex("3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688")
    assert tlog.build_tree(LEAVES[:3]) == expected


def test_seven_leaf_tree_root() -> None:
    # Independently computed with hashlib.sha256, never attest.tlog: h0 through h6
    # are hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(7), then:
    # n01 = hashlib.sha256(b"\x01" + h0 + h1).digest()
    # n23 = hashlib.sha256(b"\x01" + h2 + h3).digest()
    # left = hashlib.sha256(b"\x01" + n01 + n23).digest()
    # n45 = hashlib.sha256(b"\x01" + h4 + h5).digest()
    # right = hashlib.sha256(b"\x01" + n45 + h6).digest()
    # root = hashlib.sha256(b"\x01" + left + right).digest()
    expected = bytes.fromhex("3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3")
    assert tlog.build_tree(LEAVES) == expected


def test_leaf_hash_matches_rfc_prefix_scheme() -> None:
    assert tlog.leaf_hash(b"\x00") == hashlib.sha256(b"\x00\x00").digest()


def test_node_hash_matches_rfc_prefix_scheme() -> None:
    left = tlog.leaf_hash(b"\x00")
    right = tlog.leaf_hash(b"\x01")
    assert tlog.node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()


# --------------------------------------------------------------------------
# Inclusion proof: round-trip for every index of a 7-leaf tree.
# --------------------------------------------------------------------------


def test_inclusion_round_trip_every_index_of_seven_leaf_tree() -> None:
    root = tlog.build_tree(LEAVES)
    for index in range(len(LEAVES)):
        proof = tlog.inclusion_proof(LEAVES, index)
        leaf = tlog.leaf_hash(LEAVES[index])
        assert tlog.verify_inclusion(leaf, index, len(LEAVES), proof, root)


def test_inclusion_round_trip_single_leaf_tree() -> None:
    root = tlog.build_tree(LEAVES[:1])
    proof = tlog.inclusion_proof(LEAVES[:1], 0)
    assert proof == []
    assert tlog.verify_inclusion(tlog.leaf_hash(LEAVES[0]), 0, 1, proof, root)


def test_inclusion_fails_on_wrong_root() -> None:
    proof = tlog.inclusion_proof(LEAVES, 3)
    wrong_root = bytes(32)
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), proof, wrong_root)


def test_inclusion_fails_on_wrong_index() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 2, len(LEAVES), proof, root)


def test_inclusion_fails_on_truncated_proof() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    assert proof  # sanity: 7-leaf tree at index 3 has a non-empty path
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), proof[:-1], root)


def test_inclusion_fails_on_oversized_proof() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    bogus = [*proof, bytes(32)]
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), bogus, root)


def test_inclusion_fails_closed_on_malformed_shapes() -> None:
    root = tlog.build_tree(LEAVES)
    leaf = tlog.leaf_hash(LEAVES[0])
    proof = tlog.inclusion_proof(LEAVES, 0)
    assert not tlog.verify_inclusion(leaf, -1, len(LEAVES), proof, root)
    assert not tlog.verify_inclusion(leaf, 0, 0, proof, root)
    assert not tlog.verify_inclusion(leaf, 99, len(LEAVES), proof, root)
    assert not tlog.verify_inclusion(leaf, 0, len(LEAVES), [b"short"], root)  # not 32 bytes
    assert not tlog.verify_inclusion(leaf, 0, len(LEAVES), ["not-bytes"], root)  # type: ignore[list-item]
    assert not tlog.verify_inclusion(leaf, "0", len(LEAVES), proof, root)  # type: ignore[arg-type]


@pytest.mark.parametrize("malformed_digest", [b"x", b"x" * 33])
def test_inclusion_rejects_short_or_long_leaf_and_root(
    malformed_digest: bytes,
) -> None:
    assert not tlog.verify_inclusion(malformed_digest, 0, 1, [], malformed_digest)


# --------------------------------------------------------------------------
# Consistency proof: round-trip for every (size1, size2 <= 7) pair.
# --------------------------------------------------------------------------


def test_consistency_round_trip_every_size_pair_up_to_seven_leaves() -> None:
    for size2 in range(0, len(LEAVES) + 1):
        leaves2 = LEAVES[:size2]
        root2 = tlog.build_tree(leaves2)
        for size1 in range(0, size2 + 1):
            root1 = tlog.build_tree(LEAVES[:size1])
            proof = tlog.consistency_proof(leaves2, size1)
            assert tlog.verify_consistency(size1, root1, size2, root2, proof)


def test_consistency_fails_on_cross_tree_roots() -> None:
    root1 = tlog.build_tree(LEAVES[:3])
    root2 = tlog.build_tree(LEAVES[:7])
    wrong_root2 = tlog.build_tree(LEAVES[:6])
    proof = tlog.consistency_proof(LEAVES[:7], 3)
    assert tlog.verify_consistency(3, root1, 7, root2, proof)
    assert not tlog.verify_consistency(3, root1, 7, wrong_root2, proof)
    wrong_root1 = tlog.build_tree(LEAVES[:2])
    assert not tlog.verify_consistency(3, wrong_root1, 7, root2, proof)


def test_consistency_fails_closed_on_malformed_shapes() -> None:
    root1 = tlog.build_tree(LEAVES[:3])
    root2 = tlog.build_tree(LEAVES[:7])
    proof = tlog.consistency_proof(LEAVES[:7], 3)
    assert not tlog.verify_consistency(7, root2, 3, root1, proof)  # size1 > size2
    assert not tlog.verify_consistency(3, root1, 7, root2, proof[:-1])  # truncated
    assert not tlog.verify_consistency(3, root1, 7, root2, [*proof, bytes(32)])  # oversized
    assert not tlog.verify_consistency(3, root1, 7, root2, [b"short"])  # not 32 bytes
    assert not tlog.verify_consistency("3", root1, 7, root2, proof)  # type: ignore[arg-type]


@pytest.mark.parametrize("malformed_digest", [b"x", b"x" * 33])
def test_consistency_rejects_short_or_long_roots(malformed_digest: bytes) -> None:
    assert not tlog.verify_consistency(1, malformed_digest, 1, malformed_digest, [])
    assert not tlog.verify_consistency(0, malformed_digest, 1, malformed_digest, [])


def test_consistency_empty_old_tree_is_vacuously_true() -> None:
    root2 = tlog.build_tree(LEAVES[:5])
    assert tlog.verify_consistency(0, bytes(32), 5, root2, [])


def test_consistency_equal_sizes_requires_matching_root_and_empty_proof() -> None:
    root = tlog.build_tree(LEAVES[:4])
    assert tlog.verify_consistency(4, root, 4, root, [])
    assert not tlog.verify_consistency(4, root, 4, root, [bytes(32)])
    assert not tlog.verify_consistency(4, root, 4, bytes(32), [])


def test_inclusion_proof_raises_on_out_of_range_index() -> None:
    with pytest.raises(ValueError, match="out of range"):
        tlog.inclusion_proof(LEAVES, len(LEAVES))
    with pytest.raises(ValueError, match="out of range"):
        tlog.inclusion_proof(LEAVES, -1)


def test_consistency_proof_raises_on_out_of_range_size1() -> None:
    with pytest.raises(ValueError, match="out of range"):
        tlog.consistency_proof(LEAVES, len(LEAVES) + 1)
    with pytest.raises(ValueError, match="out of range"):
        tlog.consistency_proof(LEAVES, -1)


# --------------------------------------------------------------------------
# encode_entry: closed schemas.
# --------------------------------------------------------------------------


def _valid_key_manifest_entry() -> dict[str, object]:
    return {
        "type": "key-manifest",
        "issuer": "shop.example.com",
        "manifest_version": 1,
        "manifest_sha256": "a" * 64,
    }


def _valid_receipt_entry() -> dict[str, object]:
    return {
        "type": "receipt",
        "issuer": "shop.example.com",
        "core_sha256": "b" * 64,
    }


def test_encode_entry_accepts_valid_key_manifest_entry() -> None:
    entry = _valid_key_manifest_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    # Round-trips through the canonicalizer used to produce it.
    from attest import canon

    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_accepts_valid_receipt_entry() -> None:
    entry = _valid_receipt_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)


def test_encode_entry_rejects_unknown_type() -> None:
    entry = _valid_receipt_entry()
    entry["type"] = "bogus"
    with pytest.raises(tlog.TlogError, match="unknown entry type"):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_extra_member() -> None:
    entry = _valid_receipt_entry()
    entry["extra_field"] = "nope"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_mixed_type_extra_keys() -> None:
    entry = _valid_receipt_entry()
    entry[1] = "nope"  # type: ignore[index]
    entry["extra_field"] = "nope"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_missing_member() -> None:
    entry = _valid_receipt_entry()
    del entry["issuer"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_uppercase_hex() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "B" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_non_int_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = "1"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_version_below_one() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 0
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_accepts_largest_jcs_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 2**53 - 1
    assert tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_version_above_jcs_limit() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 2**53
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_bool_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = True
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_uppercase_issuer() -> None:
    entry = _valid_receipt_entry()
    entry["issuer"] = "Shop.Example.com"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_issuer_with_trailing_newline() -> None:
    entry = _valid_receipt_entry()
    entry["issuer"] = "shop.example.com\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_non_dict_entry() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry([])  # type: ignore[arg-type]


def test_encode_entry_rejects_short_hex() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "b" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_hash_with_trailing_newline() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_sha256"] = "a" * 64 + "\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_core_hash_with_trailing_newline() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "b" * 64 + "\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


# --------------------------------------------------------------------------
# Hybrid signed-note checkpoints: parse_checkpoint / verify_checkpoint /
# sign_checkpoint.
# --------------------------------------------------------------------------

ORIGIN = "log.attest.example/2026"
LOG_NAME = "attest-log-1"
ROOT = hashlib.sha256(b"checkpoint-test-root").digest()


def _hybrid_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _log_key(hk: pq.HybridSigningKeys, origin: str = ORIGIN, name: str = LOG_NAME) -> tlog.LogKey:
    return tlog.LogKey(origin=origin, name=name, ed25519_pub=hk.ed.pub, mldsa_pub=hk.mldsa.pub)


def _signed_checkpoint(
    tree_size: int = 5, root: bytes = ROOT, origin: str = ORIGIN, name: str = LOG_NAME
) -> tuple[str, pq.HybridSigningKeys]:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(origin, tree_size, root, hk, name)
    return text, hk


def _corrupt_line(text: str, index: int, new_line: str) -> str:
    lines = text.split("\n")
    lines[index] = new_line
    return "\n".join(lines)


# --- parse_checkpoint: structural validation only -------------------------


def test_parse_checkpoint_round_trip() -> None:
    text, _hk = _signed_checkpoint(tree_size=7, root=ROOT, origin=ORIGIN)
    checkpoint = tlog.parse_checkpoint(text)
    assert checkpoint.origin == ORIGIN
    assert checkpoint.tree_size == 7
    assert checkpoint.root == ROOT
    expected_note = f"{ORIGIN}\n7\n{base64.b64encode(ROOT).decode('ascii')}\n"
    assert checkpoint.note_bytes == expected_note.encode("utf-8")


def test_sign_checkpoint_ed25519_signature_uses_c2sp_note_boundary() -> None:
    text, hk = _signed_checkpoint()
    checkpoint = tlog.parse_checkpoint(text)
    _dash, _name, blob_b64 = text.split("\n")[4].split(" ", 2)
    signature = base64.b64decode(blob_b64)[4:]
    assert keys.verify_strict(checkpoint.note_bytes, signature, hk.ed.pub)
    assert not keys.verify_strict(checkpoint.note_bytes + b"\n", signature, hk.ed.pub)


def test_parse_checkpoint_rejects_zero_signature_lines() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize("origin", ["", "bad\x1forigin", "bad\x7forigin"])
def test_parse_checkpoint_rejects_empty_or_control_character_origin(origin: str) -> None:
    text = f"{origin}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_missing_blank_line() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\nnot-blank\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_two_line_body() -> None:
    # Root line entirely missing: only origin + size before the blank line.
    text = f"{ORIGIN}\n3\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_decimal_size() -> None:
    text = f"{ORIGIN}\nfive\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_negative_size() -> None:
    text = f"{ORIGIN}\n-3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_leading_zero_size() -> None:
    text = f"{ORIGIN}\n01\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_accepts_uint64_max_size() -> None:
    text = f"{ORIGIN}\n{2**64 - 1}\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    assert tlog.parse_checkpoint(text).tree_size == 2**64 - 1


def test_parse_checkpoint_rejects_uint64_overflow_size() -> None:
    text = f"{ORIGIN}\n{2**64}\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_oversized_decimal_size() -> None:
    # A 5000-digit tree size must fail closed as TlogError, not leak the
    # bare ValueError CPython's int() raises past its digit-string limit
    # (3.11+ default 4300 digits) -- and must not pay the O(n^2) parse cost.
    huge_size = "9" * 5000
    text = f"{ORIGIN}\n{huge_size}\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_ascii_digit_size() -> None:
    # str.isdigit() accepts non-decimal Unicode digit-value characters
    # (e.g. superscript "²") that int() then rejects -- must fail
    # closed as TlogError, not leak a bare ValueError.
    text = f"{ORIGIN}\n²²²\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_root_not_32_bytes() -> None:
    short_root_b64 = base64.b64encode(bytes(31)).decode("ascii")
    text = f"{ORIGIN}\n3\n{short_root_b64}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_bad_base64_root() -> None:
    text = f"{ORIGIN}\n3\nnot-valid-base64!!\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_missing_trailing_newline() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text[:-1])


def test_parse_checkpoint_rejects_malformed_signature_line() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\nnot-a-signature-line\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_signature_line_with_wrong_dash() -> None:
    # Plain hyphen instead of U+2014 em dash: must be rejected, not tolerated.
    text = (
        f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
        f"- {LOG_NAME} {base64.b64encode(bytes(68)).decode('ascii')}\n"
    )
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize("name", ["bad name", "bad+name", "bad\tname", "bad\x1fname"])
def test_parse_checkpoint_rejects_invalid_c2sp_signature_name(name: str) -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {name} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_lone_surrogate_origin() -> None:
    text = f"bad\ud800origin\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_more_than_64_signature_lines() -> None:
    signature = f"— {LOG_NAME} {base64.b64encode(bytes(68)).decode('ascii')}\n"
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n" + signature * 65
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_str_input() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(b"not-a-str")  # type: ignore[arg-type]


# --- verify_checkpoint: hybrid AND + origin binding ------------------------


def test_verify_checkpoint_both_legs_good_passes() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    checkpoint = tlog.verify_checkpoint(text, log_key, ORIGIN)
    assert checkpoint.tree_size == 5
    assert checkpoint.root == ROOT


def test_verify_checkpoint_ed_only_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    # Drop the last (ML-DSA) signature line, keep the Ed25519-only one.
    lines = text.split("\n")
    truncated = "\n".join(lines[:-2]) + "\n"  # drop mldsa sig line + trailing ""
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(truncated, log_key, ORIGIN)


def test_verify_checkpoint_mldsa_only_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    # lines layout: [origin, size, root, "", ed_sig, mldsa_sig, ""]
    without_ed = lines[:4] + lines[5:]
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(without_ed), log_key, ORIGIN)


def test_verify_checkpoint_wrong_expected_origin_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, "different-origin/2026")


def test_verify_checkpoint_wrong_log_key_origin_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk, origin="different-origin/2026")
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_tampered_body_fails_both_legs() -> None:
    text, hk = _signed_checkpoint(tree_size=5)
    log_key = _log_key(hk)
    tampered = _corrupt_line(text, 1, "6")  # change signed tree_size 5 -> 6
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(tampered, log_key, ORIGIN)


def test_verify_checkpoint_signature_by_different_name_ignored_fails() -> None:
    text, hk = _signed_checkpoint(name="attest-log-1")
    log_key = _log_key(hk, name="attest-log-2")  # verifier expects a different name
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_wrong_key_hash_prefix_does_not_count() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    # Corrupt the Ed25519 signature line's key-hash prefix (first 4 bytes of
    # the blob) so it no longer matches SHA256(name||"\n"||ed_pub)[:4], while
    # leaving the ML-DSA leg intact -- must still fail (no valid ed leg).
    dash, name, blob_b64 = lines[4].split(" ", 2)
    blob = bytearray(base64.b64decode(blob_b64))
    blob[0] ^= 0xFF
    lines[4] = f"{dash} {name} {base64.b64encode(bytes(blob)).decode('ascii')}"
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(lines), log_key, ORIGIN)


def test_verify_checkpoint_corrupted_mldsa_key_hash_prefix_does_not_count() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    dash, name, blob_b64 = lines[5].split(" ", 2)
    blob = bytearray(base64.b64decode(blob_b64))
    blob[0] ^= 0xFF
    lines[5] = f"{dash} {name} {base64.b64encode(bytes(blob)).decode('ascii')}"
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(lines), log_key, ORIGIN)


def test_verify_checkpoint_no_signature_lines_fails() -> None:
    text = f"{ORIGIN}\n5\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    hk = _hybrid_keys()
    log_key = _log_key(hk)
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_rejects_short_log_key_ed25519_pub() -> None:
    text, hk = _signed_checkpoint()
    log_key = tlog.LogKey(
        origin=ORIGIN, name=LOG_NAME, ed25519_pub=b"short", mldsa_pub=hk.mldsa.pub
    )
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_rejects_short_log_key_mldsa_pub() -> None:
    text, hk = _signed_checkpoint()
    log_key = tlog.LogKey(origin=ORIGIN, name=LOG_NAME, ed25519_pub=hk.ed.pub, mldsa_pub=b"short")
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def _malformed_log_key(field: str, value: object, hk: pq.HybridSigningKeys) -> tlog.LogKey:
    fields: dict[str, object] = {
        "origin": ORIGIN,
        "name": LOG_NAME,
        "ed25519_pub": hk.ed.pub,
        "mldsa_pub": hk.mldsa.pub,
    }
    fields[field] = value
    return tlog.LogKey(
        origin=cast(str, fields["origin"]),
        name=cast(str, fields["name"]),
        ed25519_pub=cast(bytes, fields["ed25519_pub"]),
        mldsa_pub=cast(bytes, fields["mldsa_pub"]),
    )


@pytest.mark.parametrize("field", ["origin", "name", "ed25519_pub", "mldsa_pub"])
def test_verify_checkpoint_rejects_malformed_log_key_field_types(field: str) -> None:
    text, hk = _signed_checkpoint()
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, _malformed_log_key(field, None, hk), ORIGIN)


def test_verify_checkpoint_rejects_malformed_expected_origin_type() -> None:
    text, hk = _signed_checkpoint()
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, _log_key(hk), None)  # type: ignore[arg-type]


def test_verify_checkpoint_stops_after_hybrid_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    text, hk = _signed_checkpoint()
    lines = text.split("\n")
    lines.insert(-1, lines[5])  # an attacker-appended duplicate ML-DSA signature
    mldsa_verify = tlog.pq.verify_strict
    calls = 0

    def count_mldsa_verify(payload: bytes, signature: bytes, public_key: bytes) -> bool:
        nonlocal calls
        calls += 1
        return mldsa_verify(payload, signature, public_key)

    monkeypatch.setattr(tlog.pq, "verify_strict", count_mldsa_verify)
    tlog.verify_checkpoint("\n".join(lines), _log_key(hk), ORIGIN)
    assert calls == 1


# --- sign_checkpoint: builder side -----------------------------------------


def test_sign_checkpoint_round_trips_through_verify() -> None:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(ORIGIN, 42, ROOT, hk, LOG_NAME)
    log_key = _log_key(hk)
    checkpoint = tlog.verify_checkpoint(text, log_key, ORIGIN)
    assert checkpoint.origin == ORIGIN
    assert checkpoint.tree_size == 42
    assert checkpoint.root == ROOT


def test_sign_checkpoint_output_ends_with_two_signature_lines() -> None:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, LOG_NAME)
    lines = text.split("\n")
    assert lines[-1] == ""
    assert lines[-2].startswith("— " + LOG_NAME + " ")
    assert lines[-3].startswith("— " + LOG_NAME + " ")


def test_sign_checkpoint_rejects_wrong_length_root() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, b"short", hk, LOG_NAME)


def test_sign_checkpoint_rejects_newline_in_origin() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint("bad\norigin", 1, ROOT, hk, LOG_NAME)


def test_sign_checkpoint_rejects_whitespace_in_name() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, "bad name")


@pytest.mark.parametrize("origin", ["", "bad\x1forigin", "bad\x7forigin"])
def test_sign_checkpoint_rejects_empty_or_control_character_origin(origin: str) -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(origin, 1, ROOT, _hybrid_keys(), LOG_NAME)


@pytest.mark.parametrize("name", ["", "bad+name", "bad\tname", "bad\x1fname"])
def test_sign_checkpoint_rejects_invalid_c2sp_name(name: str) -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, ROOT, _hybrid_keys(), name)


def test_sign_checkpoint_rejects_uint64_overflow_tree_size() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 2**64, ROOT, _hybrid_keys(), LOG_NAME)


def test_sign_checkpoint_rejects_lone_surrogate_origin() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint("bad\ud800origin", 1, ROOT, _hybrid_keys(), LOG_NAME)


# --- key-hash prefix: hand-pinned KAT ---------------------------------------


def test_key_hash_prefix_matches_hand_computed_sha256() -> None:
    # Hand-computed, independent of attest.tlog: C2SP's key-ID input is
    # name + "\n" + signature-type bytes + public key. Ed25519 uses the
    # assigned byte 0x01; ML-DSA-65 has no assigned byte and uses the C2SP
    # 0xff extension mechanism (0xff + a longer identifier). The ML-DSA-65
    # public key is fixed-length fixture material because this KAT covers
    # the hash format, not ML-DSA key validity. Never derive either literal
    # via tlog._key_hash, avoiding a tautological KAT.
    seed = bytes([7]) * 32
    ed_kp = keys.from_seed(seed)
    mldsa_pub = bytes(range(256)) * 7 + bytes(160)
    expected_ed_prefix = bytes.fromhex("fa60fb40")
    expected_mldsa_prefix = bytes.fromhex("5aded660")
    assert len(mldsa_pub) == pq.ML_DSA_65_PK_LEN
    assert hashlib.sha256(b"test-log\n\x01" + ed_kp.pub).digest()[:4] == expected_ed_prefix
    assert (
        hashlib.sha256(b"test-log\n\xffattest-ml-dsa-65" + mldsa_pub).digest()[:4]
        == expected_mldsa_prefix
    )

    hk = pq.HybridSigningKeys(ed=ed_kp, mldsa=pq.generate())
    text = tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, "test-log")
    ed_line = text.split("\n")[4]
    mldsa_line = text.split("\n")[5]
    _dash, _name, blob_b64 = ed_line.split(" ", 2)
    _dash, _name, mldsa_blob_b64 = mldsa_line.split(" ", 2)
    assert (
        base64.b64decode(blob_b64)[:4] == hashlib.sha256(b"test-log\n\x01" + hk.ed.pub).digest()[:4]
    )
    assert (
        base64.b64decode(mldsa_blob_b64)[:4]
        == hashlib.sha256(b"test-log\n\xffattest-ml-dsa-65" + hk.mldsa.pub).digest()[:4]
    )
