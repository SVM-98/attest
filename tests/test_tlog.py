"""RFC 6962 Merkle tree primitives + closed transparency-log entry schemas.

Known-answer tests (KATs) for the empty/1-leaf/2-leaf/3-leaf roots are
hand-pinned `bytes.fromhex` literals, derived by hand from the RFC 6962
§2.1 construction (shown in the comments below) — never computed through
`attest.tlog` itself. Larger trees (7 leaves) and consistency proofs are
checked via round-trip properties against the module's own builder/verify
pair, which is the only practical way to exercise every index/size-pair
combination; the KATs are what pins the hashing scheme itself.
"""

from __future__ import annotations

import hashlib

import pytest

from attest import tlog

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


def test_encode_entry_rejects_non_dict_entry() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry([])  # type: ignore[arg-type]


def test_encode_entry_rejects_short_hex() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "b" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)
