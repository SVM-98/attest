"""OTS op-chain anchor verification, `AnchorPolicy`, CRQC horizon gating.

The positive fixture builds a synthetic OTS op-chain forward by hand: start
from `SHA256(note_bytes)`, append a sibling, hash, prepend a prefix, hash
again — the exact op sequence the task brief specifies — then pins the
resulting root as a `PinnedHeader` and asserts `verify_anchor` recognizes it.
Every other test is a controlled mutation of that one working fixture, so a
single assertion isolates exactly one failure mode.
"""

from __future__ import annotations

import hashlib

import pytest

from attest import anchor, tlog

NOTE_BYTES = b"log.example/1\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
HEADER_TIME = 1700000000
HEADER_HASH = "3a" * 32  # deliberately contains a hex letter, not just digits


def _checkpoint(note_bytes: bytes = NOTE_BYTES) -> tlog.Checkpoint:
    return tlog.Checkpoint(
        origin="log.example/1", tree_size=1, root=b"\x00" * 32, note_bytes=note_bytes
    )


def _working_chain(note_bytes: bytes = NOTE_BYTES) -> tuple[list[list[str]], str]:
    """Build the op-chain forward and return `(ops, header_merkle_root)`.

    Sequence per the brief: append sibling, sha256, prepend prefix, sha256.
    Computed independently of `anchor.py` (plain `hashlib` calls) so the test
    pins the real algorithm rather than round-tripping the module's own logic.
    """
    sibling = bytes.fromhex("ab" * 32)  # hex letters, not just digits — needed for uppercase tests
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(note_bytes).digest()
    acc = acc + sibling
    acc = hashlib.sha256(acc).digest()
    acc = prefix + acc
    acc = hashlib.sha256(acc).digest()
    ops: list[list[str]] = [
        ["append", sibling.hex()],
        ["sha256"],
        ["prepend", prefix.hex()],
        ["sha256"],
    ]
    return ops, acc.hex()


def _ots_proof(
    ops: list[list[str]] | None = None,
    header_merkle_root: str | None = None,
    header_time: object = HEADER_TIME,
    header_hash: object = HEADER_HASH,
) -> dict[str, object]:
    working_ops, working_root = _working_chain()
    if ops is None:
        ops = working_ops
    if header_merkle_root is None:
        header_merkle_root = working_root
    return {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": header_merkle_root,
        "header_time": header_time,
        "header_hash": header_hash,
    }


def _policy(
    header_hash: str = HEADER_HASH,
    merkle_root: str | None = None,
    time: int = HEADER_TIME,
    crqc_horizon: int | None = None,
) -> anchor.AnchorPolicy:
    if merkle_root is None:
        _, merkle_root = _working_chain()
    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=merkle_root, time=time)
    return anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=crqc_horizon)


# --------------------------------------------------------------------------
# Positive round trip.
# --------------------------------------------------------------------------


def test_ots_proof_verifies_and_anchors_before_pinned_header_time() -> None:
    verdict = anchor.verify_anchor({"proofs": [_ots_proof()]}, _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert verdict.pq_surviving is True
    assert verdict.warnings == []


# --------------------------------------------------------------------------
# Negatives from the brief's Step 1 list.
# --------------------------------------------------------------------------


def test_ots_proof_fails_on_wrong_header_root() -> None:
    ops, _real_root = _working_chain()
    wrong_root = "aa" * 32
    proof = _ots_proof(ops=ops, header_merkle_root=wrong_root)
    verdict = anchor.verify_anchor(
        {"proofs": [proof]}, _checkpoint(), _policy(merkle_root=wrong_root)
    )
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert verdict.warnings == ["proof[0]: ots op-chain result does not match header_merkle_root"]


def test_ots_proof_fails_when_header_not_pinned() -> None:
    proof = _ots_proof(header_hash="44" * 32)  # valid shape, not in policy.pinned_headers
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: header_hash is not in policy.pinned_headers"]


def test_ots_proof_fails_on_unknown_op_name() -> None:
    ops, root = _working_chain()
    ops = [*ops, ["frobnicate"]]
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: unknown ots op 'frobnicate'"]


def test_ots_proof_fails_on_empty_ops() -> None:
    _, root = _working_chain()
    proof = _ots_proof(ops=[], header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots op-chain result does not match header_merkle_root"]


def test_rfc3161_only_evidence_is_classical_corroboration_without_pq_or_anchor_time() -> None:
    evidence = {"proofs": [{"kind": "rfc3161", "token_b64": "cXVpdGVvcGFxdWU="}]}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is True
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert verdict.warnings == [
        "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight"
    ]


# --------------------------------------------------------------------------
# passes_horizon.
# --------------------------------------------------------------------------


def test_passes_horizon_false_when_horizon_before_anchor_time() -> None:
    verdict = anchor.verify_anchor({"proofs": [_ots_proof()]}, _checkpoint(), _policy())
    policy = _policy(crqc_horizon=1600000000)  # before HEADER_TIME
    assert anchor.passes_horizon(verdict, policy) is False


def test_passes_horizon_true_when_horizon_none() -> None:
    verdict = anchor.verify_anchor({"proofs": [_ots_proof()]}, _checkpoint(), _policy())
    policy = _policy(crqc_horizon=None)
    assert anchor.passes_horizon(verdict, policy) is True


def test_passes_horizon_true_when_horizon_after_anchor_time_and_pq_surviving() -> None:
    verdict = anchor.verify_anchor({"proofs": [_ots_proof()]}, _checkpoint(), _policy())
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon(verdict, policy) is True


def test_passes_horizon_false_for_rfc3161_only_with_any_horizon_set() -> None:
    evidence = {"proofs": [{"kind": "rfc3161", "token_b64": "opaque"}]}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon(verdict, policy) is False


def test_passes_horizon_raises_anchor_error_on_non_anchor_policy() -> None:
    verdict = anchor.AnchorVerdict(
        anchored=False, anchored_before=None, pq_surviving=False, warnings=[]
    )
    with pytest.raises(anchor.AnchorError):
        anchor.passes_horizon(verdict, "not-a-policy")  # type: ignore[arg-type]


def test_passes_horizon_never_raises_on_malformed_verdict_content() -> None:
    policy = _policy(crqc_horizon=HEADER_TIME + 1)
    assert anchor.passes_horizon("not-a-verdict", policy) is False  # type: ignore[arg-type]
    bad_verdict = anchor.AnchorVerdict(
        anchored=True,
        anchored_before="not-an-int",
        pq_surviving=True,
        warnings=[],  # type: ignore[arg-type]
    )
    assert anchor.passes_horizon(bad_verdict, policy) is False


def test_passes_horizon_true_with_malformed_verdict_when_horizon_none() -> None:
    # policy.crqc_horizon is None short-circuits True before verdict is even inspected.
    policy = _policy(crqc_horizon=None)
    assert anchor.passes_horizon("not-a-verdict", policy) is True  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Multiple proofs: anchored_before is the min over verified PQ proofs.
# --------------------------------------------------------------------------


def test_anchored_before_is_min_over_multiple_verified_pq_proofs() -> None:
    ops, root = _working_chain()
    earlier_hash = "55" * 32
    later_hash = "66" * 32
    earlier_time = HEADER_TIME - 100
    later_time = HEADER_TIME + 100
    evidence = {
        "proofs": [
            _ots_proof(
                ops=ops, header_merkle_root=root, header_hash=later_hash, header_time=later_time
            ),
            _ots_proof(
                ops=ops, header_merkle_root=root, header_hash=earlier_hash, header_time=earlier_time
            ),
        ]
    }
    policy = anchor.AnchorPolicy(
        pinned_headers={
            later_hash: anchor.PinnedHeader(
                header_hash=later_hash, merkle_root=root, time=later_time
            ),
            earlier_hash: anchor.PinnedHeader(
                header_hash=earlier_hash, merkle_root=root, time=earlier_time
            ),
        },
        crqc_horizon=None,
    )
    verdict = anchor.verify_anchor(evidence, _checkpoint(), policy)
    assert verdict.anchored_before == earlier_time
    assert verdict.pq_surviving is True


# --------------------------------------------------------------------------
# verify_anchor never raises on malformed EVIDENCE (untrusted input).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_evidence", [None, [], "not-a-dict", 42, True])
def test_verify_anchor_never_raises_on_non_dict_evidence(bad_evidence: object) -> None:
    verdict = anchor.verify_anchor(bad_evidence, _checkpoint(), _policy())  # type: ignore[arg-type]
    assert verdict.anchored is False
    assert verdict.anchored_before is None
    assert verdict.pq_surviving is False
    assert len(verdict.warnings) == 1
    assert "evidence must be an object" in verdict.warnings[0]


def test_verify_anchor_never_raises_when_proofs_key_missing() -> None:
    verdict = anchor.verify_anchor({}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


@pytest.mark.parametrize("bad_proofs", ["not-a-list", 1, None, {}])
def test_verify_anchor_never_raises_when_proofs_not_a_list(bad_proofs: object) -> None:
    verdict = anchor.verify_anchor({"proofs": bad_proofs}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert "evidence.proofs must be a list" in verdict.warnings[0]


def test_verify_anchor_caps_proofs_list_length() -> None:
    oversized = [{"kind": "bogus"}] * (anchor._MAX_PROOFS_PER_EVIDENCE + 1)
    verdict = anchor.verify_anchor({"proofs": oversized}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert f"exceeds max length {anchor._MAX_PROOFS_PER_EVIDENCE}" in verdict.warnings[0]


@pytest.mark.parametrize("bad_proof", [None, "string", 42, [], True])
def test_verify_anchor_ignores_non_dict_proof_entry_with_warning(bad_proof: object) -> None:
    verdict = anchor.verify_anchor({"proofs": [bad_proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [f"proof[0]: must be an object, got {type(bad_proof).__name__}"]


def test_verify_anchor_unknown_kind_is_ignored_not_fatal() -> None:
    evidence = {"proofs": [{"kind": "future-kind", "stuff": 1}, _ots_proof()]}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    # The unrecognized proof doesn't crash the whole evidence, and the valid
    # ots proof alongside it still verifies.
    assert verdict.anchored is True
    assert verdict.anchored_before == HEADER_TIME
    assert "proof[0]: unknown proof kind 'future-kind', ignored" in verdict.warnings


def test_verify_anchor_ots_proof_missing_ops_field() -> None:
    proof = _ots_proof()
    del proof["ops"]
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'ops' must be a list"]


def test_verify_anchor_rfc3161_rejects_non_str_token() -> None:
    evidence = {"proofs": [{"kind": "rfc3161", "token_b64": 12345}]}
    verdict = anchor.verify_anchor(evidence, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: rfc3161 token_b64 must be a str, got int"]


def test_verify_anchor_raises_anchor_error_on_non_checkpoint_argument() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, "not-a-checkpoint", _policy())  # type: ignore[arg-type]


def test_verify_anchor_raises_anchor_error_on_non_anchor_policy() -> None:
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), "not-a-policy")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Hex validation discipline: lowercase-only, strict length, guard before
# bytes.fromhex (which itself accepts uppercase and odd-padded input).
# --------------------------------------------------------------------------


def test_ots_proof_rejects_uppercase_header_merkle_root() -> None:
    ops, root = _working_chain()
    proof = _ots_proof(ops=ops, header_merkle_root=root.upper())
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    ]


@pytest.mark.parametrize("bad_root", ["aa" * 31, "aa" * 33, "not-hex-at-all-" + "a" * 49])
def test_ots_proof_rejects_wrong_length_or_non_hex_header_merkle_root(bad_root: str) -> None:
    proof = _ots_proof(header_merkle_root=bad_root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    ]


def test_ots_proof_rejects_uppercase_header_hash() -> None:
    proof = _ots_proof(header_hash=HEADER_HASH.upper())
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'header_hash' must be 64 lowercase hex chars"]


def test_ots_proof_rejects_uppercase_op_operand_even_though_bytes_fromhex_would_accept_it() -> None:
    ops, root = _working_chain()
    sibling_hex_upper = ops[0][1].upper()
    assert bytes.fromhex(sibling_hex_upper) == bytes.fromhex(
        ops[0][1]
    )  # sanity: fromhex tolerates it
    bad_ops = [["append", sibling_hex_upper], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_rejects_odd_length_op_operand() -> None:
    ops, root = _working_chain()
    bad_ops = [["append", "abc"], *ops[1:]]  # 3 hex chars: valid charset, odd length
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_rejects_op_operand_over_max_hex_length() -> None:
    ops, root = _working_chain()
    too_long = "ab" * (anchor._MAX_OP_HEX_LEN // 2 + 1)
    bad_ops = [["append", too_long], *ops[1:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == [
        "proof[0]: ots 'append' operand must be bounded, even-length lowercase hex"
    ]


def test_ots_proof_accepts_op_operand_at_exactly_max_hex_length() -> None:
    # Boundary check the cap itself doesn't off-by-one reject a legitimate max-size operand.
    note_bytes = NOTE_BYTES
    operand_hex = "ab" * (anchor._MAX_OP_HEX_LEN // 2)
    operand = bytes.fromhex(operand_hex)
    acc = hashlib.sha256(note_bytes).digest()
    acc = acc + operand
    acc = hashlib.sha256(acc).digest()
    root = acc.hex()
    ops = [["append", operand_hex], ["sha256"]]
    proof = _ots_proof(ops=ops, header_merkle_root=root)
    verdict = anchor.verify_anchor(
        {"proofs": [proof]}, _checkpoint(note_bytes), _policy(merkle_root=root)
    )
    assert verdict.anchored is True


def test_ots_proof_rejects_sha256_op_with_operand() -> None:
    ops, root = _working_chain()
    bad_ops = [*ops[:1], ["sha256", "ff"], *ops[2:]]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots 'sha256' op takes no operand"]


def test_ots_proof_rejects_op_that_is_not_a_list() -> None:
    ops, root = _working_chain()
    bad_ops = ["sha256", *ops]  # bare string instead of ["sha256"]
    proof = _ots_proof(ops=bad_ops, header_merkle_root=root)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy(merkle_root=root))
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots op must be a non-empty list with a string opcode"]


def test_ots_proof_caps_ops_list_length() -> None:
    oversized_ops = [["sha256"]] * (anchor._MAX_OPS_PER_PROOF + 1)
    proof = _ots_proof(ops=oversized_ops)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == [
        f"proof[0]: ots proof has more than {anchor._MAX_OPS_PER_PROOF} ops"
    ]


# --------------------------------------------------------------------------
# bool-is-int traps: `isinstance(True, int)` is True in Python — must be
# excluded everywhere an int is required.
# --------------------------------------------------------------------------


def test_ots_proof_rejects_bool_header_time() -> None:
    proof = _ots_proof(header_time=True)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'header_time' must be a positive int"]


def test_ots_proof_rejects_zero_or_negative_header_time() -> None:
    proof = _ots_proof(header_time=0)
    verdict = anchor.verify_anchor({"proofs": [proof]}, _checkpoint(), _policy())
    assert verdict.anchored is False
    assert verdict.warnings == ["proof[0]: ots proof 'header_time' must be a positive int"]


def test_anchor_policy_rejects_bool_pinned_header_time() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="aa" * 32, time=True)  # type: ignore[arg-type]
    policy = anchor.AnchorPolicy(pinned_headers={HEADER_HASH: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_bool_crqc_horizon() -> None:
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=True)  # type: ignore[arg-type]
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


# --------------------------------------------------------------------------
# AnchorPolicy structural validation (trusted config side — raises).
# --------------------------------------------------------------------------


def test_anchor_policy_rejects_mismatched_dict_key_and_header_hash_field() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="aa" * 32, time=HEADER_TIME)
    policy = anchor.AnchorPolicy(pinned_headers={"ff" * 32: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_non_pinned_header_value() -> None:
    policy = anchor.AnchorPolicy(
        pinned_headers={HEADER_HASH: "not-a-pinned-header"}, crqc_horizon=None
    )  # type: ignore[dict-item]
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)


def test_anchor_policy_rejects_uppercase_pinned_header_merkle_root() -> None:
    pinned = anchor.PinnedHeader(header_hash=HEADER_HASH, merkle_root="AA" * 32, time=HEADER_TIME)
    policy = anchor.AnchorPolicy(pinned_headers={HEADER_HASH: pinned}, crqc_horizon=None)
    with pytest.raises(anchor.AnchorError):
        anchor.verify_anchor({"proofs": []}, _checkpoint(), policy)
