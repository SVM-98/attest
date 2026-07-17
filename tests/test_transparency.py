"""Transparency/corroboration evaluator: decision-order rules + adversarial
evidence handling.

Fixtures build a real 3-leaf transparency log by hand (via `tlog`'s own
builder side — `build_tree`/`inclusion_proof`/`consistency_proof` — which is
the intended, documented way to produce proofs the verify side consumes; see
`tlog.py`'s own module docstring). Every negative test is a controlled
mutation of the one working fixture, so a single assertion isolates exactly
one failure mode, mirroring `test_anchor.py`'s style.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any, cast

import pytest

from attest import anchor, keys, pq, tlog, transparency

ORIGIN = "log.attest.example/2026"
LOG_NAME = "attest-log-1"


def _hybrid_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _log_key(hk: pq.HybridSigningKeys, origin: str = ORIGIN, name: str = LOG_NAME) -> tlog.LogKey:
    return tlog.LogKey(origin=origin, name=name, ed25519_pub=hk.ed.pub, mldsa_pub=hk.mldsa.pub)


def _entries(n: int, salt: str = "leaf") -> list[dict[str, Any]]:
    return [
        {
            "type": "receipt",
            "issuer": "issuer.example",
            "core_sha256": hashlib.sha256(f"{salt}-{i}".encode()).hexdigest(),
        }
        for i in range(n)
    ]


def _no_horizon_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


class _Bundle:
    """A working 3-leaf log fixture: entry-under-test at index 1, signed
    checkpoint at tree_size=3, and its inclusion proof — everything
    `evaluate_transparency` needs for a passing evaluation out of the box.
    Individual tests mutate copies of `evidence`/`log_keys`/etc. to isolate
    one failure mode at a time.
    """

    def __init__(self) -> None:
        self.hk = _hybrid_keys()
        self.log_key = _log_key(self.hk)
        self.entries = _entries(3)
        self.leaves = [tlog.encode_entry(e) for e in self.entries]
        self.root = tlog.build_tree(self.leaves)
        self.proof = tlog.inclusion_proof(self.leaves, 1)
        self.checkpoint_text = tlog.sign_checkpoint(ORIGIN, 3, self.root, self.hk, LOG_NAME)
        self.entry = self.entries[1]

    def evidence(self) -> dict[str, Any]:
        return {
            "entry": dict(self.entry),
            "leaf_index": 1,
            "tree_size": 3,
            "inclusion_proof": [p.hex() for p in self.proof],
            "checkpoint": self.checkpoint_text,
        }

    def log_keys(self) -> list[tlog.LogKey]:
        return [self.log_key]

    def expected_entry(self) -> dict[str, Any]:
        return dict(self.entry)


def _evaluate(
    bundle: _Bundle, evidence: dict[str, Any], **overrides: Any
) -> transparency.TransparencyResult:
    kwargs: dict[str, Any] = {
        "log_keys": bundle.log_keys(),
        "expected_origin": ORIGIN,
        "policy": _no_horizon_policy(),
        "expected_entry": bundle.expected_entry(),
    }
    kwargs.update(overrides)
    return transparency.evaluate_transparency(evidence, **kwargs)


# --------------------------------------------------------------------------
# Happy path + decision order steps 1-3.
# --------------------------------------------------------------------------


def test_evaluate_transparency_returns_logged_for_a_fully_valid_bundle() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence())
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_flags_entry_schema_violation() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    del evidence["entry"]["core_sha256"]  # violates the closed receipt schema
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["entry_invalid"]


def test_evaluate_transparency_flags_entry_mismatch_against_expected_entry() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"]["core_sha256"] = hashlib.sha256(b"different-artifact").hexdigest()
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["transparency_entry_mismatch"]


def test_evaluate_transparency_reports_entry_mismatch_before_checkpoint_failure() -> None:
    # Both the entry AND the checkpoint are broken; decision order requires
    # step 1 (entry) to short-circuit before step 2 (checkpoint) is ever
    # attempted — asserts the ORDERING, not just that one of them fails.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"]["core_sha256"] = hashlib.sha256(b"different-artifact").hexdigest()
    evidence["checkpoint"] = "not even a parseable checkpoint\n"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["transparency_entry_mismatch"]


def test_evaluate_transparency_flags_non_dict_entry_field() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"] = "not-a-dict"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["entry_invalid"]


def test_evaluate_transparency_flags_checkpoint_field_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["checkpoint"] = 12345
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["checkpoint_invalid"]


def test_evaluate_transparency_flags_checkpoint_verification_failure_for_unknown_origin() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence(), expected_origin="different-log/2026")
    assert result.warnings == ["checkpoint_verification_failed"]


def test_evaluate_transparency_flags_checkpoint_signed_by_untrusted_key() -> None:
    bundle = _Bundle()
    other_hk = _hybrid_keys()
    other_key = _log_key(other_hk)  # same origin, different keypair -> signature won't verify
    result = _evaluate(bundle, bundle.evidence(), log_keys=[other_key])
    assert result.warnings == ["checkpoint_verification_failed"]


def test_evaluate_transparency_tries_next_log_key_when_first_does_not_verify() -> None:
    # Log-key rotation: multiple pinned keys share the origin, only the
    # second one actually matches the checkpoint's signature.
    bundle = _Bundle()
    stale_hk = _hybrid_keys()
    stale_key = _log_key(stale_hk)
    result = _evaluate(bundle, bundle.evidence(), log_keys=[stale_key, bundle.log_key])
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_flags_leaf_index_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = "1"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["leaf_index_invalid"]


def test_evaluate_transparency_rejects_bool_leaf_index() -> None:
    # bool-is-int trap: isinstance(True, int) is True in Python.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = True
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["leaf_index_invalid"]


def test_evaluate_transparency_flags_tree_size_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = "3"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_invalid"]


def test_evaluate_transparency_rejects_bool_tree_size() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = True
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_invalid"]


def test_evaluate_transparency_flags_tree_size_mismatch_against_checkpoint() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = 4  # checkpoint actually attests to tree_size=3
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_mismatch"]


def test_evaluate_transparency_flags_inclusion_proof_wrong_shape() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["inclusion_proof"] = "not-a-list"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_rejects_uppercase_inclusion_proof_entry() -> None:
    # Uppercase one entry but keep the proof otherwise complete: bytes.fromhex
    # would decode it to the identical bytes as the lowercase original, so
    # this isolates the lowercase-only shape guard from a truncated/corrupted
    # proof (which would fail verification for an unrelated reason).
    bundle = _Bundle()
    evidence = bundle.evidence()
    proof = list(evidence["inclusion_proof"])
    proof[0] = proof[0].upper()
    evidence["inclusion_proof"] = proof
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_rejects_wrong_length_inclusion_proof_entry() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["inclusion_proof"] = ["aa" * 31]
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_caps_oversized_inclusion_proof_list() -> None:
    # A distinct warning from "inclusion_proof_invalid" so this guard is
    # independently observable: tlog.verify_inclusion's own internal bound
    # would otherwise reject an oversized-but-well-formed proof with the
    # exact same generic outcome, masking removal of this cap.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["inclusion_proof"] = ["aa" * 32] * (transparency._MAX_PROOF_LEN + 1)
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_too_long"]


def test_evaluate_transparency_flags_inclusion_proof_that_does_not_verify() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = 0  # well-formed proof, but for the wrong leaf
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


# --------------------------------------------------------------------------
# Step 4: prior checkpoint / consistency / equivocation.
# --------------------------------------------------------------------------


def test_evaluate_transparency_no_warning_when_prior_checkpoint_is_consistent() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    consistency = tlog.consistency_proof(bundle.leaves, 2)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [p.hex() for p in consistency]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_detects_equivocation_on_inconsistent_prior() -> None:
    bundle = _Bundle()
    # A real proof for an honest 2->3 extension of a DIFFERENT tree (built
    # forward from tlog's own builder side, never round-tripped through the
    # verify side under test), presented against the bundle's actual
    # (unrelated) current root: verify_consistency must reject it.
    other_entries = _entries(2, salt="fork-prefix")
    other_leaves = [tlog.encode_entry(e) for e in other_entries]
    prior_root = tlog.build_tree(other_leaves)
    extended_leaves = [*other_leaves, bundle.leaves[2]]
    real_extension_proof = tlog.consistency_proof(extended_leaves, 2)
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)

    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [p.hex() for p in real_extension_proof]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_EQUIVOCATION_DETECTED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["log_equivocation_detected"]


def test_evaluate_transparency_does_not_treat_unverifiable_prior_as_equivocation() -> None:
    # A prior checkpoint with a bad signature is NOT proof of equivocation —
    # fail-safe, not a hard verdict.
    bundle = _Bundle()
    forged_hk = _hybrid_keys()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    forged_prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, forged_hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = forged_prior_text
    evidence["consistency_proof"] = [p.hex() for p in tlog.consistency_proof(bundle.leaves, 2)]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["prior_checkpoint_invalid"]


def test_evaluate_transparency_warns_when_prior_verifies_but_consistency_proof_missing() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    # consistency_proof intentionally absent
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["consistency_proof_missing"]


def test_evaluate_transparency_flags_malformed_consistency_proof_shape() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = ["not-hex"]
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["consistency_proof_invalid"]


def test_evaluate_transparency_caps_oversized_consistency_proof_list() -> None:
    # Load-bearing, not just defense-in-depth: without this cap, an oversized
    # proof reaches tlog.verify_consistency, which returns False on it (unlike
    # verify_inclusion's own internal bound) — and this module would then
    # misclassify it as TRANSPARENCY_EQUIVOCATION_DETECTED, a hard verdict,
    # for what is really just a malformed/garbage proof.
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = ["aa" * 32] * (transparency._MAX_PROOF_LEN + 1)
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["consistency_proof_too_long"]
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED


def test_evaluate_transparency_flags_prior_checkpoint_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = 42
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["prior_checkpoint_invalid"]


# --------------------------------------------------------------------------
# Steps 6-7: anchors + CRQC horizon.
# --------------------------------------------------------------------------


def _working_ots_evidence(note_bytes: bytes) -> tuple[dict[str, Any], anchor.AnchorPolicy, int]:
    """Build a verifying `ots` anchor-evidence dict + matching policy, per
    the op-chain sequence documented in `test_anchor.py`."""
    header_time = 1700000000
    header_hash = "3a" * 32
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(note_bytes).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    ops = [["append", sibling.hex()], ["sha256"], ["prepend", prefix.hex()], ["sha256"]]
    proof = {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }
    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=acc.hex(), time=header_time)
    policy = anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=None)
    dummy_sig_line = "— test-key AA==\n"
    checkpoint_text = note_bytes.decode() + "\n" + dummy_sig_line
    return {"checkpoint": checkpoint_text, "proofs": [proof]}, policy, header_time


def test_evaluate_transparency_sets_anchored_before_on_verified_pq_anchor() -> None:
    bundle = _Bundle()
    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy, header_time = _working_ots_evidence(note_bytes)
    evidence = bundle.evidence()
    evidence["anchors"] = anchors_evidence
    result = _evaluate(bundle, evidence, policy=policy)
    expected_iso = datetime.datetime.fromtimestamp(header_time, tz=datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert result.transparency == f"anchored_before:{expected_iso}"
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.warnings == []


def test_iso8601_kat_pins_the_helper_independent_of_the_brief_arithmetic() -> None:
    assert transparency._iso8601(1700000000) == "2023-11-14T22:13:20Z"


def test_evaluate_transparency_caps_to_not_checked_when_post_horizon_unanchored() -> None:
    # Base standing alone (no PQ-surviving anchor) cannot survive a declared
    # CRQC horizon: checkpoint signatures alone don't count.
    bundle = _Bundle()
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1)
    result = _evaluate(bundle, bundle.evidence(), policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["post_horizon_unanchored"]


def test_evaluate_transparency_horizon_cap_applies_when_anchor_too_late() -> None:
    bundle = _Bundle()
    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy_base, header_time = _working_ots_evidence(note_bytes)
    policy = anchor.AnchorPolicy(
        pinned_headers=policy_base.pinned_headers, crqc_horizon=header_time - 1
    )
    evidence = bundle.evidence()
    evidence["anchors"] = anchors_evidence
    result = _evaluate(bundle, evidence, policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert "post_horizon_unanchored" in result.warnings


def test_evaluate_transparency_no_horizon_cap_when_crqc_horizon_none() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence(), policy=_no_horizon_policy())
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert "post_horizon_unanchored" not in result.warnings


def test_evaluate_transparency_horizon_cap_overrides_prior_logged_anchor_state() -> None:
    # An anchor that IS present but never PQ-surviving (rfc3161-only) still
    # gets capped by a declared horizon.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["anchors"] = {
        "checkpoint": bundle.checkpoint_text,
        "proofs": [{"kind": "rfc3161", "token_b64": "b3BhcXVl"}],
    }
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1700000000)
    result = _evaluate(bundle, evidence, policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert "post_horizon_unanchored" in result.warnings
    # The rfc3161 corroboration warning from anchor.py should still surface.
    assert any("rfc3161" in w for w in result.warnings)


def test_evaluate_transparency_surfaces_anchor_warnings_on_failed_anchor_evidence() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["anchors"] = {"checkpoint": bundle.checkpoint_text, "proofs": "not-a-list"}
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_LOGGED  # anchors are non-fatal
    assert "evidence.proofs must be a list, got str" in result.warnings


# --------------------------------------------------------------------------
# NEVER raises on malformed evidence.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_evidence", [None, [], "not-a-dict", 42, True])
def test_evaluate_transparency_never_raises_on_non_dict_evidence(bad_evidence: object) -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, cast(dict[str, Any], bad_evidence))
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["evidence_invalid"]


def test_evaluate_transparency_never_raises_when_required_fields_missing() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, {})
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["entry_invalid"]


# --------------------------------------------------------------------------
# Trusted-arg validation: raises TransparencyError, never degrades.
# --------------------------------------------------------------------------


def test_evaluate_transparency_raises_on_non_list_log_keys() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), log_keys=cast(list[tlog.LogKey], "not-a-list"))


def test_evaluate_transparency_raises_on_log_keys_list_with_non_logkey_element() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(
            bundle, bundle.evidence(), log_keys=cast(list[tlog.LogKey], [bundle.log_key, "x"])
        )


def test_evaluate_transparency_raises_on_non_str_expected_origin() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_origin=cast(str, 123))


def test_evaluate_transparency_raises_on_non_anchor_policy() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), policy=cast(anchor.AnchorPolicy, "not-a-policy"))


def test_evaluate_transparency_raises_on_non_dict_expected_entry() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_entry=cast(dict[str, Any], "not-a-dict"))


# --------------------------------------------------------------------------
# Module contract: CORROBORATION_WITNESSED is defined but unreachable.
# --------------------------------------------------------------------------


def test_corroboration_witnessed_constant_is_defined() -> None:
    assert transparency.CORROBORATION_WITNESSED == "witnessed"


def test_corroboration_witnessed_never_returned_across_representative_scenarios() -> None:
    # Stage 2 has no witness input on the evidence schema: every branch of
    # evaluate_transparency sets corroboration to CORROBORATION_NONE or
    # CORROBORATION_LOGGED only. Independently re-derive one evidence bundle
    # per major branch (base standing, consistent prior, equivocation,
    # anchored, horizon-capped) and assert none produces "witnessed".
    bundle = _Bundle()

    base = _evaluate(bundle, bundle.evidence())

    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    consistent_evidence = bundle.evidence()
    consistent_evidence["prior_checkpoint"] = prior_text
    consistent_evidence["consistency_proof"] = [
        p.hex() for p in tlog.consistency_proof(bundle.leaves, 2)
    ]
    consistent = _evaluate(bundle, consistent_evidence)

    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy, _header_time = _working_ots_evidence(note_bytes)
    anchored_evidence = bundle.evidence()
    anchored_evidence["anchors"] = anchors_evidence
    anchored = _evaluate(bundle, anchored_evidence, policy=policy)

    horizon_policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1)
    capped = _evaluate(bundle, bundle.evidence(), policy=horizon_policy)

    for result in (base, consistent, anchored, capped):
        assert result.corroboration != transparency.CORROBORATION_WITNESSED
