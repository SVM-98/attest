"""Tests for attest.transfer — issuer-mediated transfer records (v0.2 §17)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from attest import anchor, canon, keys, manifests, pq, revocation, tlog, transfer, transparency

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
OTHER_KID = f"{ISSUER}/keys/test#ed25519-2"

# TEST ONLY — fixed seeds, never use in production.
ISSUER_KP = keys.from_seed(bytes([21]) * 32)
OTHER_ISSUER_KP = keys.from_seed(bytes([22]) * 32)
HOLDER_KP = keys.from_seed(bytes([23]) * 32)
OTHER_HOLDER_KP = keys.from_seed(bytes([24]) * 32)
NEW_HOLDER_KP = keys.from_seed(bytes([25]) * 32)

OLD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
AT = "2026-07-23T00:00:00Z"
PUB_B64U = keys.b64u(NEW_HOLDER_KP.pub)


def _key_manifest() -> dict[str, Any]:
    entries = [manifests.key_entry(KID, ISSUER_KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, ISSUER_KP, KID)


def _hybrid_key_manifest() -> tuple[pq.HybridSigningKeys, dict[str, Any]]:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    entry = manifests.key_entry(KID, hk.ed.pub, "2026-01-01T00:00:00Z", pub_ml_dsa_65=hk.mldsa.pub)
    key_manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", [entry], hk, KID)
    return hk, key_manifest


def _build_record(
    receipt_id: str = OLD_ID,
    new_receipt_id: str = NEW_ID,
    new_holder_pubkey: str = PUB_B64U,
    transferred_at: str = AT,
    holder_kp: keys.SigningKeyPair = HOLDER_KP,
    issuer_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ISSUER_KP,
    kid: str = KID,
) -> dict[str, Any]:
    sig = transfer.sign_authorization(receipt_id, new_holder_pubkey, transferred_at, holder_kp)
    return transfer.build_record(
        receipt_id, new_receipt_id, new_holder_pubkey, transferred_at, sig, issuer_kp, kid
    )


def _resign_record(record: dict[str, Any]) -> None:
    body = {key: value for key, value in record.items() if key != "signature"}
    record["signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(body), ISSUER_KP, KID
    )


# --- authorization_message ---------------------------------------------------


def test_authorization_message_domain_separated() -> None:
    msg = transfer.authorization_message(OLD_ID, PUB_B64U, AT)
    assert msg == (
        b"Attest-transfer-authorization-v1\x00"
        + OLD_ID.encode()
        + b"\x00"
        + PUB_B64U.encode()
        + b"\x00"
        + AT.encode()
    )


def test_authorization_message_label_is_exact_literal() -> None:
    assert transfer.LABEL_TRANSFER_AUTHORIZATION == b"Attest-transfer-authorization-v1"


# --- build_record / verify_record roundtrip ---------------------------------


def test_build_and_verify_record_roundtrip_ed25519() -> None:
    sig = transfer.sign_authorization(OLD_ID, PUB_B64U, AT, HOLDER_KP)
    record = transfer.build_record(OLD_ID, NEW_ID, PUB_B64U, AT, sig, ISSUER_KP, KID)

    assert set(record) == {
        "receipt_id",
        "new_receipt_id",
        "new_holder_pubkey",
        "transferred_at",
        "holder_authorization",
        "signature",
    }
    assert transfer.verify_record(record, _key_manifest()) is True
    assert transfer.verify_authorization(record, keys.b64u(HOLDER_KP.pub)) is True


def test_verify_authorization_wrong_holder_key_fails() -> None:
    record = _build_record()
    assert transfer.verify_authorization(record, keys.b64u(OTHER_HOLDER_KP.pub)) is False


def test_verify_authorization_never_raises_on_malformed_record() -> None:
    record = _build_record()
    del record["holder_authorization"]["sig"]
    assert transfer.verify_authorization(record, keys.b64u(HOLDER_KP.pub)) is False


def test_verify_authorization_never_raises_on_wrong_typed_fields() -> None:
    record = _build_record()
    record["receipt_id"] = 12345  # wrong-typed; must fail closed, never raise
    assert transfer.verify_authorization(record, keys.b64u(HOLDER_KP.pub)) is False


# --- review round 1: holder authorization strictness ------------------------


def test_issuer_signed_record_with_undecodable_holder_sig_fails() -> None:
    """The malformed holder signature is present before issuer signing."""
    record: dict[str, Any] = {
        "receipt_id": OLD_ID,
        "new_receipt_id": NEW_ID,
        "new_holder_pubkey": PUB_B64U,
        "transferred_at": AT,
        "holder_authorization": {"sig": "!" * 86},
    }
    _resign_record(record)

    assert transfer.verify_record(record, _key_manifest()) is False


def test_post_signing_undecodable_holder_sig_also_fails() -> None:
    record = _build_record()
    record["holder_authorization"]["sig"] = "!" * 86

    assert transfer.verify_record(record, _key_manifest()) is False


# --- review round 1: fail-closed verification boundary ----------------------


@pytest.mark.parametrize(
    ("mutate_record", "key_manifest", "observed_exception"),
    [
        (
            lambda record: record.__setitem__("signature", []),
            _key_manifest(),
            AttributeError,
        ),
        (
            lambda record: record.__setitem__("receipt_id", object()),
            _key_manifest(),
            canon.CanonError,
        ),
        (lambda record: None, [], AttributeError),
    ],
    ids=["non_dict_signature", "non_canonicalizable_record", "malformed_manifest"],
)
def test_verify_record_fails_closed_at_untrusted_boundary(
    mutate_record: Callable[[dict[str, Any]], None],
    key_manifest: object,
    observed_exception: type[Exception],
) -> None:
    """`observed_exception` documents the review repro's pre-fix failure mode."""
    record = _build_record()
    mutate_record(record)

    assert transfer.verify_record(record, key_manifest) is False


# --- review round 1: §17.1 closed record profile ----------------------------


def test_issuer_signed_record_with_extra_member_fails() -> None:
    record = _build_record()
    record["extra"] = "not permitted"
    _resign_record(record)

    assert transfer.verify_record(record, _key_manifest()) is False


@pytest.mark.parametrize("field", ["receipt_id", "new_receipt_id"])
def test_issuer_signed_record_with_bad_ulid_fails(field: str) -> None:
    record = _build_record()
    record[field] = "not-a-ulid"
    _resign_record(record)

    assert transfer.verify_record(record, _key_manifest()) is False


def test_issuer_signed_record_with_31_byte_new_holder_pubkey_fails() -> None:
    record = _build_record(new_holder_pubkey=keys.b64u(bytes(31)))

    assert transfer.verify_record(record, _key_manifest()) is False


def test_issuer_signed_record_with_noncanonical_transferred_at_fails() -> None:
    record = _build_record(transferred_at="2026-7-3T0:0:0Z")

    assert transfer.verify_record(record, _key_manifest()) is False


# --- review round 1: direct holder-authorization verification ---------------


def test_verify_authorization_rejects_extra_holder_authorization_member() -> None:
    record = _build_record()
    record["holder_authorization"]["extra"] = "not permitted"

    assert transfer.verify_authorization(record, keys.b64u(HOLDER_KP.pub)) is False


def test_verify_authorization_rejects_noncanonical_holder_signature_encoding() -> None:
    record = _build_record()
    record["holder_authorization"]["sig"] += "="

    assert transfer.verify_authorization(record, keys.b64u(HOLDER_KP.pub)) is False


# --- hybrid AND-rule (mirrors tests/test_sibling_hybrid_sidedocs.py) --------


def test_classical_only_record_against_hybrid_key_fails_closed() -> None:
    """An issuer key-manifest entry declaring the hybrid profile
    (`pub_ml_dsa_65` present), but the transfer record's own signature
    carries only the classical Ed25519 leg — the AND-rule (v0.2 §13) fails
    this closed even though the Ed25519 leg alone verifies fine."""
    hk, key_manifest = _hybrid_key_manifest()
    classical_only_kp = keys.SigningKeyPair(seed=hk.ed.seed, pub=hk.ed.pub)
    record = _build_record(issuer_kp=classical_only_kp)
    assert transfer.verify_record(record, key_manifest) is False


def test_hybrid_record_roundtrip() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = _build_record(issuer_kp=hk)
    assert "sig" in record["signature"]
    assert "sig_ml_dsa_65" in record["signature"]
    assert transfer.verify_record(record, key_manifest) is True


def test_hybrid_record_with_tampered_mldsa_leg_fails() -> None:
    hk, key_manifest = _hybrid_key_manifest()
    record = _build_record(issuer_kp=hk)
    raw = bytearray(keys.b64u_decode(record["signature"]["sig_ml_dsa_65"]))
    raw[0] ^= 0xFF
    record["signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(raw))

    assert transfer.verify_record(record, key_manifest) is False


def test_ed25519_record_with_stray_mldsa_leg_fails() -> None:
    record = _build_record()
    record["signature"]["sig_ml_dsa_65"] = keys.b64u(bytes(pq.ML_DSA_65_SIG_LEN))

    assert transfer.verify_record(record, _key_manifest()) is False


# --- signer key window --------------------------------------------------


def test_transferred_at_outside_key_window_fails() -> None:
    entries = [
        manifests.key_entry(
            KID, ISSUER_KP.pub, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "active"
        )
    ]
    km = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, ISSUER_KP, KID)
    record = _build_record(transferred_at="2026-07-23T00:00:00Z")
    assert transfer.verify_record(record, km) is False


# --- malformed holder_authorization shapes ----------------------------------


def _missing_member(sig: str) -> object:
    return {}


def _extra_member(sig: str) -> object:
    return {"sig": sig, "extra": "x"}


def _non_dict(sig: str) -> object:
    return "not-a-dict"


def _non_b64u_sig(sig: str) -> object:
    return {"sig": "!" * len(sig)}


def _wrong_length_sig(sig: str) -> object:
    return {"sig": sig[:-1]}


@pytest.mark.parametrize(
    "mutate",
    [_missing_member, _extra_member, _non_dict, _non_b64u_sig, _wrong_length_sig],
    ids=["missing_member", "extra_member", "non_dict", "non_b64u_sig", "wrong_length_sig"],
)
def test_malformed_holder_authorization_shapes_fail_closed(
    mutate: Callable[[str], object],
) -> None:
    record = _build_record()
    original_sig = record["holder_authorization"]["sig"]
    record["holder_authorization"] = mutate(original_sig)
    assert transfer.verify_record(record, _key_manifest()) is False


# --- record_hash (mirrors revocation.record_hash) ---------------------------


def test_record_hash_is_sha256_of_canonical_bytes() -> None:
    record = _build_record()
    expected = hashlib.sha256(canon.canonical_bytes(record)).hexdigest()
    assert transfer.record_hash(record) == expected
    assert len(transfer.record_hash(record)) == 64


def test_record_hash_covers_signature_member() -> None:
    """Two records differing ONLY in their signature (e.g. re-signed by a
    different issuer key) must hash differently — `record_hash` commits to
    the WHOLE record, not just the unsigned body (mirrors
    revocation.record_hash's own G5-style discipline)."""
    record_a = _build_record(issuer_kp=ISSUER_KP, kid=KID)
    record_b = _build_record(issuer_kp=OTHER_ISSUER_KP, kid=OTHER_KID)
    assert transfer.record_hash(record_a) != transfer.record_hash(record_b)


# --- record_logged_standing (mirrors verify._revocation_deadline_satisfied's
# untrusted-evidence confinement; not in the brief's illustrative test list
# but required by TDD discipline for a new, security-relevant function) -----

_TRANSFER_LOG_ORIGIN = "transfer-log.attest.example/2026"
_TRANSFER_LOG_NAME = "attest-transfer-log-1"


def _transfer_log_key(hk: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=_TRANSFER_LOG_ORIGIN,
        name=_TRANSFER_LOG_NAME,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )


def _no_horizon_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _transfer_log_evidence(
    record: dict[str, Any], hk: pq.HybridSigningKeys, issuer_id: str = ISSUER
) -> dict[str, Any]:
    entry = {
        "type": "transfer-record",
        "issuer": issuer_id,
        "record_sha256": transfer.record_hash(record),
    }
    entry_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([entry_bytes])
    checkpoint_text = tlog.sign_checkpoint(_TRANSFER_LOG_ORIGIN, 1, root, hk, _TRANSFER_LOG_NAME)
    return {
        "entry": entry,
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": checkpoint_text,
    }


def test_record_logged_standing_returns_leaf_index_when_logged() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _build_record()
    evidence = _transfer_log_evidence(record, hk)

    leaf_index = transfer.record_logged_standing(
        record, evidence, ISSUER, [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert leaf_index == 0


def test_record_logged_standing_returns_none_without_evidence() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _build_record()

    assert (
        transfer.record_logged_standing(
            record, None, ISSUER, [_transfer_log_key(hk)], _no_horizon_policy()
        )
        is None
    )


def test_record_logged_standing_returns_none_on_unresolvable_evidence() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    record = _build_record()
    evidence = _transfer_log_evidence(record, hk)
    evidence["checkpoint"] = "not a real checkpoint\n"

    warnings: list[str] = []
    leaf_index = transfer.record_logged_standing(
        record, evidence, ISSUER, [_transfer_log_key(hk)], _no_horizon_policy(), warnings
    )

    assert leaf_index is None
    assert warnings  # the shared evaluator's warning was surfaced, not swallowed


def test_record_logged_standing_raises_on_malformed_log_keys() -> None:
    """`log_keys`/`anchor_policy` are TRUSTED verifier config — a malformed
    one is a caller/config bug and raises, mirroring
    `verify._revocation_deadline_satisfied`'s discipline exactly."""
    record = _build_record()
    with pytest.raises(transparency.TransparencyError):
        transfer.record_logged_standing(record, {"entry": {}}, ISSUER, [], _no_horizon_policy())


# --- audit_chain (v0.2 §17.5) -------------------------------------------------

SECOND_NEW_HOLDER_KP = keys.from_seed(bytes([26]) * 32)
ID0 = OLD_ID
ID1 = NEW_ID
ID2 = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
LOSING_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
AT2 = "2026-07-24T00:00:00Z"


def _chain_payload(receipt_id: str, buyer_kp: keys.SigningKeyPair) -> dict[str, Any]:
    """The minimal payload shape `audit_chain` reads: `receipt_id` and
    `buyer.pubkey` only — a full signed envelope is never needed for this
    audit surface (§17.5: the new receipt stands alone; the chain lives in
    the explicit transfer/revocation records, not in the receipt envelope)."""
    return {"receipt_id": receipt_id, "buyer": {"pubkey": keys.b64u(buyer_kp.pub)}}


def _chain_transfer_record(
    receipt_id: str,
    new_receipt_id: str,
    new_holder_kp: keys.SigningKeyPair,
    holder_kp: keys.SigningKeyPair,
    transferred_at: str = AT,
) -> dict[str, Any]:
    new_holder_pubkey = keys.b64u(new_holder_kp.pub)
    sig = transfer.sign_authorization(receipt_id, new_holder_pubkey, transferred_at, holder_kp)
    return transfer.build_record(
        receipt_id, new_receipt_id, new_holder_pubkey, transferred_at, sig, ISSUER_KP, KID
    )


def _chain_transferred_revocation(receipt_id: str, at: str = AT) -> dict[str, Any]:
    return revocation.build_record(receipt_id, "transferred", at, ISSUER_KP, KID)


def _chain_log_bundle(
    records_in_order: list[dict[str, Any]], hk: pq.HybridSigningKeys
) -> list[dict[str, Any]]:
    """One genuine transfer-record log containing every record in
    `records_in_order`, in that log order (index 0 = earliest/first-logged).
    Mirrors `tests/test_verify_transfer.py`'s identically-named helper."""
    entries = [
        {"type": "transfer-record", "issuer": ISSUER, "record_sha256": transfer.record_hash(r)}
        for r in records_in_order
    ]
    leaves = [tlog.encode_entry(e) for e in entries]
    root = tlog.build_tree(leaves)
    tree_size = len(leaves)
    checkpoint_text = tlog.sign_checkpoint(
        _TRANSFER_LOG_ORIGIN, tree_size, root, hk, _TRANSFER_LOG_NAME
    )
    return [
        {
            "entry": entry,
            "leaf_index": i,
            "tree_size": tree_size,
            "inclusion_proof": [p.hex() for p in tlog.inclusion_proof(leaves, i)],
            "checkpoint": checkpoint_text,
        }
        for i, entry in enumerate(entries)
    ]


def test_audit_chain_two_links_valid() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    p0 = _chain_payload(ID0, HOLDER_KP)
    p1 = _chain_payload(ID1, NEW_HOLDER_KP)
    p2 = _chain_payload(ID2, SECOND_NEW_HOLDER_KP)

    record1 = _chain_transfer_record(ID0, ID1, NEW_HOLDER_KP, HOLDER_KP, AT)
    record2 = _chain_transfer_record(ID1, ID2, SECOND_NEW_HOLDER_KP, NEW_HOLDER_KP, AT2)
    bundle1, bundle2 = _chain_log_bundle([record1, record2], hk)
    view = [
        {"record": record1, "evidence": bundle1},
        {"record": record2, "evidence": bundle2},
    ]
    rev_view = [
        _chain_transferred_revocation(ID0, AT),
        _chain_transferred_revocation(ID1, AT2),
    ]

    res = transfer.audit_chain(
        [p0, p1, p2], view, rev_view, _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.valid is True
    assert res.link_status == ("valid", "valid")
    assert res.errors == ()


def test_audit_chain_pubkey_loop_closure_failure() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    p0 = _chain_payload(ID0, HOLDER_KP)
    # p1's own buyer.pubkey does NOT match the transfer record's new_holder_pubkey.
    p1 = _chain_payload(ID1, SECOND_NEW_HOLDER_KP)

    record1 = _chain_transfer_record(ID0, ID1, NEW_HOLDER_KP, HOLDER_KP, AT)
    bundle1 = _chain_log_bundle([record1], hk)[0]
    view = [{"record": record1, "evidence": bundle1}]
    rev_view = [_chain_transferred_revocation(ID0, AT)]

    res = transfer.audit_chain(
        [p0, p1], view, rev_view, _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.link_status == ("invalid",)
    assert "chain link 1: new receipt buyer.pubkey != new_holder_pubkey" in res.errors


def test_audit_chain_losing_branch_rejected() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    p0 = _chain_payload(ID0, HOLDER_KP)
    # The chain is built on the LATER-logged record (new_receipt_id=LOSING_ID).
    p1 = _chain_payload(LOSING_ID, SECOND_NEW_HOLDER_KP)

    early_record = _chain_transfer_record(ID0, ID1, NEW_HOLDER_KP, HOLDER_KP, AT)
    late_record = _chain_transfer_record(ID0, LOSING_ID, SECOND_NEW_HOLDER_KP, HOLDER_KP, AT)
    # Log order: early_record first (leaf_index 0), late_record second (1).
    early_bundle, late_bundle = _chain_log_bundle([early_record, late_record], hk)
    view = [
        {"record": early_record, "evidence": early_bundle},
        {"record": late_record, "evidence": late_bundle},
    ]
    rev_view = [_chain_transferred_revocation(ID0, AT)]

    res = transfer.audit_chain(
        [p0, p1], view, rev_view, _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.link_status == ("invalid",)
    assert "chain link 1: losing branch of a double assignment" in res.errors


def test_audit_chain_missing_transferred_revocation() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    p0 = _chain_payload(ID0, HOLDER_KP)
    p1 = _chain_payload(ID1, NEW_HOLDER_KP)

    record1 = _chain_transfer_record(ID0, ID1, NEW_HOLDER_KP, HOLDER_KP, AT)
    bundle1 = _chain_log_bundle([record1], hk)[0]
    view = [{"record": record1, "evidence": bundle1}]

    res = transfer.audit_chain(
        [p0, p1], view, [], _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.link_status == ("invalid",)
    assert (
        "chain link 1: previous receipt lacks a backed transferred-class revocation" in res.errors
    )


def test_audit_chain_unlogged_record() -> None:
    p0 = _chain_payload(ID0, HOLDER_KP)
    p1 = _chain_payload(ID1, NEW_HOLDER_KP)

    record1 = _chain_transfer_record(ID0, ID1, NEW_HOLDER_KP, HOLDER_KP, AT)
    view = [{"record": record1, "evidence": None}]
    rev_view = [_chain_transferred_revocation(ID0, AT)]
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())

    res = transfer.audit_chain(
        [p0, p1], view, rev_view, _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.link_status == ("invalid",)
    assert "chain link 1: transfer record not logged" in res.errors


def test_audit_chain_no_record_for_link() -> None:
    p0 = _chain_payload(ID0, HOLDER_KP)
    p1 = _chain_payload(ID1, NEW_HOLDER_KP)
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    rev_view = [_chain_transferred_revocation(ID0, AT)]

    res = transfer.audit_chain(
        [p0, p1], [], rev_view, _key_manifest(), [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.link_status == ("invalid",)
    assert res.errors == ("chain link 1: no transfer record",)


def test_audit_chain_self_inconsistent_manifest_marks_every_link_invalid() -> None:
    """Hoisted `manifests.verify_key_manifest` check (Step 4): a manifest
    that does not self-verify marks EVERY link invalid with the
    issuer-signature literal, without evaluating anything else."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    p0 = _chain_payload(ID0, HOLDER_KP)
    p1 = _chain_payload(ID1, NEW_HOLDER_KP)
    p2 = _chain_payload(ID2, SECOND_NEW_HOLDER_KP)
    broken_manifest = dict(_key_manifest())
    broken_manifest["manifest_signature"] = {"kid": KID, "sig": "!" * 86}

    res = transfer.audit_chain(
        [p0, p1, p2], [], [], broken_manifest, [_transfer_log_key(hk)], _no_horizon_policy()
    )

    assert res.valid is False
    assert res.link_status == ("invalid", "invalid")
    assert res.errors == (
        "chain link 1: issuer signature invalid",
        "chain link 2: issuer signature invalid",
    )
