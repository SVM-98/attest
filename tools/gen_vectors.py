"""Generate the attest v0.1 language-neutral conformance vectors (design §11,
Fase 1 vectors 1-11 plus Fase 2 lifecycle/policy vectors 12-18).

Deterministic by construction: every keypair, salt, timestamp and ULID
randomness source below is a FIXED constant — no wall-clock reads
(`datetime.now`), no CSPRNG reads (`os.urandom`). Running this script twice
must produce byte-identical output under `docs/spec/vectors/`
(`git diff --exit-code docs/spec/vectors` after a second run is the
determinism gate — see the Task 10 report for the recorded check).

Each vector directory ("leaf", identified by containing `expected.json`)
holds:
  - `payload.json` — the receipt payload, for readability (not itself fed
    to `verify()`; it is embedded inside `envelope.json`).
  - `envelope.json` — the full envelope (`payload` + `signatures` + optional
    `delivery`), OR `envelope.raw.json` for vector 06, whose hand-written
    bytes intentionally cannot round-trip through a dict (duplicate JSON
    object member) — the replay test feeds that file's raw bytes straight
    to `verify()`, never through `json.load`/`json.dump`.
  - `manifests.json` — the trust material: `{"manifests": {...}, "provenance":
    {...}, "chains": {...}}`, fed straight into `verify.TrustStore`.
  - `expected.json` — the SPEC-INTENDED `VerificationResult`, hand-derived
    from design §6/§11 (not a dump of whatever `verify()` happened to
    return): `signature`, `schema`, `trust`, `revocation`, `binding`, `ok`,
    `errors` (exact list) or `errors_contains` (substrings), `warnings` or
    `warnings_contains`.
  - optional `disclosure.json` — `{"identifier", "identifier_type",
    "salt_b64u"}` (salt path) or `{"nonce_b64u", "sig_b64u"}` (challenge
    path) for the §6 step 7 binding check (vector 09, and Fase 2 vector 17).
  - optional `manifest_pristine.json` — only for vector 11 (manifest-tamper):
    the untampered, self-consistent manifest, so the replay test can also
    assert the self-consistency delta directly via
    `manifests.verify_key_manifest()`.

Fase 2 (lifecycle/policy, vectors 12-18, design §11) additions to the format
above, following the same fixed-input determinism discipline:

  - optional `revocation.json` — a single issuer-signed revocation record
    (`attest.revocation.build_record()` output), fed to the replay test as
    `revocation_view=[record]` (vectors 15, 16). Per the Task 9 hardening, a
    record only authenticates if signed by a key that is `active` in the
    issuer manifest with a `[valid_from, valid_to]` window covering the
    record's own `revoked_at` — every revocation.json shipped here satisfies
    that, checked with a generator-time `revocation.verify_record()` assert.
  - `manifests.json`'s `"chains"` member (always present, empty `{}` by
    default since Task 10) is populated for vectors 14/14b:
    `{issuer_id: [manifest_v1, manifest_v2]}`, oldest first, ending with the
    same manifest keyed under `"manifests"` for that issuer — exactly the
    shape `verify.TrustStore.chains` and the replay test's `_trust_store()`
    already consume. No new file convention needed; Task 10 already reserved
    this field, just never populated it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import unicodedata
from pathlib import Path
from typing import Any

from attest import canon, commitment, issue, keys, manifests, revocation, ulid, validate

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "docs" / "spec" / "vectors"

# --- fixed, deterministic inputs (never wall-clock, never os.urandom) -----

ISSUER_ID = "store.example.com"
EVIL_ISSUER_ID = "evil.example.com"

ISSUER_SEED = bytes([1]) * 32
EVIL_SEED = bytes([9]) * 32
WRONG_KEY_SEED = bytes([2]) * 32  # a real key, deliberately absent from the manifest (vector 04)
BUYER_PUBKEY_SEED = bytes([3]) * 32  # populates buyer.pubkey in vector 02

ISSUER_KP = keys.from_seed(ISSUER_SEED)
EVIL_KP = keys.from_seed(EVIL_SEED)
WRONG_KP = keys.from_seed(WRONG_KEY_SEED)
BUYER_KP = keys.from_seed(BUYER_PUBKEY_SEED)

ISSUER_KID = f"{ISSUER_ID}/keys/2025-01#ed25519-1"
EVIL_KID = f"{EVIL_ISSUER_ID}/keys/2025-01#ed25519-1"
WRONG_KID = f"{ISSUER_ID}/keys/2025-01#ed25519-9"  # right domain, never listed in the manifest

SALT = bytes(range(16))
ULID_TIMESTAMP_MS = 1751464200000
ULID_RANDOMNESS = bytes(range(10))
RECEIPT_ID = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=ULID_RANDOMNESS)
# datetime.fromtimestamp(ULID_TIMESTAMP_MS / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
# hardcoded rather than computed at generation time per the determinism brief
# (fixed inputs only, no runtime clock/timezone dependency).
ISSUED_AT = "2025-07-02T13:50:00Z"

KEY_VALID_FROM = "2025-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2025-01-01T00:00:00Z"

LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-vectors-legal-text-v1").hexdigest()
MIRROR_POLICY_SHA256 = hashlib.sha256(b"attest-vectors-mirror-policy-v1").hexdigest()
EOL_COMMITMENT_SHA256 = hashlib.sha256(b"attest-vectors-eol-commitment-v1").hexdigest()
ARTIFACT_SHA256 = hashlib.sha256(b"attest-vectors-artifact-v1").hexdigest()

PRIOR_RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"  # design §3.1 example, reused as `supersedes`

INT_MAX_ACCEPTED = 2**53 - 1  # I-JSON safe range boundary (design §3.1, canon.py _INT_MAX)
INT_MAX_REJECTED = 2**53

# --- Fase 2 (lifecycle/policy, vectors 12-18) additional fixed inputs ------
#
# Continuing the seed numbering already used above (1=issuer, 2=wrong-key,
# 3=buyer-pubkey, 9=evil-issuer): 4 and 5 are new keys needed only for the
# rotation-continuity vectors (12/13/15/16/17/18 all reuse ISSUER_KP/ISSUER_KID
# under a different manifest `status`, or ISSUER_KP's existing signature — no
# new key material needed for those).

ROTATED_KEY_SEED = bytes([4]) * 32  # the genuinely new key introduced by rotation (vector 14)
ROGUE_KEY_SEED = bytes([5]) * 32  # a key never active in the trusted root (vector 14b)

ROTATED_KP = keys.from_seed(ROTATED_KEY_SEED)
ROGUE_KP = keys.from_seed(ROGUE_KEY_SEED)

ROTATION_ISSUED_AT = "2025-04-01T00:00:00Z"  # v2 manifest issued_at / old key's retirement valid_to
ROTATED_KID = f"{ISSUER_ID}/keys/2025-04#ed25519-2"
# ROGUE_KID: same domain (passes the step-2 domain match) but never listed in v1.
ROGUE_KID = f"{ISSUER_ID}/keys/2025-04#ed25519-3"

# within both ROTATED_KP's and ROGUE_KP's validity window
RECEIPT_ISSUED_AFTER_ROTATION = "2025-05-01T00:00:00Z"

# revocation record timestamp (vectors 15, 16); within ISSUER_KID's open-ended validity
REVOKED_AT = "2025-08-01T00:00:00Z"

# 16 fixed bytes, distinct from SALT (bytes(range(16))) — vector 17b
CHALLENGE_NONCE = bytes(range(32, 48))


# --- 2026-07-13 regression-corpus constants (vectors 19-25) -------------------

SUBSTITUTED_KEY_SEED = (
    bytes([6]) * 32
)  # vector 19a: key the attacker swaps into the candidate manifest
SUBSTITUTED_KP = keys.from_seed(SUBSTITUTED_KEY_SEED)

SMALL_ORDER_POINT = bytes([1]) + bytes(31)  # canonical encoding of the identity element (order 1)
SMALL_ORDER_KID = (
    f"{ISSUER_ID}/keys/2025-01#ed25519-5"  # vector 20b: listed key whose pub is small-order
)

REFUND_WINDOW_DAYS = 14  # vector 23: ISSUED_AT 2025-07-02 -> window end 2025-07-16
REVOKED_INSIDE_WINDOW_AT = (
    "2025-07-10T00:00:00Z"  # vector 23a: inside the window (REVOKED_AT 2025-08-01 is outside)
)

SUPPLEMENTARY_TITLE = (
    "Music \U0001d11e Theme"  # vector 21f/g: U+1D11E, needs a surrogate pair when escaped
)


# --- generic helpers --------------------------------------------------------


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _clear_leaf_dirs(root: Path) -> None:
    """Remove only the leaf *directories* under `root`, preserving files —
    regeneration must not delete the hand-authored README.md (pre-2026-07-13
    the whole tree was rmtree'd and the README lost on every regen)."""
    if not root.exists():
        return
    for child in root.iterdir():
        if child.is_dir():
            shutil.rmtree(child)


def _text_max_depth(text: str) -> int:
    """Max bracket nesting depth of a JSON text, ignoring brackets inside
    strings — the measuring twin of `canon._check_depth`'s walk, used to
    assert the depth-boundary vectors (21b/c/d) sit exactly on 255/256/257."""
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in "]}":
            depth -= 1
    return max_depth


def _manifest_material(
    issuer_id: str, kid: str, kp: keys.SigningKeyPair, status: str = "active"
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, KEY_VALID_FROM, None, status)]
    return manifests.build_key_manifest(issuer_id, 1, MANIFEST_ISSUED_AT, entries, kp, kid)


def _trust_material(
    *issuer_manifest_provenance: tuple[str, dict[str, Any], str],
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Assemble a `manifests.json` payload from `(issuer_id, manifest, provenance)` triples.

    `chains`, when supplied, is embedded verbatim under `"chains"` — the same
    shape `verify.TrustStore.chains` and the replay test's `_trust_store()`
    already expect (design §5/§7.3): `{issuer_id: [manifest_v1, manifest_v2,
    ...]}`, oldest first, ending with the same manifest passed under
    `manifests` for that issuer. Only vectors 14/14b populate it; every other
    vector keeps the Task-10 default of an empty `chains` object.
    """
    return {
        "manifests": {issuer: manifest for issuer, manifest, _ in issuer_manifest_provenance},
        "provenance": {issuer: prov for issuer, _, prov in issuer_manifest_provenance},
        "chains": chains if chains is not None else {},
    }


def _issuer_only_trust() -> dict[str, Any]:
    """The common case: a single trusted issuer manifest, TLS provenance."""
    return _trust_material((ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "tls"))


def _base_payload_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "issuer_id": ISSUER_ID,
        "display_name": "Example Games Store",
        "buyer_identifier": "buyer-001",
        "buyer_identifier_type": "issuer-account",
        "buyer_salt": SALT,
        "title": "Example Game",
        "publisher": "Example Publisher srl",
        "identifiers": {"issuer_sku": "EXG-001"},
        "artifact_series": f"{ISSUER_ID}/works/EXG-001",
        "terms_uri": f"https://{ISSUER_ID}/attest/license-templates/standard-v1",
        "legal_text_sha256": LEGAL_TEXT_SHA256,
        "receipt_id": RECEIPT_ID,
        "issued_at": ISSUED_AT,
    }
    kwargs.update(overrides)
    return kwargs


def _assert_schema_valid(payload: dict[str, Any]) -> None:
    violations = validate.validate_payload(payload)
    if violations:
        raise AssertionError(f"generator built a schema-invalid payload: {violations}")


def write_vector(
    name: str,
    *,
    payload: dict[str, Any] | None,
    envelope: dict[str, Any] | None,
    envelope_raw: bytes | None,
    trust: dict[str, Any],
    expected: dict[str, Any],
    disclosure: dict[str, Any] | None = None,
    manifest_pristine: dict[str, Any] | None = None,
    revocation_record: dict[str, Any] | None = None,
    canonical: bytes | None = None,
) -> None:
    vector_dir = VECTORS_DIR / name
    if payload is not None:
        _write_json(vector_dir / "payload.json", payload)
    if envelope is not None:
        _write_json(vector_dir / "envelope.json", envelope)
    if envelope_raw is not None:
        _write_bytes(vector_dir / "envelope.raw.json", envelope_raw)
    _write_json(vector_dir / "manifests.json", trust)
    _write_json(vector_dir / "expected.json", expected)
    if disclosure is not None:
        _write_json(vector_dir / "disclosure.json", disclosure)
    if manifest_pristine is not None:
        _write_json(vector_dir / "manifest_pristine.json", manifest_pristine)
    if revocation_record is not None:
        _write_json(vector_dir / "revocation.json", revocation_record)
    if canonical is not None:
        _write_bytes(vector_dir / "canonical.json", canonical)


# --- vector 01: valid-minimal ------------------------------------------------


def gen_01_valid_minimal() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "01-valid-minimal",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 02: valid-full ----------------------------------------------------


def gen_02_valid_full() -> None:
    payload = issue.build_payload(
        **_base_payload_kwargs(
            edition="Deluxe",
            artifacts=[
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": 734003200,
                    "sha256": ARTIFACT_SHA256,
                }
            ],
            grant="perpetual",
            revocability="refund_window",
            revocation_window_days=14,
            transferable=False,
            drm="drm-bound",
            jurisdiction_flags={"eu_usedsoft_asserted": False},
            redownload_right=True,
            mirror_policy_uri=f"https://{ISSUER_ID}/attest/mirror-policy-v1",
            mirror_policy_sha256=MIRROR_POLICY_SHA256,
            end_of_life="escrow",
            eol_commitment_uri=f"https://{ISSUER_ID}/attest/eol-commitment-v1",
            eol_commitment_sha256=EOL_COMMITMENT_SHA256,
            supersedes=PRIOR_RECEIPT_ID,
            buyer_pubkey=BUYER_KP.pub,
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["drm-bound"],
    }
    write_vector(
        "02-valid-full",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 03: tampered-payload ----------------------------------------------


def gen_03_tampered_payload() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    tampered = copy.deepcopy(envelope)
    title = tampered["payload"]["work"]["title"]
    assert title[0] == "E", f"unexpected title, fix the tamper index: {title!r}"
    tampered["payload"]["work"]["title"] = "F" + title[1:]  # flip one byte, post-signing
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }
    write_vector(
        "03-tampered-payload",
        payload=payload,
        envelope=tampered,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 04: wrong-key -----------------------------------------------------


def gen_04_wrong_key() -> None:
    """Signed by a key whose kid domain matches the issuer but is absent from
    the trusted manifest (§6 step 3, not step 2 — the domain check passes)."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, WRONG_KP, WRONG_KID)  # kid domain matches issuer.id
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["no key", "in issuer manifest"],
        "warnings": [],
    }
    write_vector(
        "04-wrong-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 05: issuer-mismatch -----------------------------------------------


def gen_05_issuer_mismatch() -> None:
    """A valid signature by evil.example.com's key over a payload claiming
    issuer.id store.example.com — must reject at §6 step 2 (issuer_mismatch).
    `issue.issue()` itself refuses to build this (kid-domain/issuer.id check
    at issuance time), so the envelope is hand-signed exactly like the attack
    it models."""
    payload = issue.build_payload(**_base_payload_kwargs())  # issuer.id == store.example.com
    _assert_schema_valid(payload)
    sig = keys.sign(canon.canonical_bytes(payload), EVIL_KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": EVIL_KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    trust = _trust_material(
        (ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "tls"),
        (EVIL_ISSUER_ID, _manifest_material(EVIL_ISSUER_ID, EVIL_KID, EVIL_KP), "tls"),
    )
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["issuer_mismatch"],
        "warnings": [],
    }
    write_vector(
        "05-issuer-mismatch",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 06: duplicate-key-reject ------------------------------------------


def gen_06_duplicate_key_reject() -> None:
    """A genuinely duplicated JSON object member — a Python dict cannot
    represent this, so the envelope is a hand-written raw byte string, not a
    serialized dict. Rejected at §6 step 0 (RFC 8785 forbids duplicate
    members; `canon.loads_strict` raises `DuplicateKeyError`), before any
    issuer/key resolution — trust stays at its unresolved default."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    text = json.dumps(envelope, separators=(",", ":"))
    marker = '"attest_version":"0.1"'
    assert text.count(marker) == 1, "expected exactly one attest_version member to duplicate"
    duplicated = text.replace(marker, marker + "," + marker, 1)
    assert json.loads(duplicated)  # sanity: still syntactically valid generic JSON
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unauthenticated_tofu",  # step 0 fails before any issuer is even identified
        "ok": False,
        "errors_contains": ["duplicate object key"],
        "warnings": [],
    }
    write_vector(
        "06-duplicate-key-reject",
        payload=payload,
        envelope=None,
        envelope_raw=duplicated.encode("utf-8"),
        trust=trust,
        expected=expected,
    )


# --- vector 07: unicode-canon (two sub-cases) ---------------------------------


def gen_07_unicode_canon() -> None:
    # NFD-decomposed "é" (e + combining acute accent U+0301) — JCS must sign
    # and verify the exact code points given, never silently NFC-normalizing
    # arbitrary payload string content (unlike commitment.normalize(), which
    # is the one place NFC normalization is normative, §3.2).
    nfd_title = "Café"

    assert unicodedata.normalize("NFC", nfd_title) != nfd_title, "title must be genuinely NFD"

    payload = issue.build_payload(
        **_base_payload_kwargs(
            title=nfd_title,
            artifacts=[
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": INT_MAX_ACCEPTED,
                    "sha256": ARTIFACT_SHA256,
                }
            ],
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()

    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "07-unicode-canon/a-nfd-and-int-boundary-accepted",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
    )

    # Sub-case b: bump the same field one past the I-JSON safe boundary. This
    # payload can never be produced by issue() (canon.canonical_bytes() -
    # required to sign it - raises CanonError on the oversized int), so it is
    # built as a post-signing mutation of sub-case a's envelope, exactly like
    # vector 03's tamper: the (now stale) signature no longer applies to the
    # mutated payload, AND the mutated payload cannot even be canonicalized.
    # Design §11 vector 7 says "rejected by schema" in shorthand; the actual
    # rejection point is earlier and unavoidable — every payload field,
    # including this one, is part of JCS(payload), which `verify()` step 4
    # must canonicalize BEFORE it could ever reach step 5's schema check. See
    # the Task 10 report for the full discrepancy note.
    rejected_envelope = copy.deepcopy(envelope)
    rejected_envelope["payload"]["work"]["artifacts"][0]["size_bytes"] = INT_MAX_REJECTED
    expected_b = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["integer out of I-JSON safe range"],
        "warnings": [],
    }
    write_vector(
        "07-unicode-canon/b-int-boundary-rejected",
        payload=None,
        envelope=rejected_envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
    )


# --- vector 08: sig-malleability ----------------------------------------------


def _malleate_signature(sig: bytes) -> bytes:
    """S -> S + L (group order): mathematically the same scalar mod L, since
    `B` has order `L`, so `[S+L]B == [S]B` — a non-canonical re-encoding of
    "the same" signature that the attest pinned ruleset (design §4) must reject
    (SUF-CMA: reject S >= L)."""
    r, s = sig[:32], int.from_bytes(sig[32:], "little")
    malleated_s = s + keys.L
    return r + malleated_s.to_bytes(32, "little")


def gen_08_sig_malleability() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    original_sig = keys.b64u_decode(envelope["signatures"][0]["sig"])
    malleated = copy.deepcopy(envelope)
    malleated["signatures"][0]["sig"] = keys.b64u(_malleate_signature(original_sig))
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }
    write_vector(
        "08-sig-malleability",
        payload=payload,
        envelope=malleated,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 09: commitment (three sub-cases) ----------------------------------


def _commitment_subvector(subname: str, identifier: str, identifier_type: str) -> None:
    payload = issue.build_payload(
        **_base_payload_kwargs(buyer_identifier=identifier, buyer_identifier_type=identifier_type)
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    commitment_b64u = payload["buyer"]["commitment"]
    assert commitment_b64u == keys.b64u(commitment.compute(identifier, identifier_type, SALT))
    trust = _issuer_only_trust()
    disclosure = {
        "identifier": identifier,
        "identifier_type": identifier_type,
        "salt_b64u": keys.b64u(SALT),
    }
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
        "commitment_b64u": commitment_b64u,
        "normalized_identifier": commitment.normalize(identifier, identifier_type),
    }
    write_vector(
        f"09-commitment/{subname}",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        disclosure=disclosure,
    )


def gen_09_commitment() -> None:
    _commitment_subvector("a-ascii-email", "Buyer@Example.com", "email")
    _commitment_subvector("b-unicode-email", "Büyér+Tag@Example.com", "email")
    # NFD input ("Zan" + combining tilde U+0303 + "y_ID-042"): normalize() for
    # issuer-account NFC-composes without case-folding, so the commitment is
    # computed over "Zañy_ID-042" (NFC), not the NFD bytes as typed.
    _commitment_subvector("c-issuer-account", "Zañy_ID-042", "issuer-account")


# --- vector 10: unknown-field -------------------------------------------------


def gen_10_unknown_field() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    payload["promo_code"] = "SUMMER2026"  # unknown top-level field, signed and warned about
    _assert_schema_valid(payload)  # additionalProperties: true at the top level
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["unknown payload field", "promo_code"],
    }
    write_vector(
        "10-unknown-field",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 11: manifest-tamper -----------------------------------------------


def gen_11_manifest_tamper() -> None:
    """A key's `status` flipped from `active` to `compromised` after the
    manifest was signed. `verify()` never re-checks a trust-store manifest's
    own self-signature (that is the caller's responsibility before trusting
    a manifest at all — see `manifests.verify_key_manifest`); it reads
    `status` directly off whatever manifest the trust store hands it. So the
    tampered manifest has two independently checkable effects, both asserted
    here: (a) it no longer self-verifies (`manifest_pristine.json` lets the
    replay test check this directly), and (b) any receipt genuinely signed
    while the key WAS active now reports `signature: invalid` via the §6
    step 3 fail-closed compromise check, because the trust store's copy says
    `compromised` regardless of what was true when the manifest was signed."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)  # signed while genuinely active

    pristine_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="active")
    tampered_manifest = copy.deepcopy(pristine_manifest)
    tampered_manifest["keys"][0]["status"] = "compromised"  # post-signing tamper
    assert manifests.verify_key_manifest(pristine_manifest) is True
    assert manifests.verify_key_manifest(tampered_manifest) is False

    trust = _trust_material((ISSUER_ID, tampered_manifest, "tls"))
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["compromised"],
        "warnings": [],
        "note": (
            "manifests.json carries the TAMPERED manifest (what verify() is fed); "
            "manifest_pristine.json is the untampered, self-consistent original."
        ),
    }
    write_vector(
        "11-manifest-tamper",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        manifest_pristine=pristine_manifest,
    )


# --- vector 12: retired-key-ok ------------------------------------------------


def gen_12_retired_key_ok() -> None:
    """A receipt genuinely signed while `ISSUER_KID` was `active`, verified
    against a trust-store manifest where that same key is now `retired`
    (design §7.3: "Receipts signed while a key was active remain valid after
    that key is later retired"). `verify()` step 3 only rejects on
    `compromised`; `retired` continues verification but MUST emit a warning
    (§11.2) — this vector is that warning path, distinct from vector 13
    (compromised) which rejects outright."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="retired")
    trust = _trust_material((ISSUER_ID, manifest, "tls"))
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["retired"],
    }
    write_vector(
        "12-retired-key-ok",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 13: compromised-key -------------------------------------------------


def gen_13_compromised_key() -> None:
    """A receipt genuinely signed by `ISSUER_KID`, verified against a
    trust-store manifest where that key is now `compromised`. Unlike vector
    11 (manifest-tamper, where the manifest's OWN signature breaks because a
    field was mutated post-signing), this manifest is fully self-consistent
    — it is the ordinary, honestly-authored lifecycle state an issuer
    publishes after a real compromise. §7.3 / §11 step 3: `compromised`
    fails closed unconditionally, checked BEFORE the `issued_at`-in-window
    test in `verify.py` — so rejection here does not depend on `issued_at`
    at all, which is the concrete evidence for "ALL its signatures invalid
    regardless of issued_at" (design §11 vector 13)."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)  # genuinely signed while active
    manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="compromised")
    assert manifests.verify_key_manifest(manifest) is True  # self-consistent, unlike vector 11
    trust = _trust_material((ISSUER_ID, manifest, "tls"))
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["compromised"],
        "warnings": [],
    }
    write_vector(
        "13-compromised-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 14 / 14b: rotation continuity / discontinuity -----------------------


def _genuine_rotation_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """A legitimate v1 -> v2 rotation: v2 retires the old key, introduces
    ROTATED_KID, and is signed by ISSUER_KID (active in v1) -> continuity holds."""
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    v2_entries = [
        manifests.key_entry(
            ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, ROTATION_ISSUED_AT, "retired"
        ),
        manifests.key_entry(ROTATED_KID, ROTATED_KP.pub, ROTATION_ISSUED_AT, None, "active"),
    ]
    v2 = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, v2_entries, ISSUER_KP, ISSUER_KID
    )
    assert manifests.check_continuity(v1, v2) is True
    return v1, v2


def gen_14_rotation_continuity() -> None:
    """A two-manifest chain: v1 (`ISSUER_KID` sole active key) -> v2, where v2
    introduces a genuinely NEW active key (`ROTATED_KID`) and retires the old
    one, but v2 is itself signed by the OLD key — the standard "old key
    signs off on the new one" handoff (design §7.3). `manifests.check_continuity`
    requires the signer to be `active` in the TRUSTED (v1) manifest; it is,
    so the chain is continuous and `trust` stays at its provenance-derived
    value (`verified`, since provenance is `tls`) rather than being forced
    to `unverified_rotation`. The receipt itself is issued by the NEW key,
    proving verification correctly resolves against the CURRENT (v2) manifest."""
    v1, v2 = _genuine_rotation_pair()

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROTATED_KP, ROTATED_KID)

    trust = _trust_material((ISSUER_ID, v2, "tls"), chains={ISSUER_ID: [v1, v2]})
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "14-rotation-continuity",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


def gen_14b_rotation_discontinuous() -> None:
    """Same v1 root as vector 14, but the candidate v2 is signed by
    `ROGUE_KID` — a key that is never listed, active or otherwise, in v1.
    `manifests.check_continuity` looks up the CANDIDATE's signer inside the
    TRUSTED manifest's own keys; that lookup misses, so the chain is
    discontinuous (design §7.3: "if intermediates are unavailable, the
    manifest MUST be treated as reached via a discontinuous rotation").
    `verify()` forces `trust: "unverified_rotation"`, overriding provenance,
    even though the receipt's own signature (by `ROGUE_KID`, which IS active
    in the CURRENT/v2 manifest actually used to resolve it) verifies cleanly
    — `trust` is not one of the four components `VerificationResult.ok`
    checks (§11.1: signature/schema/revocation/errors only), so `ok` stays
    `True` by explicit spec definition: this is a trust *downgrade* signal
    for the caller to act on, not a rejection. (Mirrors the existing
    `test_rotation_discontinuous_chain_yields_unverified_rotation` unit test
    in `tests/test_verify.py`.)"""
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)  # same root as vector 14
    rogue_entries = [
        manifests.key_entry(ROGUE_KID, ROGUE_KP.pub, ROTATION_ISSUED_AT, None, "active")
    ]
    v2_rogue = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, rogue_entries, ROGUE_KP, ROGUE_KID
    )
    assert manifests.check_continuity(v1, v2_rogue) is False  # signer absent from the trusted root

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROGUE_KP, ROGUE_KID)

    trust = _trust_material((ISSUER_ID, v2_rogue, "tls"), chains={ISSUER_ID: [v1, v2_rogue]})
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "14b-rotation-discontinuous",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 15: revoked-policy ---------------------------------------------------


def gen_15_revoked_policy() -> None:
    """A `revocability: "policy"` receipt plus an authenticated, matching
    revocation record: per §12.2, `policy` honors an effective record as-is
    -> `revocation: "revoked"`, `ok: False`. The record is signed by
    `ISSUER_KID` while it is `active` with a `[valid_from, valid_to]` window
    covering `REVOKED_AT` — the Task 9 hardening
    (`revocation.verify_record`, mirroring `manifests.verify_artifact_manifest`)
    requires exactly this or the record is silently ignored; the generator
    asserts `verify_record` is True so a future regression here fails loudly
    at generation time, not just at replay time."""
    payload = issue.build_payload(**_base_payload_kwargs(revocability="policy"))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID)
    assert revocation.verify_record(record, issuer_manifest) is True
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "revoked",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "15-revoked-policy",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        revocation_record=record,
    )


# --- vector 16: revocation-against-none-ignored ----------------------------------


def gen_16_revocation_against_none_ignored() -> None:
    """A `revocability: "none"` receipt (the `_base_payload_kwargs()` default)
    plus an authenticated, matching revocation record: §6.2 / §12.2's
    irrevocability guarantee means the record itself is treated as invalid —
    `revocation: "invalid_revocation_ignored"`, a warning is emitted, and the
    receipt's `ok` is UNAFFECTED (`True`). Without this rule the revocation
    mechanism would falsify every `revocability: "none"` receipt's own
    claim (design vector 16 is exactly this regression test)."""
    payload = issue.build_payload(**_base_payload_kwargs())  # revocability defaults to "none"
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID)
    assert revocation.verify_record(record, issuer_manifest) is True  # authenticated, but ignored
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "invalid_revocation_ignored",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["revocability is 'none'"],
    }
    write_vector(
        "16-revocation-against-none-ignored",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        revocation_record=record,
    )


# --- vector 17: binding-proven (two sub-cases) -----------------------------------


def gen_17_binding_proven() -> None:
    """§8/§11 step 7 buyer binding, both proof paths (design vector 17):

    (a) salt disclosure — `(identifier, identifier_type, salt)` recomputes
    `buyer.commitment`; a clean minimal-receipt case (the default
    `_base_payload_kwargs()` identity), isolating the binding proof itself
    from the normalization edge cases already covered by vector 09.

    (b) pubkey challenge-response — `buyer.pubkey` is populated at issuance;
    the disclosure carries `(nonce, sig)` where `sig` is the buyer's own
    Ed25519 signature (§8.2) over the fixed challenge transcript, proving
    possession of the private key without ever revealing an identifier.
    Neither vectors 01-16 nor vector 09 exercise this path — vector 09 only
    ever populates the salt path."""
    # (a) salt disclosure
    payload_a = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload_a)
    envelope_a = issue.issue(payload_a, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    disclosure_a = {
        "identifier": "buyer-001",  # matches _base_payload_kwargs()'s buyer_identifier default
        "identifier_type": "issuer-account",
        "salt_b64u": keys.b64u(SALT),
    }
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "17-binding-proven/a-salt-disclosure",
        payload=payload_a,
        envelope=envelope_a,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
        disclosure=disclosure_a,
    )

    # (b) pubkey challenge-response transcript
    payload_b = issue.build_payload(**_base_payload_kwargs(buyer_pubkey=BUYER_KP.pub))
    _assert_schema_valid(payload_b)
    envelope_b = issue.issue(payload_b, ISSUER_KP, ISSUER_KID)
    receipt_id_b = payload_b["receipt_id"]
    challenge_sig = commitment.sign_challenge(receipt_id_b, CHALLENGE_NONCE, BUYER_KP)
    assert commitment.verify_challenge(receipt_id_b, CHALLENGE_NONCE, challenge_sig, BUYER_KP.pub)
    disclosure_b = {
        "nonce_b64u": keys.b64u(CHALLENGE_NONCE),
        "sig_b64u": keys.b64u(challenge_sig),
    }
    expected_b = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "17-binding-proven/b-pubkey-challenge",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
        disclosure=disclosure_b,
    )


# --- vector 18: drm-bound ---------------------------------------------------------


def gen_18_drm_bound() -> None:
    """`license.drm == "drm-bound"` MUST verify green but MUST carry a
    mandatory warning (§5.5, §11.2) — a receipt never removes DRM and this
    specification never claims it does. `revocability` is bumped off the
    schema default `"none"` to `"policy"` purely because §6.1's conditional
    requires `drm == "drm-free"` when `revocability == "none"`; `"policy"`
    carries no such constraint, so this is the minimal change that keeps the
    payload schema-valid while setting `drm: "drm-bound"`."""
    payload = issue.build_payload(**_base_payload_kwargs(revocability="policy", drm="drm-bound"))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["drm-bound"],
    }
    write_vector(
        "18-drm-bound",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 19: rotation-substituted-key (2 sub-cases) ---------------------------


def gen_19_rotation_substituted_key() -> None:
    """Regression pair for the 2026-07-13 must-fix #1 (key substitution in
    check_continuity) and the PR #4 chain-tail binding fix.

    (a) The candidate v2 re-declares ISSUER_KID but with SUBSTITUTED_KP's
    public key, and is signed by SUBSTITUTED_KP under that kid. The manifest
    is SELF-consistent (its own declared pub verifies its own signature) —
    exactly the attack the pre-fix code fell for by validating the candidate
    signature against the candidate's self-declared pub. The fixed
    check_continuity resolves the signer pub from the TRUSTED manifest, where
    ISSUER_KID maps to the real key -> signature mismatch -> discontinuous ->
    trust: "unverified_rotation" (a trust downgrade, not a rejection: ok stays
    True per §11.1, same reasoning as vector 14b).

    (b) The chain [v1, v2] is genuinely continuous, but the manifest under
    `manifests` (the one used to resolve the receipt's kid) is v1, NOT the
    chain tail v2. Post-PR#4, a chain only vouches for the manifest it ends
    with -> unverified_rotation."""
    # (a) substituted candidate key
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    evil_entries = [
        manifests.key_entry(ISSUER_KID, SUBSTITUTED_KP.pub, KEY_VALID_FROM, None, "active"),
        manifests.key_entry(ROTATED_KID, ROTATED_KP.pub, ROTATION_ISSUED_AT, None, "active"),
    ]
    v2_evil = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, evil_entries, SUBSTITUTED_KP, ISSUER_KID
    )
    assert manifests.verify_key_manifest(v2_evil) is True  # self-consistent: that's the point
    assert manifests.check_continuity(v1, v2_evil) is False  # but the trusted root unmasks it

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROTATED_KP, ROTATED_KID)
    trust_a = _trust_material((ISSUER_ID, v2_evil, "tls"), chains={ISSUER_ID: [v1, v2_evil]})
    expected_downgrade = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "19-rotation-substituted-key/a-substituted-candidate-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_a,
        expected=expected_downgrade,
    )

    # (b) valid chain whose tail is not the manifest in use
    v1b, v2b = _genuine_rotation_pair()
    payload_b = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload_b)
    envelope_b = issue.issue(
        payload_b, ISSUER_KP, ISSUER_KID
    )  # resolvable in v1 (the manifest used)
    trust_b = _trust_material((ISSUER_ID, v1b, "tls"), chains={ISSUER_ID: [v1b, v2b]})
    write_vector(
        "19-rotation-substituted-key/b-chain-tail-not-manifest-used",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust_b,
        expected=expected_downgrade,
    )


# --- vector 20: sig-canonicity (three sub-cases) ------------------------------


def gen_20_sig_canonicity() -> None:
    """Ed25519 pinned-ruleset edges (design §4): S must satisfy S < L
    (vector 08 already pins S+L; sub-case a pins the exact boundary S == L),
    and small-order A (signer pubkey) / small-order R (signature prefix) must
    be rejected — libsodium rejects both natively, @noble does with
    zip215:false (verifiers/ts/src/ed25519.ts). The identity element is used
    as the canonical small-order point."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    original_sig = keys.b64u_decode(envelope["signatures"][0]["sig"])
    r_bytes, s_bytes = original_sig[:32], original_sig[32:]

    rejected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }

    # (a) S == L exactly: the smallest non-canonical scalar.
    s_equals_l = copy.deepcopy(envelope)
    s_equals_l["signatures"][0]["sig"] = keys.b64u(r_bytes + keys.L.to_bytes(32, "little"))
    write_vector(
        "20-sig-canonicity/a-s-equals-l",
        payload=payload,
        envelope=s_equals_l,
        envelope_raw=None,
        trust=trust,
        expected=rejected,
    )

    # (b) signer pubkey is small-order: manifest lists SMALL_ORDER_KID with the
    # identity point as pub (manifest itself is signed by ISSUER_KID, so its
    # self-verify holds); the envelope claims SMALL_ORDER_KID.
    so_entries = [
        manifests.key_entry(ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None, "active"),
        manifests.key_entry(SMALL_ORDER_KID, SMALL_ORDER_POINT, KEY_VALID_FROM, None, "active"),
    ]
    so_manifest = manifests.build_key_manifest(
        ISSUER_ID, 1, MANIFEST_ISSUED_AT, so_entries, ISSUER_KP, ISSUER_KID
    )
    so_envelope = copy.deepcopy(envelope)
    so_envelope["signatures"][0]["kid"] = SMALL_ORDER_KID
    write_vector(
        "20-sig-canonicity/b-small-order-pubkey",
        payload=None,
        envelope=so_envelope,
        envelope_raw=None,
        trust=_trust_material((ISSUER_ID, so_manifest, "tls")),
        expected=rejected,
    )

    # (c) signature R component is small-order, S kept from the real signature.
    so_r = copy.deepcopy(envelope)
    so_r["signatures"][0]["sig"] = keys.b64u(SMALL_ORDER_POINT + s_bytes)
    write_vector(
        "20-sig-canonicity/c-small-order-r",
        payload=None,
        envelope=so_r,
        envelope_raw=None,
        trust=trust,
        expected=rejected,
    )


def _nested_list(levels: int) -> Any:
    value: Any = 1
    for _ in range(levels):
        value = [value]
    return value


def gen_21_canon_strict() -> None:
    """Strict-parser parity set: BOM, depth boundary triple, lone surrogate,
    and supplementary-plane raw-vs-escaped equivalence. Parse-level rejects
    reuse vector 06's expected shape (issuer unextractable -> TOFU trust)."""
    parse_reject_base = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unauthenticated_tofu",
        "ok": False,
        "warnings": [],
    }
    accepted_with_unknown_field = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["unknown payload field"],
    }
    trust = _issuer_only_trust()

    # (a) BOM: both parsers reject, with language-specific messages -> no errors* field.
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    bom_raw = b"\xef\xbb\xbf" + json.dumps(envelope).encode("utf-8")
    write_vector(
        "21-canon-strict/a-bom",
        payload=None,
        envelope=None,
        envelope_raw=bom_raw,
        trust=trust,
        expected=dict(parse_reject_base),
    )

    # (b)(c)(d) depth boundary triple: whole-text nesting 255 / 256 / 257.
    # The deep structure lives in an unknown top-level payload field "x"
    # (vector 10 pins unknown-field tolerance: schema stays valid + warning).
    for depth_target, subname in ((255, "b-depth-255"), (256, "c-depth-256"), (257, "d-depth-257")):
        deep_payload = issue.build_payload(**_base_payload_kwargs())
        # envelope text depth at "x" = {envelope {payload [x nesting...]}} = 2 + levels
        deep_payload["x"] = _nested_list(depth_target - 2)
        deep_envelope = issue.issue(deep_payload, ISSUER_KP, ISSUER_KID)
        deep_raw = json.dumps(deep_envelope).encode("utf-8")
        assert _text_max_depth(deep_raw.decode("utf-8")) == depth_target
        if depth_target <= 256:
            expected: dict[str, Any] = dict(accepted_with_unknown_field)
        else:
            expected = dict(parse_reject_base)
            expected["errors_contains"] = ["maximum nesting depth exceeded"]
        write_vector(
            f"21-canon-strict/{subname}",
            payload=None,
            envelope=None,
            envelope_raw=deep_raw,
            trust=trust,
            expected=expected,
        )

    # (e) lone surrogate via \uXXXX escape, injected textually (a payload
    # carrying it can never be signed: canonical_bytes rejects it).
    surr_payload = issue.build_payload(**_base_payload_kwargs())
    surr_payload["x"] = "PLACEHOLDER_SURR"
    surr_envelope = issue.issue(surr_payload, ISSUER_KP, ISSUER_KID)
    surr_raw_text = json.dumps(surr_envelope).replace('"PLACEHOLDER_SURR"', '"\\ud800"')
    assert "\\ud800" in surr_raw_text
    surr_expected = dict(parse_reject_base)
    surr_expected["errors_contains"] = ["lone surrogate"]
    write_vector(
        "21-canon-strict/e-lone-surrogate",
        payload=None,
        envelope=None,
        envelope_raw=surr_raw_text.encode("utf-8"),
        trust=trust,
        expected=surr_expected,
    )

    # (f)(g) supplementary-plane raw vs escaped: same signed payload, two
    # byte-level encodings of the same envelope -> both must verify (JCS
    # canonical form is what got signed, independent of transport escaping).
    supp_payload = issue.build_payload(**_base_payload_kwargs(title=SUPPLEMENTARY_TITLE))
    _assert_schema_valid(supp_payload)
    supp_envelope = issue.issue(supp_payload, ISSUER_KP, ISSUER_KID)
    raw_text = json.dumps(supp_envelope, ensure_ascii=False)
    escaped_text = json.dumps(supp_envelope, ensure_ascii=True)
    assert "\U0001d11e" in raw_text and "\\ud834\\udd1e" in escaped_text
    accepted_clean = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "21-canon-strict/f-supplementary-raw",
        payload=supp_payload,
        envelope=None,
        envelope_raw=raw_text.encode("utf-8"),
        trust=trust,
        expected=dict(accepted_clean),
    )
    write_vector(
        "21-canon-strict/g-supplementary-escaped",
        payload=None,
        envelope=None,
        envelope_raw=escaped_text.encode("utf-8"),
        trust=trust,
        expected=dict(accepted_clean),
    )


def main() -> None:
    _clear_leaf_dirs(VECTORS_DIR)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    gen_01_valid_minimal()
    gen_02_valid_full()
    gen_03_tampered_payload()
    gen_04_wrong_key()
    gen_05_issuer_mismatch()
    gen_06_duplicate_key_reject()
    gen_07_unicode_canon()
    gen_08_sig_malleability()
    gen_09_commitment()
    gen_10_unknown_field()
    gen_11_manifest_tamper()
    gen_12_retired_key_ok()
    gen_13_compromised_key()
    gen_14_rotation_continuity()
    gen_14b_rotation_discontinuous()
    gen_15_revoked_policy()
    gen_16_revocation_against_none_ignored()
    gen_17_binding_proven()
    gen_18_drm_bound()
    gen_19_rotation_substituted_key()
    gen_20_sig_canonicity()
    gen_21_canon_strict()
    leaf_count = sum(1 for _ in VECTORS_DIR.rglob("expected.json"))
    print(f"generated {leaf_count} vector cases under {VECTORS_DIR}")


if __name__ == "__main__":
    main()
