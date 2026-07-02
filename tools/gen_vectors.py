"""Generate the OPR v0.1 language-neutral conformance vectors (design §11 Fase 1).

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
    path) for the §6 step 7 binding check (vector 09).
  - optional `manifest_pristine.json` — only for vector 11 (manifest-tamper):
    the untampered, self-consistent manifest, so the replay test can also
    assert the self-consistency delta directly via
    `manifests.verify_key_manifest()`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import unicodedata
from pathlib import Path
from typing import Any

from opr import canon, commitment, issue, keys, manifests, ulid, validate

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

LEGAL_TEXT_SHA256 = hashlib.sha256(b"opr-vectors-legal-text-v1").hexdigest()
MIRROR_POLICY_SHA256 = hashlib.sha256(b"opr-vectors-mirror-policy-v1").hexdigest()
EOL_COMMITMENT_SHA256 = hashlib.sha256(b"opr-vectors-eol-commitment-v1").hexdigest()
ARTIFACT_SHA256 = hashlib.sha256(b"opr-vectors-artifact-v1").hexdigest()

PRIOR_RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"  # design §3.1 example, reused as `supersedes`

INT_MAX_ACCEPTED = 2**53 - 1  # I-JSON safe range boundary (design §3.1, canon.py _INT_MAX)
INT_MAX_REJECTED = 2**53


# --- generic helpers --------------------------------------------------------


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _manifest_material(
    issuer_id: str, kid: str, kp: keys.SigningKeyPair, status: str = "active"
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, KEY_VALID_FROM, None, status)]
    return manifests.build_key_manifest(issuer_id, 1, MANIFEST_ISSUED_AT, entries, kp, kid)


def _trust_material(
    *issuer_manifest_provenance: tuple[str, dict[str, Any], str],
) -> dict[str, Any]:
    """Assemble a `manifests.json` payload from `(issuer_id, manifest, provenance)` triples."""
    return {
        "manifests": {issuer: manifest for issuer, manifest, _ in issuer_manifest_provenance},
        "provenance": {issuer: prov for issuer, _, prov in issuer_manifest_provenance},
        "chains": {},
    }


def _issuer_only_trust() -> dict[str, Any]:
    """The common case: a single trusted issuer manifest, TLS provenance."""
    return _trust_material(
        (ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "tls")
    )


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
        "terms_uri": f"https://{ISSUER_ID}/opr/license-templates/standard-v1",
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


def write_vector(name: str, *, payload: dict[str, Any] | None, envelope: dict[str, Any] | None,
                  envelope_raw: bytes | None, trust: dict[str, Any], expected: dict[str, Any],
                  disclosure: dict[str, Any] | None = None,
                  manifest_pristine: dict[str, Any] | None = None) -> None:
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
    write_vector("01-valid-minimal", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected)


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
            mirror_policy_uri=f"https://{ISSUER_ID}/opr/mirror-policy-v1",
            mirror_policy_sha256=MIRROR_POLICY_SHA256,
            end_of_life="escrow",
            eol_commitment_uri=f"https://{ISSUER_ID}/opr/eol-commitment-v1",
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
    write_vector("02-valid-full", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected)


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
    write_vector("03-tampered-payload", payload=payload, envelope=tampered, envelope_raw=None,
                 trust=trust, expected=expected)


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
    write_vector("04-wrong-key", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected)


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
    write_vector("05-issuer-mismatch", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected)


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
    marker = '"opr_version":"0.1"'
    assert text.count(marker) == 1, "expected exactly one opr_version member to duplicate"
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
    write_vector("06-duplicate-key-reject", payload=payload, envelope=None,
                 envelope_raw=duplicated.encode("utf-8"), trust=trust, expected=expected)


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
    write_vector("07-unicode-canon/a-nfd-and-int-boundary-accepted", payload=payload,
                 envelope=envelope, envelope_raw=None, trust=trust, expected=expected_a)

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
    write_vector("07-unicode-canon/b-int-boundary-rejected", payload=None,
                 envelope=rejected_envelope, envelope_raw=None, trust=trust, expected=expected_b)


# --- vector 08: sig-malleability ----------------------------------------------


def _malleate_signature(sig: bytes) -> bytes:
    """S -> S + L (group order): mathematically the same scalar mod L, since
    `B` has order `L`, so `[S+L]B == [S]B` — a non-canonical re-encoding of
    "the same" signature that the OPR pinned ruleset (design §4) must reject
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
    write_vector("08-sig-malleability", payload=payload, envelope=malleated, envelope_raw=None,
                 trust=trust, expected=expected)


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
    write_vector(f"09-commitment/{subname}", payload=payload, envelope=envelope,
                 envelope_raw=None, trust=trust, expected=expected, disclosure=disclosure)


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
    write_vector("10-unknown-field", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected)


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
    write_vector("11-manifest-tamper", payload=payload, envelope=envelope, envelope_raw=None,
                 trust=trust, expected=expected, manifest_pristine=pristine_manifest)


def main() -> None:
    shutil.rmtree(VECTORS_DIR, ignore_errors=True)
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
    leaf_count = sum(1 for _ in VECTORS_DIR.rglob("expected.json"))
    print(f"generated {leaf_count} vector cases under {VECTORS_DIR}")


if __name__ == "__main__":
    main()
