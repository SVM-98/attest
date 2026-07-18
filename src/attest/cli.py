"""`attest` command-line interface — the operator surface (design §10).

Every verb wraps a single library call 1:1: no domain logic (schema rules,
crypto, revocation classification, bundle packaging...) lives here, only
argument parsing, file I/O, and JSON in/out. Stdlib only.

Conventions (per Task 14 brief):
  - `--help` text per verb (argparse default).
  - Primary/status output is JSON on stdout; errors go to stderr.
  - Exit codes: 0 = ok, 1 = verification-failed (a `verify`/`check-artifact`
    call that ran successfully but concluded "not ok"/"no match"), 2 =
    usage-or-IO error (bad flags, missing/malformed files, library-raised
    `ValueError`/`BundleError`/schema violations at issuance).
  - Secrets (seeds, buyer-binding salts) are never printed to stdout and are
    written to disk with 0600 permissions.

`--trust-dir` for `verify` (and the `trust/` directory `import` writes) is a
directory of key-manifest JSON files, one issuer per file (or one file per
manifest *version* when multiple versions of the same issuer are present —
grouped by the manifest's own `issuer` field, not by filename). Every
manifest found is trusted with provenance `"bundle"` (design §5:
unauthenticated TOFU) — a local trust directory was not fetched over TLS at
verification time, so `verify()` reports `trust: "unauthenticated_tofu"`
rather than `"verified"` even when the signature checks out.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from attest import bundle, canon, issue, keys, manifests, pq, verify

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE_ERROR = 2

_SECRET_FILE_MODE = 0o600
_PROVENANCE_BUNDLE = "bundle"  # local trust material is unauthenticated TOFU (design §5)
_REDACTED_SALT = "<redacted: run on the .private material to see it>"


class CliUsageError(Exception):
    """A usage/IO problem this CLI can explain better than the raw exception."""


# --- small I/O helpers -------------------------------------------------------


def _same_file_target(a: Path, b: Path) -> bool:
    """True if `a` and `b` denote the same file: identical resolved path
    (covers relative paths and symlinks, even for a path that does not exist
    yet) OR the same existing inode (covers hard links, which resolve()
    cannot see). Fail-safe: a stat error means 'not provably the same'."""
    if a.resolve() == b.resolve():
        return True
    try:
        return a.samefile(b)
    except OSError:
        return False


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {path}") from exc
    except OSError as exc:
        raise CliUsageError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliUsageError(f"invalid JSON in {path}: {exc}") from exc


def _write_json_file(path: Path, obj: Any, *, secret: bool = False) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True)
    if secret:
        _write_secret_text(path, text)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_secret_text(path: Path, text: str) -> None:
    """Write a secret (seed, salt, salt-bearing envelope, salts.json) to
    `path`, created atomically with owner-only 0600 permissions.

    `os.open(..., O_CREAT, 0600)` sets the mode at creation time, so there is
    never the brief window `write_text(...)` + `chmod(...)` leaves where the
    file exists world-readable at the default umask. `os.fchmod` on the
    already-open fd then also pins the mode when `path` pre-existed with
    looser perms (a re-run overwriting a prior file) — still race-free
    because it operates on the fd, not the path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _SECRET_FILE_MODE)
    # `os.fdopen` takes ownership of `fd`, so the `with` closes it even if
    # `fchmod`/`write` raise — no manual close, no double-close.
    with os.fdopen(fd, "w") as fh:
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        fh.write(text)


def _read_b64u_file(path: Path) -> bytes:
    return keys.b64u_decode(path.read_text(encoding="utf-8").strip())


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _load_seed_kp(path: Path) -> keys.SigningKeyPair:
    return keys.from_seed(_read_b64u_file(path))


def _load_mldsa_kp(path: Path) -> pq.MLDSAKeyPair:
    """Load an ML-DSA-65 key file written by `keygen --hybrid` (0600 JSON:
    `{"alg": "ML-DSA-65", "sk": <b64u>, "pub": <b64u>}`).

    Any deviation (missing file, bad JSON, wrong alg, malformed/wrong-length
    b64u material) is a `CliUsageError` — clean exit-2 message, no traceback.
    """
    obj = _read_json(path)
    if not isinstance(obj, dict) or obj.get("alg") != pq.ML_DSA_65_ALG:
        raise CliUsageError(
            f"{path} is not a valid ML-DSA-65 key file (expected alg={pq.ML_DSA_65_ALG!r})"
        )
    try:
        sk = keys.b64u_decode(obj["sk"])
        pub = keys.b64u_decode(obj["pub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CliUsageError(f"{path} has malformed sk/pub fields: {exc}") from exc
    if len(sk) != pq.ML_DSA_65_SK_LEN or len(pub) != pq.ML_DSA_65_PK_LEN:
        raise CliUsageError(f"{path} has wrong-length ML-DSA-65 key material")
    return pq.MLDSAKeyPair(sk=sk, pub=pub)


# --- trust-dir loading (shared by `verify` and documented for `import`) -----


def _load_trust_dir(trust_dir: Path) -> verify.TrustStore:
    if not trust_dir.is_dir():
        raise CliUsageError(f"--trust-dir {trust_dir} is not a directory")

    by_issuer: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(trust_dir.glob("*.json")):
        manifest = _read_json(path)
        issuer = manifest.get("issuer") if isinstance(manifest, dict) else None
        if not isinstance(issuer, str):
            continue
        by_issuer.setdefault(issuer, []).append(manifest)

    manifests_map: dict[str, dict[str, Any]] = {}
    provenance: dict[str, str] = {}
    chains: dict[str, list[dict[str, Any]]] = {}
    for issuer, versions in by_issuer.items():
        ordered = sorted(versions, key=lambda m: m.get("manifest_version", 0))
        manifests_map[issuer] = ordered[-1]
        provenance[issuer] = _PROVENANCE_BUNDLE
        chains[issuer] = ordered

    return verify.TrustStore(manifests=manifests_map, provenance=provenance, chains=chains)


def _safe_name(value: str) -> str:
    """Sanitize a bundle-controlled issuer/series identifier into a single
    filename component: neutralize path separators (both platforms), the
    drive-letter colon, and any parent-directory component, so a hostile name
    can never escape the output directory (2026-07-13 review, finding 14)."""
    safe = value.replace("/", "_").replace("\\", "_").replace(":", "_").replace("..", "_")
    return safe or "_"


# --- keygen -------------------------------------------------------------------


def _cmd_keygen(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed_out, args.pub_out):
        # Aliased outputs would overwrite the seed with the pubkey (2026-07-13
        # review, finding 18).
        raise CliUsageError("--seed-out and --pub-out must be different paths")
    if args.hybrid and args.mldsa_out is None:
        raise CliUsageError("--hybrid requires --mldsa-out")
    if not args.hybrid and args.mldsa_out is not None:
        raise CliUsageError("--mldsa-out requires --hybrid")
    if args.mldsa_out is not None and (
        _same_file_target(args.mldsa_out, args.seed_out)
        or _same_file_target(args.mldsa_out, args.pub_out)
    ):
        # Same aliasing hazard as --seed-out/--pub-out above (2026-07-13 review,
        # finding 18), extended to the new ML-DSA output (fix wave, Task 8).
        raise CliUsageError("--mldsa-out must differ from --seed-out and --pub-out")

    kp = keys.generate()
    _write_secret_text(args.seed_out, keys.b64u(kp.seed))
    args.pub_out.parent.mkdir(parents=True, exist_ok=True)
    args.pub_out.write_text(keys.b64u(kp.pub), encoding="utf-8")

    report = {
        "pub": keys.b64u(kp.pub),
        "seed_out": str(args.seed_out),
        "pub_out": str(args.pub_out),
    }
    if args.hybrid:
        mldsa_kp = pq.generate()
        mldsa_key_file = {
            "alg": pq.ML_DSA_65_ALG,
            "sk": keys.b64u(mldsa_kp.sk),
            "pub": keys.b64u(mldsa_kp.pub),
        }
        _write_secret_text(args.mldsa_out, json.dumps(mldsa_key_file, indent=2, sort_keys=True))
        report["mldsa_pub"] = keys.b64u(mldsa_kp.pub)
        report["mldsa_out"] = str(args.mldsa_out)
    _print_json(report)
    return EXIT_OK


# --- manifest init / rotate / artifacts ---------------------------------------


def _cmd_manifest_init(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed, args.out):
        raise CliUsageError("--seed and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Reading --mldsa-key then writing --out to the same path would clobber
        # the freshly-read ML-DSA secret file.
        raise CliUsageError("--mldsa-key and --out must be different paths")
    kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = kp
    if args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        entry = manifests.key_entry(
            args.kid, kp.pub, args.valid_from, args.valid_to, pub_ml_dsa_65=mldsa_kp.pub
        )
        signing_kp = pq.HybridSigningKeys(ed=kp, mldsa=mldsa_kp)
    else:
        entry = manifests.key_entry(args.kid, kp.pub, args.valid_from, args.valid_to)
    manifest = manifests.build_key_manifest(
        args.issuer, 1, args.issued_at, [entry], signing_kp, args.kid
    )
    if not manifests.verify_key_manifest(manifest):
        raise CliUsageError(
            "built manifest does not self-verify; check that --seed and --mldsa-key are "
            "a valid matching keypair"
        )
    _write_json_file(args.out, manifest)
    _print_json({"out": str(args.out), "issuer": args.issuer, "manifest_version": 1})
    return EXIT_OK


def _cmd_manifest_rotate(args: argparse.Namespace) -> int:
    if _same_file_target(args.signing_seed, args.out):
        raise CliUsageError("--signing-seed and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy, extended to the new hybrid input).
        raise CliUsageError("--mldsa-key and --out must be different paths")
    if args.new_mldsa_pub is not None and _same_file_target(args.new_mldsa_pub, args.out):
        raise CliUsageError("--new-mldsa-pub and --out must be different paths")

    existing = _read_json(args.manifest_in)
    if not isinstance(existing, dict) or "keys" not in existing:
        raise CliUsageError(f"{args.manifest_in} is not a key manifest")

    retire_kids: list[str] = args.retire_kid or []
    compromise_kids: list[str] = args.compromise_kid or []

    new_entry = None
    if args.new_mldsa_pub is not None and (args.new_kid is None or args.new_pub is None):
        raise CliUsageError("--new-mldsa-pub requires --new-kid and --new-pub")
    if args.new_kid is not None or args.new_pub is not None:
        if args.new_kid is None or args.new_pub is None:
            raise CliUsageError("--new-kid and --new-pub must be given together")
        if args.valid_from is None:
            raise CliUsageError("--valid-from is required when adding a new key")
        new_pub = _read_b64u_file(args.new_pub)
        new_mldsa_pub = None
        if args.new_mldsa_pub is not None:
            new_mldsa_pub = _read_b64u_file(args.new_mldsa_pub)
            if len(new_mldsa_pub) != pq.ML_DSA_65_PK_LEN:
                raise CliUsageError("new --mldsa-pub is not a 1952-byte ML-DSA-65 public key")
        new_entry = manifests.key_entry(
            args.new_kid,
            new_pub,
            args.valid_from,
            args.valid_to,
            pub_ml_dsa_65=new_mldsa_pub,
        )

    if new_entry is None and not retire_kids and not compromise_kids:
        raise CliUsageError(
            "nothing to do: supply a new key (--new-kid/--new-pub) and/or "
            "--retire-kid/--compromise-kid"
        )

    # The signature shape MUST follow the signing entry's own hybrid-ness, not
    # whether the operator happened to pass --mldsa-key: `_verify_signature_block`
    # requires the manifest_signature shape to match "pub_ml_dsa_65" in entry and
    # verifies the ML-DSA leg against the ENTRY's bound pub, so a mismatch here
    # produces a manifest that is cryptographically invalid at exit 0 (2026-07-13
    # adversarial review, Task 8 fix wave, finding 1/critical).
    signer_entry = manifests.find_key(existing, args.signing_kid)
    mldsa_kp: pq.MLDSAKeyPair | None = None
    if signer_entry is not None:
        is_hybrid_signer = "pub_ml_dsa_65" in signer_entry
        if is_hybrid_signer and args.mldsa_key is None:
            raise CliUsageError(
                f"signing key {args.signing_kid!r} is hybrid; --mldsa-key is required"
            )
        if not is_hybrid_signer and args.mldsa_key is not None:
            raise CliUsageError(
                f"signing key {args.signing_kid!r} is Ed25519-only; --mldsa-key is not allowed"
            )
        if is_hybrid_signer and args.mldsa_key is not None:
            mldsa_kp = _load_mldsa_kp(args.mldsa_key)
            try:
                entry_mldsa_pub = keys.b64u_decode(signer_entry["pub_ml_dsa_65"])
            except (KeyError, TypeError, ValueError) as exc:
                raise CliUsageError(
                    f"{args.manifest_in} has a malformed pub_ml_dsa_65 for "
                    f"{args.signing_kid!r}: {exc}"
                ) from exc
            if mldsa_kp.pub != entry_mldsa_pub:
                raise CliUsageError(
                    "--mldsa-key does not match the signing key's ML-DSA-65 public "
                    "key in the manifest"
                )

    ed_signing_kp = _load_seed_kp(args.signing_seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if args.mldsa_key is not None:
        if mldsa_kp is None:
            mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)

    try:
        manifest = manifests.rotate_key_manifest(
            existing,
            signing_kp,
            args.signing_kid,
            args.issued_at,
            new_entry=new_entry,
            retire_kids=retire_kids,
            compromise_kids=compromise_kids,
        )
    except ValueError as exc:
        raise CliUsageError(str(exc)) from exc

    # A candidate must be self-consistent AND directly continue the input
    # manifest: the signing key must be active in the input, its validity
    # window must cover this issuance, and the version must advance by one.
    if not manifests.check_continuity(existing, manifest):
        raise CliUsageError(
            "rotation does not continue the input manifest: the signing key must be active "
            "in it and the version must increment by one"
        )

    _write_json_file(args.out, manifest)
    _print_json(
        {
            "out": str(args.out),
            "issuer": existing["issuer"],
            "manifest_version": manifest["manifest_version"],
        }
    )
    return EXIT_OK


def _cmd_manifest_artifacts(args: argparse.Namespace) -> int:
    if _same_file_target(args.signing_seed, args.out):
        raise CliUsageError("--signing-seed and --out must be different paths")
    if _same_file_target(args.manifest_in, args.out):
        raise CliUsageError("--in and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        raise CliUsageError("--mldsa-key and --out must be different paths")

    key_manifest = _read_json(args.manifest_in)
    if not isinstance(key_manifest, dict) or "keys" not in key_manifest:
        raise CliUsageError(f"{args.manifest_in} is not a key manifest")
    artifacts = _read_json(args.artifacts)
    if not isinstance(artifacts, list):
        raise CliUsageError(f"{args.artifacts} must contain a JSON array of artifact entries")

    # The signature shape MUST follow the signing entry's own hybrid-ness, not
    # whether the operator happened to pass --mldsa-key. The shared verifier
    # requires the manifest_signature shape to match "pub_ml_dsa_65" in the
    # entry, so any mismatch would otherwise create an invalid artifact
    # manifest at exit 0.
    signer_entry = manifests.find_key(key_manifest, args.signing_kid)
    if signer_entry is None:
        raise CliUsageError(f"signing key {args.signing_kid!r} is not in {args.manifest_in}")
    is_hybrid_signer = "pub_ml_dsa_65" in signer_entry
    mldsa_kp: pq.MLDSAKeyPair | None = None
    if is_hybrid_signer and args.mldsa_key is None:
        raise CliUsageError(f"signing key {args.signing_kid!r} is hybrid; --mldsa-key is required")
    if not is_hybrid_signer and args.mldsa_key is not None:
        raise CliUsageError(
            f"signing key {args.signing_kid!r} is Ed25519-only; --mldsa-key is not allowed"
        )
    if is_hybrid_signer and args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        try:
            entry_mldsa_pub = keys.b64u_decode(signer_entry["pub_ml_dsa_65"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CliUsageError(
                f"{args.manifest_in} has a malformed pub_ml_dsa_65 for "
                f"{args.signing_kid!r}: {exc}"
            ) from exc
        if mldsa_kp.pub != entry_mldsa_pub:
            raise CliUsageError(
                "--mldsa-key does not match the signing key's ML-DSA-65 public key in the manifest"
            )

    ed_signing_kp = _load_seed_kp(args.signing_seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if mldsa_kp is not None:
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)
    manifest = manifests.build_artifact_manifest(
        args.issuer,
        args.series,
        args.version,
        args.released_at,
        artifacts,
        signing_kp,
        args.signing_kid,
    )
    if not manifests.verify_artifact_manifest(manifest, key_manifest):
        raise CliUsageError(
            "built artifact manifest does not self-verify against --in; check that "
            "--signing-seed, --mldsa-key, issuer, signer status, and released-at match it"
        )
    _write_json_file(args.out, manifest)
    _print_json(
        {
            "out": str(args.out),
            "issuer": args.issuer,
            "series": args.series,
            "version": args.version,
        }
    )
    return EXIT_OK


# --- issue ----------------------------------------------------------------------


def _cmd_issue(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed, args.out):
        raise CliUsageError("--seed and --out must be different paths")
    if args.salt_out is not None and _same_file_target(args.seed, args.salt_out):
        raise CliUsageError("--seed and --salt-out must be different paths")
    if args.salt_out is not None and args.salt is None:
        raise CliUsageError("--salt-out requires --salt (nothing to write out otherwise)")
    if args.salt_out is not None and _same_file_target(args.out, args.salt_out):
        # Aliased outputs would overwrite the receipt with the raw salt (2026-07-13
        # review, finding 18).
        raise CliUsageError("--out and --salt-out must be different paths")
    if args.attest_version == "0.2" and args.mldsa_key is None:
        raise CliUsageError("--attest-version 0.2 requires --mldsa-key")
    if args.attest_version == "0.1" and args.mldsa_key is not None:
        raise CliUsageError("--mldsa-key requires --attest-version 0.2")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Same input-vs-output aliasing hazard as --salt/--salt-out above.
        raise CliUsageError("--mldsa-key and --out must be different paths")
    if (
        args.mldsa_key is not None
        and args.salt_out is not None
        and _same_file_target(args.mldsa_key, args.salt_out)
    ):
        # Same input-vs-output aliasing hazard, extended to --salt-out: reading
        # --mldsa-key then overwriting it with the raw salt at exit 0 would
        # silently destroy the ML-DSA secret (adversarial re-review, Task 8
        # fix wave 2, important finding).
        raise CliUsageError("--mldsa-key and --salt-out must be different paths")

    payload = _read_json(args.payload)
    ed_signing_kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)
    salt = _read_b64u_file(args.salt) if args.salt is not None else None
    manifest_snapshot = _read_json(args.manifest_snapshot) if args.manifest_snapshot else None

    envelope = issue.issue(
        payload, signing_kp, args.kid, salt=salt, manifest_snapshot=manifest_snapshot
    )
    # An envelope that embeds delivery.salt carries the buyer-binding secret
    # in cleartext, so its --out file must be as locked-down (0600) as the
    # redundant --salt-out copy. A saltless envelope has no secret and keeps
    # default perms.
    delivery = envelope.get("delivery")
    salt_bearing = isinstance(delivery, dict) and "salt" in delivery
    _write_json_file(args.out, envelope, secret=salt_bearing)
    if args.salt_out is not None and salt is not None:
        _write_secret_text(args.salt_out, keys.b64u(salt))

    _print_json({"out": str(args.out), "receipt_id": payload.get("receipt_id")})
    return EXIT_OK


# --- verify -----------------------------------------------------------------------


def _result_to_dict(result: verify.VerificationResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "signature": result.signature,
        "schema": result.schema,
        "revocation": result.revocation,
        "binding": result.binding,
        "trust": result.trust,
        "warnings": list(result.warnings),
        "errors": list(result.errors),
    }


def _build_disclosure(args: argparse.Namespace) -> verify.Disclosure | None:
    salt = _read_b64u_file(args.disclose_salt) if args.disclose_salt is not None else None
    # A half-supplied challenge (only nonce, or only sig) must be rejected, not
    # silently dropped (2026-07-13 review, finding 17).
    if (args.disclose_challenge_nonce is None) != (args.disclose_challenge_sig is None):
        raise CliUsageError(
            "--disclose-challenge-nonce and --disclose-challenge-sig must be given together"
        )
    challenge = None
    if args.disclose_challenge_nonce is not None and args.disclose_challenge_sig is not None:
        challenge = (
            _read_b64u_file(args.disclose_challenge_nonce),
            _read_b64u_file(args.disclose_challenge_sig),
        )
    nothing_supplied = (
        args.disclose_identifier is None
        and args.disclose_type is None
        and salt is None
        and challenge is None
    )
    if nothing_supplied:
        return None
    return verify.Disclosure(
        identifier=args.disclose_identifier,
        identifier_type=args.disclose_type,
        salt=salt,
        challenge=challenge,
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        envelope_bytes = args.envelope.read_bytes()
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {args.envelope}") from exc
    except OSError as exc:
        raise CliUsageError(f"cannot read {args.envelope}: {exc}") from exc

    trust_store = _load_trust_dir(args.trust_dir)
    revocation_view = _read_json(args.revocations) if args.revocations is not None else None
    # Security: require an explicit JSON array. A lone record object (exactly
    # what `revocation.build_record` emits) would otherwise be forwarded
    # untyped and silently ignored by the revocation check, passing a revoked
    # receipt as ok. Do not auto-wrap — make the operator supply the array.
    if revocation_view is not None and not isinstance(revocation_view, list):
        raise CliUsageError(
            "--revocations must contain a JSON array of records; wrap a single record in [ ]"
        )
    disclosure = _build_disclosure(args)

    result = verify.verify(envelope_bytes, trust_store, revocation_view, disclosure)
    _print_json(_result_to_dict(result))
    return EXIT_OK if result.ok else EXIT_VERIFICATION_FAILED


# --- disclose -----------------------------------------------------------------------


def _resolve_disclose_out(raw_out: str) -> Path:
    """Resolve `--out` for `disclose` into the directory-or-file target
    `bundle.disclose()` expects.

    `bundle.disclose()` only recognizes an ALREADY-EXISTING directory
    (`out.is_dir()`) — a not-yet-created target directory (a fresh demo run
    doing `disclose --out ./share/`) would otherwise be treated as a literal
    file path named "share". A trailing path separator is treated as an
    explicit "this is a directory" signal and created if missing; an
    already-existing directory is honored as-is; anything else is an exact
    file path (its parent directories are created by `bundle.disclose()`
    itself).
    """
    out_path = Path(raw_out)
    looks_like_directory = raw_out.endswith(("/", os.sep)) or out_path.is_dir()
    if looks_like_directory:
        out_path.mkdir(parents=True, exist_ok=True)
    return out_path


def _cmd_disclose(args: argparse.Namespace) -> int:
    receipts = [_read_json(p) for p in args.receipt]
    key_manifests = [_read_json(p) for p in args.key_manifest]
    salts: dict[str, bytes] = {}
    if args.salt is not None:
        salts[args.receipt_id] = _read_b64u_file(args.salt)

    out_target = _resolve_disclose_out(args.out)
    written = bundle.disclose(receipts, key_manifests, salts, args.receipt_id, out_target)
    _print_json({"out": str(written)})
    return EXIT_OK


# --- export / import -----------------------------------------------------------------


def _cmd_export(args: argparse.Namespace) -> int:
    receipts = [_read_json(p) for p in args.receipt]
    key_manifests = [_read_json(p) for p in args.key_manifest]
    artifact_manifests = [_read_json(p) for p in args.artifact_manifest]

    legal_texts: dict[str, bytes] = {}
    for path in args.legal_text:
        content = path.read_bytes()
        legal_texts[hashlib.sha256(content).hexdigest()] = content

    attest_path, private_path = bundle.export(
        receipts, key_manifests, artifact_manifests, legal_texts, args.out_dir, args.name
    )
    _print_json({"attest": str(attest_path), "private": str(private_path)})
    return EXIT_OK


def _cmd_import(args: argparse.Namespace) -> int:
    if args.private is not None:
        # Spec: a conforming CLI MUST warn whenever .private material is accessed
        # (2026-07-13 review, finding 19).
        print(
            "warning: reading .private.attest — it carries buyer-binding secrets; "
            "handle it with care and never share it.",
            file=sys.stderr,
        )
    imported = bundle.import_bundle(args.bundle, args.private)

    receipts_dir = args.out_dir / "receipts"
    trust_dir = args.out_dir / "trust"
    for envelope in imported.receipts:
        receipt_id = envelope["payload"]["receipt_id"]
        _write_json_file(receipts_dir / f"{receipt_id}.attest.json", envelope)

    for issuer, chain in imported.trust_store.chains.items():
        for version_manifest in chain:
            version = version_manifest.get("manifest_version", 0)
            _write_json_file(trust_dir / f"{_safe_name(issuer)}.v{version}.json", version_manifest)

    if imported.artifact_manifests:
        artifacts_dir = args.out_dir / "artifact-manifests"
        for series, versions in imported.artifact_manifests.items():
            for am in versions:
                version = am.get("version", 0)
                _write_json_file(artifacts_dir / f"{_safe_name(series)}.v{version}.json", am)

    if imported.legal_texts:
        legal_dir = args.out_dir / "legal"
        legal_dir.mkdir(parents=True, exist_ok=True)
        for digest, content in imported.legal_texts.items():
            (legal_dir / f"{digest}.txt").write_bytes(content)

    if imported.salts:
        salts_payload = {rid: keys.b64u(s) for rid, s in imported.salts.items()}
        _write_secret_text(args.out_dir / "salts.json", json.dumps(salts_payload, indent=2))

    _print_json(
        {
            "out_dir": str(args.out_dir),
            "receipts": len(imported.receipts),
            "issuers": sorted(imported.trust_store.manifests),
        }
    )
    return EXIT_OK


# --- inspect ----------------------------------------------------------------------


def _cmd_inspect(args: argparse.Namespace) -> int:
    envelope = _read_json(args.envelope)
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{args.envelope} is not a JSON object")

    warnings: list[str] = []
    delivery = envelope.get("delivery")
    salt_present = isinstance(delivery, dict) and "salt" in delivery
    if salt_present:
        warnings.append(
            "delivery.salt is present — a shareable file should not carry a buyer-binding salt"
        )

    # Never print the raw buyer-binding secret to stdout: an operator pasting
    # inspect output into a ticket/Slack/shell-history would leak the very
    # secret this verb warns about. Redact it on a deep copy so the on-disk
    # file and the parsed object stay untouched.
    printed = copy.deepcopy(envelope)
    if salt_present:
        printed["delivery"]["salt"] = _REDACTED_SALT

    _print_json({"envelope": printed, "warnings": warnings})
    return EXIT_OK


# --- check-artifact -----------------------------------------------------------------


def _cmd_check_artifact(args: argparse.Namespace) -> int:
    envelope = _read_json(args.receipt)
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    if not isinstance(payload, dict):
        raise CliUsageError(f"{args.receipt} is missing 'payload'")
    work = payload.get("work")
    artifacts = work.get("artifacts") if isinstance(work, dict) else None
    if not artifacts:
        raise CliUsageError(f"{args.receipt} has no work.artifacts to check against")

    try:
        digest = hashlib.sha256(args.file.read_bytes()).hexdigest()
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {args.file}") from exc

    match = next((a for a in artifacts if isinstance(a, dict) and a.get("sha256") == digest), None)
    # This verb compares hashes only; it does NOT authenticate the receipt. Say so
    # loudly and machine-readably so a match is never mistaken for verification
    # (2026-07-13 review, finding 13).
    print(
        "warning: check-artifact compares hashes only and does NOT verify the receipt "
        "signature — use `attest verify` to authenticate the receipt.",
        file=sys.stderr,
    )
    _print_json(
        {
            "file": str(args.file),
            "sha256": digest,
            "match": match is not None,
            "artifact": match,
            "authenticated": False,
        }
    )
    return EXIT_OK if match is not None else EXIT_VERIFICATION_FAILED


# --- argument parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest", description="attest v0.1 operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    p.add_argument("--seed-out", required=True, type=Path, help="secret seed output path (0600)")
    p.add_argument("--pub-out", required=True, type=Path, help="public key output path")
    p.add_argument(
        "--hybrid",
        action="store_true",
        help="also generate an ML-DSA-65 keypair for the v0.2 hybrid profile "
        "(requires --mldsa-out)",
    )
    p.add_argument(
        "--mldsa-out",
        type=Path,
        default=None,
        help="ML-DSA-65 secret key output path (0600 JSON); required with --hybrid",
    )
    p.set_defaults(func=_cmd_keygen)

    p_manifest = sub.add_parser("manifest", help="Key/artifact manifest operations")
    manifest_sub = p_manifest.add_subparsers(dest="manifest_command", required=True)

    p = manifest_sub.add_parser("init", help="Create the first, self-signed key manifest")
    p.add_argument("--issuer", required=True, help="issuer id, e.g. store.example.com")
    p.add_argument("--kid", required=True, help="key id of the bootstrap signing key")
    p.add_argument("--seed", required=True, type=Path, help="seed file for the bootstrap key")
    p.add_argument("--valid-from", required=True)
    p.add_argument("--valid-to", default=None)
    p.add_argument("--issued-at", required=True, help="manifest issuance timestamp")
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); makes the bootstrap entry "
        "and manifest signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_init)

    p = manifest_sub.add_parser(
        "rotate", help="Add a new key and/or retire/compromise existing ones"
    )
    p.add_argument("--in", dest="manifest_in", required=True, type=Path, help="trusted manifest")
    p.add_argument("--signing-kid", required=True, help="active kid from the trusted manifest")
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument("--new-kid", default=None, help="kid of a new key to add (with --new-pub)")
    p.add_argument("--new-pub", type=Path, default=None, help="public key file of the new key")
    p.add_argument(
        "--new-mldsa-pub",
        type=Path,
        default=None,
        help="ML-DSA-65 public key file for the new key; makes the new entry hybrid — "
        "requires --new-pub",
    )
    p.add_argument("--valid-from", default=None, help="required only when adding a new key")
    p.add_argument("--valid-to", default=None)
    p.add_argument(
        "--retire-kid",
        action="append",
        default=[],
        help="repeatable; set an existing key's status to retired (past signatures stay valid)",
    )
    p.add_argument(
        "--compromise-kid",
        action="append",
        default=[],
        help=(
            "repeatable; set an existing key's status to compromised "
            "(invalidates its past signatures)"
        ),
    )
    p.add_argument("--issued-at", required=True)
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 leg of the signing key; makes the manifest signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_rotate)

    p = manifest_sub.add_parser("artifacts", help="Build and sign an artifact manifest")
    p.add_argument(
        "--in", dest="manifest_in", required=True, type=Path, help="signer's key manifest"
    )
    p.add_argument("--issuer", required=True)
    p.add_argument("--series", required=True)
    p.add_argument("--version", required=True, type=int)
    p.add_argument("--released-at", required=True)
    p.add_argument("--artifacts", required=True, type=Path, help="JSON file: array of artifacts")
    p.add_argument("--signing-kid", required=True)
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 leg of the signing key; required exactly for a hybrid key entry",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_artifacts)

    p = sub.add_parser("issue", help="Sign a payload into a receipt envelope")
    p.add_argument("--payload", required=True, type=Path, help="payload JSON to sign")
    p.add_argument("--seed", required=True, type=Path, help="issuer signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument("--salt", type=Path, default=None, help="buyer-binding salt to embed")
    p.add_argument("--salt-out", type=Path, default=None, help="also copy --salt to this path")
    p.add_argument("--manifest-snapshot", type=Path, default=None)
    p.add_argument(
        "--attest-version",
        choices=("0.1", "0.2"),
        default="0.1",
        help="signing profile; 0.2 requires --mldsa-key (hybrid Ed25519+ML-DSA-65)",
    )
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); required with --attest-version 0.2",
    )
    p.add_argument("--out", required=True, type=Path, help="output envelope JSON path")
    p.set_defaults(func=_cmd_issue)

    p = sub.add_parser("verify", help="Verify a receipt envelope")
    p.add_argument("envelope", type=Path)
    p.add_argument("--trust-dir", required=True, type=Path, help="directory of key manifest files")
    p.add_argument("--revocations", type=Path, default=None, help="JSON file: revocation records")
    p.add_argument("--disclose-identifier", default=None)
    p.add_argument("--disclose-type", default=None)
    p.add_argument("--disclose-salt", type=Path, default=None)
    p.add_argument("--disclose-challenge-nonce", type=Path, default=None)
    p.add_argument("--disclose-challenge-sig", type=Path, default=None)
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("disclose", help="Emit one self-contained receipt file")
    p.add_argument("receipt_id")
    p.add_argument("--receipt", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--key-manifest", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--salt", type=Path, default=None, help="this receipt's own buyer-binding salt")
    p.add_argument("--out", required=True, help="output file, or directory (created if missing)")
    p.set_defaults(func=_cmd_disclose)

    p = sub.add_parser("export", help="Export a shareable .attest + secrets .private.attest")
    p.add_argument("--receipt", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--key-manifest", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--artifact-manifest", action="append", type=Path, default=[], help="repeatable")
    p.add_argument(
        "--legal-text",
        action="append",
        type=Path,
        default=[],
        help="repeatable; hash is computed from file content",
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--name", required=True)
    p.set_defaults(func=_cmd_export)

    p = sub.add_parser("import", help="Reconstruct receipts + a trust store from a .attest bundle")
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--private", type=Path, default=None, help=".private.attest sibling, for salts")
    p.add_argument("--out-dir", required=True, type=Path)
    p.set_defaults(func=_cmd_import)

    p = sub.add_parser("inspect", help="Pretty-print an envelope and warn on shareability issues")
    p.add_argument("envelope", type=Path)
    p.set_defaults(func=_cmd_inspect)

    p = sub.add_parser("check-artifact", help="Hash a local file against a receipt's artifacts")
    p.add_argument("file", type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.set_defaults(func=_cmd_check_artifact)

    return parser


# --- entry point ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliUsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,  # e.g. a well-formed-JSON-but-wrong-shape input (list instead of object)
        json.JSONDecodeError,
        canon.CanonError,
        bundle.BundleError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
