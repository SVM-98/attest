"""`opr` command-line interface — the operator surface (design §10).

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
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from opr import bundle, canon, issue, keys, manifests, verify

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE_ERROR = 2

_SECRET_FILE_MODE = 0o600
_PROVENANCE_BUNDLE = "bundle"  # local trust material is unauthenticated TOFU (design §5)


class CliUsageError(Exception):
    """A usage/IO problem this CLI can explain better than the raw exception."""


# --- small I/O helpers -------------------------------------------------------


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


def _write_json_file(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _write_secret_text(path: Path, text: str) -> None:
    """Write a secret (seed, salt) to `path` and lock it down to 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, _SECRET_FILE_MODE)


def _read_b64u_file(path: Path) -> bytes:
    return keys.b64u_decode(path.read_text(encoding="utf-8").strip())


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _load_seed_kp(path: Path) -> keys.SigningKeyPair:
    return keys.from_seed(_read_b64u_file(path))


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
    """Sanitize an issuer/series identifier for use as a filename component."""
    return value.replace("/", "_")


# --- keygen -------------------------------------------------------------------


def _cmd_keygen(args: argparse.Namespace) -> int:
    kp = keys.generate()
    _write_secret_text(args.seed_out, keys.b64u(kp.seed))
    args.pub_out.parent.mkdir(parents=True, exist_ok=True)
    args.pub_out.write_text(keys.b64u(kp.pub), encoding="utf-8")
    _print_json(
        {"pub": keys.b64u(kp.pub), "seed_out": str(args.seed_out), "pub_out": str(args.pub_out)}
    )
    return EXIT_OK


# --- manifest init / rotate / artifacts ---------------------------------------


def _cmd_manifest_init(args: argparse.Namespace) -> int:
    kp = _load_seed_kp(args.seed)
    entry = manifests.key_entry(args.kid, kp.pub, args.valid_from, args.valid_to)
    manifest = manifests.build_key_manifest(args.issuer, 1, args.issued_at, [entry], kp, args.kid)
    _write_json_file(args.out, manifest)
    _print_json({"out": str(args.out), "issuer": args.issuer, "manifest_version": 1})
    return EXIT_OK


def _cmd_manifest_rotate(args: argparse.Namespace) -> int:
    existing = _read_json(args.manifest_in)
    if not isinstance(existing, dict) or "keys" not in existing:
        raise CliUsageError(f"{args.manifest_in} is not a key manifest")

    signing_kp = _load_seed_kp(args.signing_seed)
    new_pub = _read_b64u_file(args.new_pub)
    new_entry = manifests.key_entry(args.new_kid, new_pub, args.valid_from, args.valid_to)

    new_version = existing["manifest_version"] + 1
    key_entries = [*existing["keys"], new_entry]
    manifest = manifests.build_key_manifest(
        existing["issuer"], new_version, args.issued_at, key_entries, signing_kp, args.signing_kid
    )
    _write_json_file(args.out, manifest)
    _print_json(
        {"out": str(args.out), "issuer": existing["issuer"], "manifest_version": new_version}
    )
    return EXIT_OK


def _cmd_manifest_artifacts(args: argparse.Namespace) -> int:
    artifacts = _read_json(args.artifacts)
    if not isinstance(artifacts, list):
        raise CliUsageError(f"{args.artifacts} must contain a JSON array of artifact entries")

    signing_kp = _load_seed_kp(args.signing_seed)
    manifest = manifests.build_artifact_manifest(
        args.issuer,
        args.series,
        args.version,
        args.released_at,
        artifacts,
        signing_kp,
        args.signing_kid,
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
    if args.salt_out is not None and args.salt is None:
        raise CliUsageError("--salt-out requires --salt (nothing to write out otherwise)")

    payload = _read_json(args.payload)
    signing_kp = _load_seed_kp(args.seed)
    salt = _read_b64u_file(args.salt) if args.salt is not None else None
    manifest_snapshot = _read_json(args.manifest_snapshot) if args.manifest_snapshot else None

    envelope = issue.issue(
        payload, signing_kp, args.kid, salt=salt, manifest_snapshot=manifest_snapshot
    )
    _write_json_file(args.out, envelope)
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

    oprx_path, private_path = bundle.export(
        receipts, key_manifests, artifact_manifests, legal_texts, args.out_dir, args.name
    )
    _print_json({"oprx": str(oprx_path), "private": str(private_path)})
    return EXIT_OK


def _cmd_import(args: argparse.Namespace) -> int:
    imported = bundle.import_bundle(args.bundle, args.private)

    receipts_dir = args.out_dir / "receipts"
    trust_dir = args.out_dir / "trust"
    for envelope in imported.receipts:
        receipt_id = envelope["payload"]["receipt_id"]
        _write_json_file(receipts_dir / f"{receipt_id}.opr.json", envelope)

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
    if isinstance(delivery, dict) and "salt" in delivery:
        warnings.append(
            "delivery.salt is present — a shareable file should not carry a buyer-binding salt"
        )

    _print_json({"envelope": envelope, "warnings": warnings})
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

    match = next(
        (a for a in artifacts if isinstance(a, dict) and a.get("sha256") == digest), None
    )
    _print_json(
        {"file": str(args.file), "sha256": digest, "match": match is not None, "artifact": match}
    )
    return EXIT_OK if match is not None else EXIT_VERIFICATION_FAILED


# --- argument parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opr", description="Open Purchase Receipt (OPR) v0.1 operator CLI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    p.add_argument("--seed-out", required=True, type=Path, help="secret seed output path (0600)")
    p.add_argument("--pub-out", required=True, type=Path, help="public key output path")
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
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_init)

    p = manifest_sub.add_parser("rotate", help="Add a new key, signed by a currently-active one")
    p.add_argument("--in", dest="manifest_in", required=True, type=Path, help="trusted manifest")
    p.add_argument("--signing-kid", required=True, help="active kid from the trusted manifest")
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument("--new-kid", required=True)
    p.add_argument("--new-pub", required=True, type=Path, help="public key file of the new key")
    p.add_argument("--valid-from", required=True)
    p.add_argument("--valid-to", default=None)
    p.add_argument("--issued-at", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_rotate)

    p = manifest_sub.add_parser("artifacts", help="Build and sign an artifact manifest")
    p.add_argument("--issuer", required=True)
    p.add_argument("--series", required=True)
    p.add_argument("--version", required=True, type=int)
    p.add_argument("--released-at", required=True)
    p.add_argument("--artifacts", required=True, type=Path, help="JSON file: array of artifacts")
    p.add_argument("--signing-kid", required=True)
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_artifacts)

    p = sub.add_parser("issue", help="Sign a payload into a receipt envelope")
    p.add_argument("--payload", required=True, type=Path, help="payload JSON to sign")
    p.add_argument("--seed", required=True, type=Path, help="issuer signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument("--salt", type=Path, default=None, help="buyer-binding salt to embed")
    p.add_argument("--salt-out", type=Path, default=None, help="also copy --salt to this path")
    p.add_argument("--manifest-snapshot", type=Path, default=None)
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

    p = sub.add_parser("export", help="Export a shareable .oprx + secrets .private.oprx")
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

    p = sub.add_parser("import", help="Reconstruct receipts + a trust store from a .oprx bundle")
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--private", type=Path, default=None, help=".private.oprx sibling, for salts")
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
        json.JSONDecodeError,
        canon.CanonError,
        bundle.BundleError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
