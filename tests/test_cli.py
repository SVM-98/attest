"""Tests for opr.cli — the operator-facing command surface (design §10).

`cli.main([...])` is driven directly (no subprocess), per Task 14's brief.
Every verb is a thin wrapper around a single library call, so these tests
exercise CLI plumbing (argument parsing, file I/O, exit codes) rather than
re-testing crypto/schema logic already covered by the library's own suite.
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from opr import cli, keys
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test-1#ed25519-1"
VALID_FROM = "2026-01-01T00:00:00Z"

CapSys = pytest.CaptureFixture[str]


# --- shared helpers (build a pipeline through the CLI itself) ---------------


def _keygen(tmp_path: Path, name: str) -> tuple[Path, Path]:
    seed_out = tmp_path / f"{name}.seed"
    pub_out = tmp_path / f"{name}.pub"
    rc = cli.main(["keygen", "--seed-out", str(seed_out), "--pub-out", str(pub_out)])
    assert rc == 0
    return seed_out, pub_out


def _manifest_init(tmp_path: Path, seed: Path, out_name: str = "manifest.json") -> Path:
    out = tmp_path / out_name
    rc = cli.main(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed),
            "--valid-from",
            VALID_FROM,
            "--issued-at",
            VALID_FROM,
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    return out


def _write_payload(tmp_path: Path, name: str = "payload.json", **overrides: Any) -> Path:
    payload = make_payload(issuer={"id": ISSUER, "display_name": "Example Store"}, **overrides)
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_salt_file(tmp_path: Path, name: str, raw: bytes) -> Path:
    path = tmp_path / name
    path.write_text(keys.b64u(raw), encoding="utf-8")
    return path


def _issue(
    tmp_path: Path,
    seed: Path,
    payload_path: Path,
    out_name: str = "envelope.json",
    salt: Path | None = None,
    salt_out: Path | None = None,
) -> Path:
    out = tmp_path / out_name
    argv = [
        "issue",
        "--payload",
        str(payload_path),
        "--seed",
        str(seed),
        "--kid",
        KID,
        "--out",
        str(out),
    ]
    if salt is not None:
        argv += ["--salt", str(salt)]
    if salt_out is not None:
        argv += ["--salt-out", str(salt_out)]
    rc = cli.main(argv)
    assert rc == 0
    return out


def _trust_dir(tmp_path: Path, manifest_path: Path, name: str = "trust") -> Path:
    trust_dir = tmp_path / name
    trust_dir.mkdir()
    manifest_text = manifest_path.read_text(encoding="utf-8")
    (trust_dir / "issuer.json").write_text(manifest_text, encoding="utf-8")
    return trust_dir


# --- keygen ------------------------------------------------------------------


def test_keygen_writes_seed_file_with_0600_perms(tmp_path: Path) -> None:
    seed_out, pub_out = _keygen(tmp_path, "issuer")

    mode = stat.S_IMODE(seed_out.stat().st_mode)
    assert mode == 0o600
    assert pub_out.exists()


def test_keygen_never_prints_the_seed_to_stdout(tmp_path: Path, capsys: CapSys) -> None:
    seed_out, _pub_out = _keygen(tmp_path, "issuer")

    seed_text = seed_out.read_text(encoding="utf-8").strip()
    captured = capsys.readouterr().out
    assert seed_text not in captured


def test_keygen_prints_pub_key_json_to_stdout(tmp_path: Path, capsys: CapSys) -> None:
    _seed_out, pub_out = _keygen(tmp_path, "issuer")

    report = json.loads(capsys.readouterr().out)
    assert report["pub"] == pub_out.read_text(encoding="utf-8").strip()


# --- manifest init -------------------------------------------------------------


def test_manifest_init_writes_self_consistent_manifest(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["issuer"] == ISSUER
    assert manifest["manifest_version"] == 1
    assert manifest["keys"][0]["kid"] == KID


# --- full happy path: keygen -> manifest init -> issue -> verify -------------


def test_full_happy_path_verify_exits_0(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["signature"] == "valid"
    assert result["trust"] == "unauthenticated_tofu"


def test_verify_of_tampered_envelope_exits_1(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["payload"]["work"]["title"] = "Tampered Title"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["signature"] == "invalid"


def test_verify_unknown_issuer_no_trust_dir_match_exits_1(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    empty_trust_dir = tmp_path / "empty_trust"
    empty_trust_dir.mkdir()

    capsys.readouterr()
    rc = cli.main(["verify", str(envelope_path), "--trust-dir", str(empty_trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False


# --- check-artifact ------------------------------------------------------------


def test_check_artifact_matching_sha256_exits_0(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    artifact_bytes = b"totally-a-game-installer"
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    payload_path = _write_payload(
        tmp_path,
        work={
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": len(artifact_bytes),
                    "sha256": digest,
                }
            ]
        },
    )
    envelope_path = _issue(tmp_path, seed, payload_path)
    local_file = tmp_path / "game.exe"
    local_file.write_bytes(artifact_bytes)

    capsys.readouterr()
    rc = cli.main(["check-artifact", str(local_file), "--receipt", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["match"] is True
    assert result["sha256"] == digest


def test_check_artifact_mismatching_sha256_exits_nonzero(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    artifact_bytes = b"totally-a-game-installer"
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    payload_path = _write_payload(
        tmp_path,
        work={
            "artifacts": [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": len(artifact_bytes),
                    "sha256": digest,
                }
            ]
        },
    )
    envelope_path = _issue(tmp_path, seed, payload_path)
    local_file = tmp_path / "game.exe"
    local_file.write_bytes(b"a completely different, corrupted file")

    capsys.readouterr()
    rc = cli.main(["check-artifact", str(local_file), "--receipt", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc != 0
    assert result["match"] is False


# --- inspect ---------------------------------------------------------------


def test_inspect_warns_on_delivery_salt_presence(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt_path = _write_salt_file(tmp_path, "salt.b64u", bytes(range(16)))
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    capsys.readouterr()
    rc = cli.main(["inspect", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert any("salt" in w for w in result["warnings"])


def test_inspect_no_warning_when_no_salt_present(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    capsys.readouterr()
    rc = cli.main(["inspect", str(envelope_path)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["warnings"] == []


# --- issue: --salt / --salt-out ---------------------------------------------


def test_issue_embeds_supplied_salt_in_delivery(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)

    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert envelope["delivery"]["salt"] == keys.b64u(raw_salt)


def test_issue_salt_out_writes_the_same_salt_with_0600_perms(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    salt_out_path = tmp_path / "receipt-salt.out"

    _issue(tmp_path, seed, payload_path, salt=salt_path, salt_out=salt_out_path)

    assert salt_out_path.read_text(encoding="utf-8").strip() == keys.b64u(raw_salt)
    mode = stat.S_IMODE(salt_out_path.stat().st_mode)
    assert mode == 0o600


def test_issue_salt_out_without_salt_is_usage_error(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
            "--salt-out",
            str(tmp_path / "salt.out"),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


# --- verify: disclosure (binding proof) -------------------------------------


def test_verify_with_matching_disclosure_proves_binding(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)

    from opr import commitment

    raw_salt = bytes(range(16))
    identifier = "buyer@example.com"
    identifier_type = "email"
    commit = commitment.compute(identifier, identifier_type, raw_salt)
    payload_path = _write_payload(
        tmp_path,
        buyer={
            "commitment": keys.b64u(commit),
            "identifier_type": identifier_type,
            "pubkey": None,
        },
    )
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--disclose-identifier",
            identifier,
            "--disclose-type",
            identifier_type,
            "--disclose-salt",
            str(salt_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["binding"] == "proven"


# --- disclose ----------------------------------------------------------------


def test_disclose_writes_into_a_not_yet_existing_directory(
    tmp_path: Path, capsys: CapSys
) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    raw_salt = bytes(range(16))
    salt_path = _write_salt_file(tmp_path, "salt.b64u", raw_salt)
    envelope_path = _issue(tmp_path, seed, payload_path, salt=salt_path)

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    receipt_id = payload["receipt_id"]

    out_dir = tmp_path / "share"
    assert not out_dir.exists()

    capsys.readouterr()
    rc = cli.main(
        [
            "disclose",
            receipt_id,
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--salt",
            str(salt_path),
            "--out",
            str(out_dir) + "/",
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    written = Path(result["out"])
    assert written == out_dir / f"{receipt_id}.opr.json"
    assert written.exists()

    disclosed = json.loads(written.read_text(encoding="utf-8"))
    assert disclosed["payload"]["receipt_id"] == receipt_id
    assert disclosed["delivery"]["salt"] == keys.b64u(raw_salt)


def test_disclose_writes_to_exact_file_path(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    receipt_id = payload["receipt_id"]
    exact_out = tmp_path / "my-receipt.opr.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "disclose",
            receipt_id,
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--out",
            str(exact_out),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert Path(result["out"]) == exact_out
    assert exact_out.exists()


# --- export / import roundtrip via CLI ---------------------------------------


def test_export_then_import_then_verify_roundtrip(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, seed, payload_path)

    legal_text = (
        make_payload()["license"]["legal_text_sha256"],  # unused, just documents shape
    )
    del legal_text
    legal_text_bytes = b"opr-test-legal-text-v1"
    assert hashlib.sha256(legal_text_bytes).hexdigest() == json.loads(
        payload_path.read_text(encoding="utf-8")
    )["license"]["legal_text_sha256"]
    legal_text_path = tmp_path / "legal.txt"
    legal_text_path.write_bytes(legal_text_bytes)

    mirror_policy_bytes = b"opr-test-mirror-policy-v1"
    mirror_policy_path = tmp_path / "mirror-policy.txt"
    mirror_policy_path.write_bytes(mirror_policy_bytes)

    out_dir = tmp_path / "bundle_out"
    capsys.readouterr()
    rc = cli.main(
        [
            "export",
            "--receipt",
            str(envelope_path),
            "--key-manifest",
            str(manifest_path),
            "--legal-text",
            str(legal_text_path),
            "--legal-text",
            str(mirror_policy_path),
            "--out-dir",
            str(out_dir),
            "--name",
            "mylibrary",
        ]
    )
    export_report = json.loads(capsys.readouterr().out)
    assert rc == 0

    import_out_dir = tmp_path / "imported"
    rc = cli.main(
        [
            "import",
            "--bundle",
            export_report["oprx"],
            "--out-dir",
            str(import_out_dir),
        ]
    )
    import_report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert import_report["receipts"] == 1

    imported_trust_dir = import_out_dir / "trust"
    imported_receipt = next((import_out_dir / "receipts").glob("*.opr.json"))

    capsys.readouterr()
    rc = cli.main(["verify", str(imported_receipt), "--trust-dir", str(imported_trust_dir)])
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["trust"] == "unauthenticated_tofu"


# --- manifest rotate / manifest artifacts -------------------------------------


def test_manifest_rotate_produces_version_2_signed_by_version_1_key(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    _new_seed, new_pub = _keygen(tmp_path, "issuer-2")
    new_kid = f"{ISSUER}/keys/test-2#ed25519-1"

    rotated_out = tmp_path / "manifest-v2.json"
    rc = cli.main(
        [
            "manifest",
            "rotate",
            "--in",
            str(manifest_path),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--new-kid",
            new_kid,
            "--new-pub",
            str(new_pub),
            "--valid-from",
            "2026-02-01T00:00:00Z",
            "--issued-at",
            "2026-02-01T00:00:00Z",
            "--out",
            str(rotated_out),
        ]
    )
    assert rc == 0

    from opr import manifests

    trusted = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidate = json.loads(rotated_out.read_text(encoding="utf-8"))
    assert candidate["manifest_version"] == 2
    assert manifests.check_continuity(trusted, candidate)


def test_manifest_artifacts_builds_signed_artifact_manifest(tmp_path: Path) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    _manifest_init(tmp_path, seed)

    artifacts_path = tmp_path / "artifacts.json"
    artifacts_path.write_text(
        json.dumps(
            [
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "game.exe",
                    "size_bytes": 123,
                    "sha256": "a" * 64,
                }
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "artifact-manifest.json"

    rc = cli.main(
        [
            "manifest",
            "artifacts",
            "--issuer",
            ISSUER,
            "--series",
            f"{ISSUER}/works/EXG-001",
            "--version",
            "1",
            "--released-at",
            VALID_FROM,
            "--artifacts",
            str(artifacts_path),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed),
            "--out",
            str(out),
        ]
    )
    assert rc == 0

    from opr import manifests

    key_manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    artifact_manifest = json.loads(out.read_text(encoding="utf-8"))
    assert manifests.verify_artifact_manifest(artifact_manifest, key_manifest)


# --- usage / IO errors exit 2 -------------------------------------------------


def test_verify_missing_envelope_file_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()

    rc = cli.main(["verify", str(tmp_path / "nope.json"), "--trust-dir", str(trust_dir)])

    assert rc == 2
    assert capsys.readouterr().err != ""


def test_issue_invalid_payload_json_exits_2(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    bad_payload = tmp_path / "bad.json"
    bad_payload.write_text("{not valid json", encoding="utf-8")
    out = tmp_path / "envelope.json"

    rc = cli.main(
        [
            "issue",
            "--payload",
            str(bad_payload),
            "--seed",
            str(seed),
            "--kid",
            KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert capsys.readouterr().err != ""


# --- --help surfaces -----------------------------------------------------------


def test_top_level_help_exits_0(capsys: CapSys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0


def test_verify_help_exits_0(capsys: CapSys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["verify", "--help"])
    assert exc_info.value.code == 0
