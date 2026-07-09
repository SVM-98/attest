"""Generate the committed sample bundle for the web verifier.

Drives the reference implementation the same way demo/store_dies.py does —
in-process CLI verbs, library only for payload assembly — to produce a small,
fictional, self-checking `.attest` bundle plus its binding sidecar. The salt
is a fixed derivation so the published sidecar always matches the published
bundle; the signing key is generated fresh on each run (a regenerated sample
is a different fictional store signing the same fictional deal, which is
fine — the committed pair is what the page serves).

Run it from the repo root: `.venv/bin/python tools/gen_site_sample.py`
(writes to site/public/sample/). Regeneration is manual, never part of CI.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from attest import cli, issue, keys

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "site" / "public" / "sample"

ISSUER = "store.nebula.example"
KID = f"{ISSUER}/keys/2026-q3#ed25519-1"
KEY_VALID_FROM = "2026-01-01T00:00:00Z"

BUYER_IDENTIFIER = "casey@example.com"
BUYER_IDENTIFIER_TYPE = "email"
# Fixed salt: the committed demo-binding.json must reproduce the commitment
# sealed in the committed demo.attest across regenerations of the sidecar.
SALT = hashlib.sha256(b"attest-site-sample-salt-v1").digest()[:16]

ARTIFACT_SERIES = f"{ISSUER}/works/STARLIGHT-001"
GAME_FILENAME = "starlight-drifter-1.0-setup.bin"
GAME_BYTES = (
    b"ATTEST-SITE-SAMPLE-BINARY\n"
    b"Stand-in for a DRM-free installer; the receipt's artifact hash commits to these bytes.\n"
) * 64
LEGAL_TEXT_BYTES = (
    b"attest sample standard license v1\n"
    b"Perpetual, irrevocable, DRM-free license for the purchased title.\n"
)


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Invoke attest.cli.main in-process, capturing stdout/stderr."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = cli.main(argv)
    return rc, stdout.getvalue(), stderr.getvalue()


def _run_cli_json(argv: list[str]) -> dict[str, Any]:
    """Invoke a CLI verb that must succeed; parse its JSON report."""
    rc, stdout, stderr = _run_cli(argv)
    if rc != 0:
        raise RuntimeError(f"attest {argv[0]} failed rc={rc}: {stderr or stdout}")
    return dict(json.loads(stdout))


def _run_cli_capture(argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Invoke a CLI verb whose exit code is part of the outcome; parse JSON."""
    rc, stdout, _stderr = _run_cli(argv)
    return rc, dict(json.loads(stdout))


def main(out_dir: Path = DEFAULT_OUT_DIR) -> dict[str, Any]:
    """Generate demo.attest + demo-binding.json into out_dir; self-check both."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attest-site-sample-") as tmp:
        ws = Path(tmp)
        store, export_dir, import_dir = ws / "store", ws / "export", ws / "import"
        for d in (store, export_dir, import_dir):
            d.mkdir(parents=True)

        seed_path, pub_path = store / "issuer.seed", store / "issuer.pub"
        _run_cli_json(["keygen", "--seed-out", str(seed_path), "--pub-out", str(pub_path)])

        manifest_path = store / "manifest.json"
        _run_cli_json(
            [
                "manifest",
                "init",
                "--issuer",
                ISSUER,
                "--kid",
                KID,
                "--seed",
                str(seed_path),
                "--valid-from",
                KEY_VALID_FROM,
                "--issued-at",
                KEY_VALID_FROM,
                "--out",
                str(manifest_path),
            ]
        )

        game_sha256 = hashlib.sha256(GAME_BYTES).hexdigest()
        artifact_entry = {
            "role": "installer",
            "platform": "linux-x86_64",
            "filename": GAME_FILENAME,
            "size_bytes": len(GAME_BYTES),
            "sha256": game_sha256,
        }
        artifacts_json_path = store / "artifacts.json"
        artifacts_json_path.write_text(json.dumps([artifact_entry]), encoding="utf-8")
        artifact_manifest_path = store / "artifact-manifest.json"
        _run_cli_json(
            [
                "manifest",
                "artifacts",
                "--issuer",
                ISSUER,
                "--series",
                ARTIFACT_SERIES,
                "--version",
                "1",
                "--released-at",
                KEY_VALID_FROM,
                "--artifacts",
                str(artifacts_json_path),
                "--signing-kid",
                KID,
                "--signing-seed",
                str(seed_path),
                "--out",
                str(artifact_manifest_path),
            ]
        )

        legal_text_path = store / "legal.txt"
        legal_text_path.write_bytes(LEGAL_TEXT_BYTES)
        salt_path = store / "receipt.salt"
        salt_path.write_text(keys.b64u(SALT), encoding="utf-8")

        payload = issue.build_payload(
            issuer_id=ISSUER,
            display_name="Nebula Games",
            buyer_identifier=BUYER_IDENTIFIER,
            buyer_identifier_type=BUYER_IDENTIFIER_TYPE,
            buyer_salt=SALT,
            title="Starlight Drifter",
            publisher="Nebula Games Co-op",
            identifiers={"issuer_sku": "STARLIGHT-001"},
            artifact_series=ARTIFACT_SERIES,
            terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
            legal_text_sha256=hashlib.sha256(LEGAL_TEXT_BYTES).hexdigest(),
            artifacts=[artifact_entry],
            revocability="none",
            drm="drm-free",
        )
        payload_path = store / "payload.json"
        payload_path.write_text(json.dumps(payload), encoding="utf-8")

        receipt_path = store / "receipt.attest.json"
        _run_cli_json(
            [
                "issue",
                "--payload",
                str(payload_path),
                "--seed",
                str(seed_path),
                "--kid",
                KID,
                "--salt",
                str(salt_path),
                "--out",
                str(receipt_path),
            ]
        )

        export_report = _run_cli_json(
            [
                "export",
                "--receipt",
                str(receipt_path),
                "--key-manifest",
                str(manifest_path),
                "--artifact-manifest",
                str(artifact_manifest_path),
                "--legal-text",
                str(legal_text_path),
                "--out-dir",
                str(export_dir),
                "--name",
                "demo",
            ]
        )
        attest_src = Path(export_report["attest"])

        # Self-check: import the bundle store-lessly and verify, then prove binding.
        _run_cli_json(["import", "--bundle", str(attest_src), "--out-dir", str(import_dir)])
        imported_receipt = next((import_dir / "receipts").glob("*.attest.json"))
        trust_dir = import_dir / "trust"
        rc_v, verify_report = _run_cli_capture(
            ["verify", str(imported_receipt), "--trust-dir", str(trust_dir)]
        )
        rc_d, disclosure_report = _run_cli_capture(
            [
                "verify",
                str(imported_receipt),
                "--trust-dir",
                str(trust_dir),
                "--disclose-identifier",
                BUYER_IDENTIFIER,
                "--disclose-type",
                BUYER_IDENTIFIER_TYPE,
                "--disclose-salt",
                str(salt_path),
            ]
        )
        if rc_v != 0 or not verify_report.get("ok"):
            raise RuntimeError(f"self-check verify failed: {verify_report}")
        if rc_d != 0 or disclosure_report.get("binding") != "proven":
            raise RuntimeError(f"self-check binding failed: {disclosure_report}")

        # Publish ONLY the shareable bundle + the binding sidecar. The
        # .private.attest stays in the temp workspace and dies with it.
        attest_dst = out_dir / "demo.attest"
        shutil.copyfile(attest_src, attest_dst)
        binding_dst = out_dir / "demo-binding.json"
        binding_dst.write_text(
            json.dumps(
                {
                    "identifier": BUYER_IDENTIFIER,
                    "identifier_type": BUYER_IDENTIFIER_TYPE,
                    "salt_b64u": keys.b64u(SALT),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return {
        "attest": str(attest_dst),
        "binding": str(binding_dst),
        "self_check": {
            "verify": verify_report,
            "verify_with_disclosure": disclosure_report,
        },
    }


if __name__ == "__main__":
    report = main()
    print(json.dumps({"attest": report["attest"], "binding": report["binding"]}, indent=2))
    sys.exit(0)
