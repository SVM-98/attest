"""Export/import bundles and the single-receipt `disclose` unit (design §9).

"A receipt whose terms can no longer be produced is a signature without a
deal — the bundle must preserve the deal." `export()` therefore refuses
(`BundleError`) to produce a bundle unless every hash-bound legal document a
receipt points to (`license.legal_text_sha256`, `survivability.
mirror_policy_sha256`, `survivability.eol_commitment_sha256`) is supplied
with matching bytes — the deal's terms travel with the signature, not just
the signature.

Two files come out of `export()`:

- `<name>.attest` — shareable-safe. Receipts have `delivery.salt` stripped
  (the buyer-binding secret never leaves the buyer's private file), key and
  artifact manifests are grouped per issuer so `import_bundle()` can rebuild
  a working `verify.TrustStore` offline, referenced legal texts travel
  content-addressed by their sha256, and a generated `README.html` explains
  what the bundle is and which sibling file must never be shared.
- `<name>.private.attest` — secrets. `salts.json` maps `receipt_id -> salt`
  (base64url); `keys/` is reserved for per-receipt buyer signing keypairs,
  but `export()`'s signature never receives that private key material (the
  store issuing receipts never holds a buyer's private key), so it stays
  empty in this implementation — buyer clients that generate per-receipt
  keypairs are expected to manage that material outside of `bundle.py` and
  write it into `keys/` themselves before distributing the private file.

`manifests/<issuer>.json` convention (chosen here, documented for
`import_bundle()` to rely on): one JSON object per issuer,
`{"issuer": ..., "key_manifests": [...], "artifact_manifests": [...]}`, each
list sorted ascending by its own version field
(`manifest_version`/`version`). `import_bundle()` treats the
highest-`manifest_version` entry as the issuer's current key manifest
(`TrustStore.manifests`) and the full sorted list as its rotation history
(`TrustStore.chains`) — every issuer found in the bundle is trusted with
provenance `"bundle"` (design §5: unauthenticated TOFU, never silently
treated as `"verified"`).

`disclose()` is the single-receipt sharing unit (design §9): it emits one
`.attest.json` self-contained via `delivery` — that receipt's own salt (never
the whole salts map) plus a key-manifest snapshot that still lists the kid
that signed it, so the file verifies standalone even against a bundle-less
verifier.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attest import keys, manifests, verify

_PROVENANCE_BUNDLE = "bundle"
_SECRET_FILE_MODE = 0o600  # disclose output carries delivery.salt (a bearer secret)

# Decompression caps for import_bundle (zip-bomb hardening). A .attest is
# attacker-supplied — it is meant to survive peer-to-peer — so every member is
# read under a bound. Defaults are generous for real libraries (JSON + legal
# text) and still stop a bomb by orders of magnitude.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024  # 64 MiB per decompressed member
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB decompressed across one bundle
_MAX_ENTRIES = 100_000  # central-directory entry count
_READ_CHUNK = 1024 * 1024  # 1 MiB streaming read granularity

_README_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>attest receipt bundle: __BUNDLE_NAME__</title>
</head>
<body>
<h1>attest receipt bundle: __BUNDLE_NAME__</h1>

<h2>What this is</h2>
<p>This is an attest export bundle. It contains one or
more signed purchase receipts, the issuer key manifests needed to verify
them, and the full text of every license, mirror policy and end-of-life
commitment document any receipt in this bundle refers to. Everything a
verifier needs is inside this one file: no network access, no account with
the original store, and no cooperation from the issuer is required.</p>

<h2>How to verify, even if the store no longer exists</h2>
<p>Feed this bundle to any attest-compatible verifier (for example, the
reference implementation: <code>attest import __BUNDLE_NAME__.attest</code> then
<code>attest verify &lt;receipt_id&gt;</code>). Verification is fully offline:
each receipt's Ed25519 signature is checked against the issuer's own key
manifest, and both travel inside this bundle. Because this bundle was built
without a live TLS connection to the issuer at verification time, a
compatible verifier reports trust as <code>unauthenticated_tofu</code>
rather than <code>verified</code> — the signatures are exactly as valid;
only their provenance could not be freshly confirmed over the network.</p>

<h2 style="color:#b00020">Never share __BUNDLE_NAME__.private.attest</h2>
<p><strong>This file, __BUNDLE_NAME__.attest, is safe to share</strong> — it
was built to contain no secrets. The separate sibling file
<strong>__BUNDLE_NAME__.private.attest is not safe to share</strong>: it holds
your buyer-binding salts (and, if you use per-receipt signing keys, those
private keys too), which are what prove these receipts belong to you.
Handing that file to anyone else hands them that proof for every receipt in
your library at once. Keep <code>__BUNDLE_NAME__.private.attest</code> for
yourself. If you need to share or prove a single receipt, use
<code>attest disclose &lt;receipt_id&gt;</code> instead — it discloses only
that one receipt's binding secret, never your whole library.</p>
</body>
</html>
"""


class BundleError(Exception):
    """A bundle cannot be produced without breaking the deal it claims to preserve (§9)."""


@dataclass(frozen=True)
class ImportedBundle:
    """Everything `import_bundle()` reconstructed from a `.attest` (and,
    optionally, its `.private.attest` sibling) — enough to verify every
    receipt offline via `trust_store`."""

    receipts: list[dict[str, Any]]
    trust_store: verify.TrustStore
    artifact_manifests: dict[str, list[dict[str, Any]]]
    legal_texts: dict[str, bytes]
    salts: dict[str, bytes]


def _referenced_legal_hashes(payload: dict[str, Any]) -> list[str]:
    """Every hash-bound legal document this payload's terms depend on:
    `license.legal_text_sha256` (always present, schema-required) plus
    `survivability.mirror_policy_sha256` and `survivability.
    eol_commitment_sha256` when present and non-null. Malformed/missing
    blocks contribute no hashes rather than raising — schema validation
    upstream is what should catch a malformed payload; this function only
    decides which legal texts a well-formed one requires."""
    hashes: list[str] = []

    license_block = payload.get("license")
    if isinstance(license_block, dict):
        h = license_block.get("legal_text_sha256")
        if isinstance(h, str):
            hashes.append(h)

    survivability = payload.get("survivability")
    if isinstance(survivability, dict):
        for field_name in ("mirror_policy_sha256", "eol_commitment_sha256"):
            h = survivability.get(field_name)
            if isinstance(h, str):
                hashes.append(h)

    return hashes


def _check_legal_text(digest: str, legal_texts: dict[str, bytes]) -> None:
    content = legal_texts.get(digest)
    if content is None:
        raise BundleError(
            f"no legal text supplied for hash {digest!r} — the bundle cannot preserve "
            "the deal this receipt refers to"
        )
    if hashlib.sha256(content).hexdigest() != digest:
        raise BundleError(f"legal text supplied for hash {digest!r} does not hash to that value")


def _strip_salt(envelope: dict[str, Any]) -> dict[str, Any]:
    """Shareable-safe copy: same envelope, `delivery.salt` removed. If
    `delivery` had no other member, it is dropped entirely rather than left
    as an empty object — `{}` and "member absent" are different shapes and a
    simpler consumer should not have to tell them apart."""
    stripped = dict(envelope)
    delivery = stripped.get("delivery")
    if isinstance(delivery, dict) and "salt" in delivery:
        remaining = {k: v for k, v in delivery.items() if k != "salt"}
        if remaining:
            stripped["delivery"] = remaining
        else:
            del stripped["delivery"]
    return stripped


def _group_manifests_by_issuer(
    key_manifests: list[dict[str, Any]], artifact_manifests: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for km in key_manifests:
        issuer = km.get("issuer")
        if not isinstance(issuer, str):
            continue
        grouped.setdefault(issuer, {"key_manifests": [], "artifact_manifests": []})
        grouped[issuer]["key_manifests"].append(km)
    for am in artifact_manifests:
        issuer = am.get("issuer")
        if not isinstance(issuer, str):
            continue
        grouped.setdefault(issuer, {"key_manifests": [], "artifact_manifests": []})
        grouped[issuer]["artifact_manifests"].append(am)

    result: dict[str, dict[str, Any]] = {}
    for issuer, blob in grouped.items():
        blob["key_manifests"].sort(key=lambda m: m.get("manifest_version", 0))
        blob["artifact_manifests"].sort(key=lambda m: m.get("version", 0))
        result[issuer] = {"issuer": issuer, **blob}
    return result


def _render_readme(name: str) -> str:
    return _README_TEMPLATE.replace("__BUNDLE_NAME__", name)


def _write_secret_json(path: Path, obj: dict[str, Any]) -> None:
    """Write a secret-bearing JSON file (the disclose output embeds
    `delivery.salt`) created atomically with owner-only 0600 permissions.

    `os.open(..., O_CREAT, 0600)` sets the mode at creation time, so there is
    never the world-readable window a plain `write_text(...)` + `chmod(...)`
    leaves under the default umask. `os.fchmod` on the already-open fd then
    also pins the mode when `path` pre-existed with looser perms (a re-run
    overwriting a prior disclosure) — race-free, it acts on the fd not the
    path. Mirrors `cli._write_secret_text` deliberately.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _SECRET_FILE_MODE)
    with os.fdopen(fd, "w") as fh:  # takes ownership of fd; closes even on raise
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        json.dump(obj, fh)


def export(
    receipts: list[dict[str, Any]],
    key_manifests: list[dict[str, Any]],
    artifact_manifests: list[dict[str, Any]],
    legal_texts: dict[str, bytes],
    out_dir: Path,
    name: str,
) -> tuple[Path, Path]:
    """Write `<name>.attest` (shareable) and `<name>.private.attest` (secrets).

    Every legal-text hash referenced by any receipt is checked against
    `legal_texts` BEFORE anything is written to disk (§9: preserve the
    deal) — a partially-written bundle is worse than none, so validation
    happens as a whole pass first.
    """
    for envelope in receipts:
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise BundleError("receipt envelope missing object member 'payload'")
        for digest in _referenced_legal_hashes(payload):
            _check_legal_text(digest, legal_texts)

    out_dir.mkdir(parents=True, exist_ok=True)
    attest_path = out_dir / f"{name}.attest"
    private_path = out_dir / f"{name}.private.attest"

    salts_b64u: dict[str, str] = {}
    referenced_hashes: set[str] = set()

    with zipfile.ZipFile(attest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for envelope in receipts:
            payload = envelope["payload"]
            receipt_id = payload["receipt_id"]
            referenced_hashes.update(_referenced_legal_hashes(payload))

            delivery = envelope.get("delivery")
            if isinstance(delivery, dict) and isinstance(delivery.get("salt"), str):
                salts_b64u[receipt_id] = delivery["salt"]

            zf.writestr(f"receipts/{receipt_id}.attest.json", json.dumps(_strip_salt(envelope)))

        for issuer, blob in _group_manifests_by_issuer(key_manifests, artifact_manifests).items():
            zf.writestr(f"manifests/{issuer}.json", json.dumps(blob))

        for digest in sorted(referenced_hashes):
            zf.writestr(f"legal/{digest}.txt", legal_texts[digest])

        zf.writestr("README.html", _render_readme(name))

    # The private archive carries buyer-binding salts (bearer secrets); create it
    # owner-only (0600) race-free, mirroring _write_secret_json, so it never has a
    # world-readable window under the default umask (2026-07-13 review, finding 2).
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _SECRET_FILE_MODE)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        with zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("salts.json", json.dumps(salts_b64u))

    return attest_path, private_path


class _SizeBudget:
    """Reads zip members under a per-member cap and a shared aggregate cap,
    streaming so a member is never fully decompressed into memory before its
    size is known. The streamed byte count — not the (spoofable)
    `ZipInfo.file_size` header — is authoritative, which is what catches a
    bomb whose header lies low."""

    def __init__(self, max_member_bytes: int, max_total_bytes: int) -> None:
        self._max_member = max_member_bytes
        self._max_total = max_total_bytes
        self._spent = 0

    def read(self, zf: zipfile.ZipFile, name: str) -> bytes:
        cap = min(self._max_member, self._max_total - self._spent)
        chunks: list[bytes] = []
        got = 0
        with zf.open(name) as member:
            while True:
                chunk = member.read(_READ_CHUNK)
                if not chunk:
                    break
                got += len(chunk)
                if got > cap:
                    raise BundleError(
                        f"member {name!r} exceeds the decompression size cap "
                        f"(max {self._max_member} bytes/member, {self._max_total} "
                        "bytes/bundle) — refusing to import a possible zip bomb"
                    )
                chunks.append(chunk)
        self._spent += got
        return b"".join(chunks)


def _guard_zip(zf: zipfile.ZipFile, max_entries: int, max_total_bytes: int) -> None:
    """Zero-cost pre-read gates: reject a central directory with too many
    entries, or one whose DECLARED uncompressed total already exceeds the
    aggregate cap (catches an honest-but-huge bundle, and a header lying high,
    before a single byte is decompressed)."""
    infos = zf.infolist()
    if len(infos) > max_entries:
        raise BundleError(
            f"bundle declares {len(infos)} entries, over the {max_entries} cap "
            "— refusing to import a possible zip bomb"
        )
    declared_total = sum(info.file_size for info in infos)
    if declared_total > max_total_bytes:
        raise BundleError(
            f"bundle declares {declared_total} uncompressed bytes, over the "
            f"{max_total_bytes} cap — refusing to import a possible zip bomb"
        )


def import_bundle(
    attest_path: Path,
    private_path: Path | None = None,
    *,
    max_member_bytes: int = _MAX_MEMBER_BYTES,
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    max_entries: int = _MAX_ENTRIES,
) -> ImportedBundle:
    """Reconstruct receipts, a working `verify.TrustStore`, artifact
    manifests and legal texts from a `.attest` (and, if given, its
    `.private.attest` sibling for salts). Every issuer found in the bundle is
    trusted with provenance `"bundle"` — offline-imported manifests are
    unauthenticated TOFU by construction (design §5), never silently
    upgraded to `"verified"`.

    `max_member_bytes`, `max_total_bytes` and `max_entries` are keyword-only
    zip-bomb decompression caps (§2.1), each defaulting to its module
    constant: a per-member cap on bytes actually streamed out of one zip
    entry, an aggregate cap on the running total decompressed across every
    member read during this call (`.attest` and, when given, `.private.attest`
    share one budget), and a cap on the central directory's entry count.
    Exceeding any of them raises `BundleError` rather than importing a
    possible bomb.
    """
    receipts: list[dict[str, Any]] = []
    key_manifests_by_issuer: dict[str, list[dict[str, Any]]] = {}
    artifact_manifests: dict[str, list[dict[str, Any]]] = {}
    legal_texts: dict[str, bytes] = {}

    # One shared budget for the whole call (spec §2.1: the aggregate cap is a
    # running total of decompressed bytes across ALL members read during one
    # import_bundle call, not per-zip) — reused below for the .private.attest
    # salts read so a hostile .attest/.private.attest pair cannot each spend up
    # to max_total_bytes and together decompress 2x the aggregate ceiling.
    budget = _SizeBudget(max_member_bytes, max_total_bytes)

    with zipfile.ZipFile(attest_path, "r") as zf:
        _guard_zip(zf, max_entries, max_total_bytes)
        for filename in sorted(zf.namelist()):
            if filename.startswith("receipts/") and filename.endswith(".attest.json"):
                receipts.append(json.loads(budget.read(zf, filename)))
            elif filename.startswith("manifests/") and filename.endswith(".json"):
                blob = json.loads(budget.read(zf, filename))
                issuer = blob.get("issuer")
                if not isinstance(issuer, str):
                    continue
                key_manifests_by_issuer[issuer] = list(blob.get("key_manifests", []))
                for am in blob.get("artifact_manifests", []):
                    series = am.get("series")
                    if isinstance(series, str):
                        artifact_manifests.setdefault(series, []).append(am)
            elif filename.startswith("legal/") and filename.endswith(".txt"):
                digest = filename[len("legal/") : -len(".txt")]
                content = budget.read(zf, filename)
                if hashlib.sha256(content).hexdigest() != digest:
                    raise BundleError(
                        f"legal text {digest!r} failed its own integrity check on import "
                        "— bundle is corrupt or tampered"
                    )
                legal_texts[digest] = content

    manifests_map: dict[str, dict[str, Any]] = {}
    provenance: dict[str, str] = {}
    chains: dict[str, list[dict[str, Any]]] = {}
    for issuer, versions in key_manifests_by_issuer.items():
        if not versions:
            continue
        ordered = sorted(versions, key=lambda m: m.get("manifest_version", 0))
        manifests_map[issuer] = ordered[-1]
        provenance[issuer] = _PROVENANCE_BUNDLE
        chains[issuer] = ordered

    for series, versions in artifact_manifests.items():
        artifact_manifests[series] = sorted(versions, key=lambda m: m.get("version", 0))

    trust_store = verify.TrustStore(manifests=manifests_map, provenance=provenance, chains=chains)

    salts: dict[str, bytes] = {}
    if private_path is not None:
        with zipfile.ZipFile(private_path, "r") as zf:
            _guard_zip(zf, max_entries, max_total_bytes)
            if "salts.json" in zf.namelist():
                raw_salts: dict[str, str] = json.loads(budget.read(zf, "salts.json"))
                salts = {receipt_id: keys.b64u_decode(s) for receipt_id, s in raw_salts.items()}

    return ImportedBundle(
        receipts=receipts,
        trust_store=trust_store,
        artifact_manifests=artifact_manifests,
        legal_texts=legal_texts,
        salts=salts,
    )


def disclose(
    receipts: list[dict[str, Any]],
    key_manifests: list[dict[str, Any]],
    salts: dict[str, bytes],
    receipt_id: str,
    out: Path,
) -> Path:
    """Emit exactly one self-contained `.attest.json` for `receipt_id` (§9): its
    own salt (never the whole `salts` map) plus a key-manifest snapshot that
    still lists the kid that signed it, embedded in `delivery` so the file
    verifies standalone.

    `out` may be an existing directory (the file is written as
    `<receipt_id>.attest.json` inside it) or an exact destination path.
    """
    envelope = next(
        (e for e in receipts if e.get("payload", {}).get("receipt_id") == receipt_id), None
    )
    if envelope is None:
        raise BundleError(f"no receipt with receipt_id {receipt_id!r} to disclose")

    payload = envelope["payload"]
    issuer_id = payload["issuer"]["id"]
    kid = envelope["signatures"][0]["kid"]

    candidates = [
        m
        for m in key_manifests
        if m.get("issuer") == issuer_id and manifests.find_key(m, kid) is not None
    ]
    if not candidates:
        # Fail closed: a disclosure with no key manifest listing the signing
        # kid could never verify standalone, which defeats disclose's whole
        # purpose (§9: "one receipt + its manifests + its salt"). Every other
        # path in this module raises rather than emit a silently-degraded
        # artifact; this one does too.
        raise BundleError(
            f"no key manifest for signing kid {kid!r}; cannot produce a self-contained disclosure"
        )
    manifest_snapshot = max(candidates, key=lambda m: m.get("manifest_version", 0))

    delivery: dict[str, Any] = {"issuer_manifest": manifest_snapshot}
    if receipt_id in salts:
        delivery["salt"] = keys.b64u(salts[receipt_id])

    disclosed: dict[str, Any] = {"payload": payload, "signatures": envelope["signatures"]}
    if delivery:
        disclosed["delivery"] = delivery

    target = out / f"{receipt_id}.attest.json" if out.is_dir() else out
    _write_secret_json(target, disclosed)
    return target
