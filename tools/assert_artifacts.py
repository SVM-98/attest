"""Assert that built distribution artifacts contain exactly what we intend to
ship. Run in CI (and locally) after building the Python wheel/sdist and after
`npm pack`, to catch packaging regressions (missing py.typed, dropped schema
resource, leaked private/source files) before publishing."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any


class ArtifactError(Exception):
    """A built artifact is missing a required member or contains a forbidden one."""


# Substrings/suffixes that MUST be present in the wheel.
_WHEEL_REQUIRED = (
    "attest/__init__.py",
    "attest/py.typed",
    ".schema.json",  # bundled JSON schema resource
)
_WHEEL_REQUIRED_LICENSE = "LICENSE"  # somewhere under dist-info (hatchling places it in licenses/)

_SDIST_REQUIRED = (
    "pyproject.toml",
    "src/attest/__init__.py",
    "src/attest/py.typed",
)
_SDIST_REQUIRED_LICENSE = "LICENSE"

_NPM_REQUIRED = ("dist/", "README.md", "CHANGELOG.md", "package.json")
# Regexes for members that must NEVER ship in the npm tarball.
_NPM_FORBIDDEN = (
    re.compile(r"\.private"),
    re.compile(r"(^|/)src/"),
    re.compile(r"(^|/)test/"),
    re.compile(r"tsconfig"),
)


def _require(members: list[str], needle: str, kind: str) -> None:
    if not any(needle in m for m in members):
        raise ArtifactError(f"{kind}: required member matching {needle!r} not found")


def assert_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as z:
        members = z.namelist()
    for needle in _WHEEL_REQUIRED:
        _require(members, needle, "wheel")
    _require(members, _WHEEL_REQUIRED_LICENSE, "wheel")


def assert_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as t:
        members = t.getnames()
    for needle in _SDIST_REQUIRED:
        _require(members, needle, "sdist")
    _require(members, _SDIST_REQUIRED_LICENSE, "sdist")


def assert_npm_tarball(pack_json: list[dict[str, Any]]) -> None:
    if not pack_json:
        raise ArtifactError("npm: empty `npm pack --json` output")
    files = [f["path"] for f in pack_json[0].get("files", [])]
    for needle in _NPM_REQUIRED:
        _require(files, needle, "npm")
    for f in files:
        for pat in _NPM_FORBIDDEN:
            if pat.search(f):
                raise ArtifactError(f"npm: forbidden member shipped: {f!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert built artifact contents.")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--npm-pack-json", type=Path, help="file with `npm pack --json` output")
    args = parser.parse_args(argv)
    try:
        if args.wheel:
            assert_wheel(args.wheel)
        if args.sdist:
            assert_sdist(args.sdist)
        if args.npm_pack_json:
            assert_npm_tarball(json.loads(args.npm_pack_json.read_text()))
    except ArtifactError as exc:
        print(f"artifact assertion failed: {exc}", file=sys.stderr)
        return 1
    print("artifact assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
