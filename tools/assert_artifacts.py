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
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any


class ArtifactError(Exception):
    """A built artifact is missing a required member or contains a forbidden one."""


# Exact-path needles: a member must equal the needle, or end with "/" + needle
# (i.e. the needle is the member's full path relative to some archive root).
# A raw substring match (the previous behaviour) would let lookalikes such as
# "attest/py.typed.old" or "backup/attest/py.typed" satisfy the requirement.
_WHEEL_REQUIRED_EXACT = (
    "attest/__init__.py",
    "attest/py.typed",
    # The exact bundled JSON schema resource loaded at runtime via
    # importlib.resources.files("attest.schema").joinpath(...) in
    # src/attest/validate.py -- a generic "*.schema.json" match would let an
    # unrelated/renamed schema satisfy this requirement.
    "attest/schema/attest-receipt.schema.json",
)
# hatchling places the license at "<dist-info>/licenses/LICENSE" in the wheel.
_LICENSE_BASENAME = "LICENSE"

_SDIST_REQUIRED_EXACT = (
    "pyproject.toml",
    "src/attest/__init__.py",
    "src/attest/py.typed",
)
# hatchling places the license at "<sdist-root>/LICENSE" in the sdist.

# Exact-path needles: npm pack paths are package-root-relative with no
# variable prefix, so an exact match (not suffix match) is required --
# "nested/dist/index.js" must NOT satisfy "dist/index.js" when the real
# top-level "dist/index.js" is absent. "dist/index.js" and "dist/index.d.ts"
# are the real entrypoints declared as "main"/"types" in
# verifiers/ts/package.json.
_NPM_REQUIRED_EXACT = (
    "README.md",
    "CHANGELOG.md",
    "package.json",
    "dist/index.js",
    "dist/index.d.ts",
)
# Regexes for members that must NEVER ship in the npm tarball. Anchored on
# path-component / filename boundaries (not raw substrings) and
# case-insensitive, so lookalikes (e.g. "api.privateer.md",
# "docs/tsconfig-guide.md") don't false-positive while real leaks
# (e.g. "secret.PRIVATE.attest", "Src/verify.ts", "tests/verify.ts") are
# still caught.
_NPM_FORBIDDEN = (
    re.compile(r"(?:^|[./])private(?:[./]|$)", re.IGNORECASE),
    re.compile(r"(^|/)(src|tests?)/", re.IGNORECASE),
    re.compile(r"(^|/)tsconfig(\.[^/]*)?$", re.IGNORECASE),
)


def _require_member(
    members: list[str], predicate: Callable[[str], bool], description: str, kind: str
) -> None:
    if not any(predicate(m) for m in members):
        raise ArtifactError(f"{kind}: required member matching {description!r} not found")


def _is_exact_or_suffix(needle: str) -> Callable[[str], bool]:
    """Member equals `needle`, or ends with `/needle` (i.e. needle is the
    member's full path under some archive root).

    Only appropriate for archives with a variable root prefix (the sdist's
    "<name-version>/" directory). For archives whose real paths are
    deterministic and root-relative (wheel, npm pack), use `_is_exact`
    instead -- suffix matching would let a nested lookalike (e.g.
    "nested/dist/index.js") satisfy a requirement even when the real
    top-level path is absent."""

    def predicate(member: str) -> bool:
        return member == needle or member.endswith("/" + needle)

    return predicate


def _is_exact(needle: str) -> Callable[[str], bool]:
    """Member equals `needle` exactly."""

    def predicate(member: str) -> bool:
        return member == needle

    return predicate


def _basename_equals(name: str) -> Callable[[str], bool]:
    def predicate(member: str) -> bool:
        return PurePosixPath(member).name == name

    return predicate


def assert_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as z:
        members = z.namelist()
    for needle in _WHEEL_REQUIRED_EXACT:
        _require_member(members, _is_exact(needle), needle, "wheel")
    _require_member(members, _basename_equals(_LICENSE_BASENAME), _LICENSE_BASENAME, "wheel")


def assert_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as t:
        members = t.getnames()
    for needle in _SDIST_REQUIRED_EXACT:
        _require_member(members, _is_exact_or_suffix(needle), needle, "sdist")
    _require_member(members, _basename_equals(_LICENSE_BASENAME), _LICENSE_BASENAME, "sdist")


def assert_npm_tarball(pack_json: list[dict[str, Any]]) -> None:
    if not pack_json:
        raise ArtifactError("npm: empty `npm pack --json` output")
    files = [f["path"] for f in pack_json[0].get("files", [])]
    for needle in _NPM_REQUIRED_EXACT:
        _require_member(files, _is_exact(needle), needle, "npm")
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
    if not (args.wheel or args.sdist or args.npm_pack_json):
        print(
            "artifact assertion failed: no target given "
            "(pass --wheel, --sdist, and/or --npm-pack-json)",
            file=sys.stderr,
        )
        return 2
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
