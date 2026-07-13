import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from tools.assert_artifacts import (
    ArtifactError,
    assert_npm_tarball,
    assert_sdist,
    assert_wheel,
)


def _make_wheel(tmp: Path, members: list[str]) -> Path:
    p = tmp / "attest_receipts-0.1.2-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        for m in members:
            z.writestr(m, b"x")
    return p


def _make_sdist(tmp: Path, members: list[str]) -> Path:
    p = tmp / "attest_receipts-0.1.2.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        for m in members:
            data = b"x"
            info = tarfile.TarInfo(name=m)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return p


WHEEL_OK = [
    "attest/__init__.py",
    "attest/py.typed",
    "attest/schema/attest-v0.1.schema.json",
    "attest_receipts-0.1.2.dist-info/METADATA",
    "attest_receipts-0.1.2.dist-info/licenses/LICENSE",
]
SDIST_OK = [
    "attest_receipts-0.1.2/pyproject.toml",
    "attest_receipts-0.1.2/src/attest/__init__.py",
    "attest_receipts-0.1.2/src/attest/py.typed",
    "attest_receipts-0.1.2/LICENSE",
]


def test_wheel_ok(tmp_path: Path) -> None:
    assert_wheel(_make_wheel(tmp_path, WHEEL_OK))  # no raise


def test_wheel_missing_py_typed_raises(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if m != "attest/py.typed"]
    with pytest.raises(ArtifactError, match=r"py\.typed"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_missing_schema_raises(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if "schema" not in m]
    with pytest.raises(ArtifactError, match="schema"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_sdist_ok(tmp_path: Path) -> None:
    assert_sdist(_make_sdist(tmp_path, SDIST_OK))  # no raise


def test_sdist_missing_license_raises(tmp_path: Path) -> None:
    members = [m for m in SDIST_OK if not m.endswith("LICENSE")]
    with pytest.raises(ArtifactError, match="LICENSE"):
        assert_sdist(_make_sdist(tmp_path, members))


def _pack(files: list[str]) -> list[dict]:
    return [{"files": [{"path": f} for f in files]}]


NPM_OK = ["dist/index.js", "dist/index.d.ts", "README.md", "CHANGELOG.md", "package.json"]


def test_npm_ok() -> None:
    assert_npm_tarball(_pack(NPM_OK))  # no raise


def test_npm_missing_changelog_raises() -> None:
    with pytest.raises(ArtifactError, match=r"CHANGELOG\.md"):
        assert_npm_tarball(_pack([f for f in NPM_OK if f != "CHANGELOG.md"]))


def test_npm_forbidden_private_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "example.private.attest"]))


def test_npm_forbidden_src_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "src/verify.ts"]))
