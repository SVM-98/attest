"""The committed web-verifier sample bundle must be regenerable and genuine.

Loads tools/gen_site_sample.py by file path (tools/ is not a package) and
checks that a fresh generation produces a bundle that imports, verifies ok
at TOFU trust, proves its binding with the sidecar salt, and never leaks a
.private.attest into the output directory.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_generator() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "tools" / "gen_site_sample.py"
    spec = importlib.util.spec_from_file_location("gen_site_sample", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_produces_verifiable_sample(tmp_path: Path) -> None:
    gen = _load_generator()
    report = gen.main(tmp_path)

    attest_path = Path(report["attest"])
    binding_path = Path(report["binding"])
    assert attest_path.name == "demo.attest" and attest_path.is_file()
    assert binding_path.name == "demo-binding.json" and binding_path.is_file()

    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    assert binding["identifier_type"] == "email"
    assert len(binding["salt_b64u"]) == 22  # 16 raw bytes, base64url unpadded

    check = report["self_check"]
    assert check["verify"]["ok"] is True
    assert check["verify"]["trust"] == "unauthenticated_tofu"
    assert check["verify_with_disclosure"]["binding"] == "proven"

    # The secrets file must never land in the published output directory.
    assert not list(tmp_path.glob("*.private.attest"))
