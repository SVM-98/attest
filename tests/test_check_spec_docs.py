"""Tests for the spec-docs drift-guard checker (tools/check_spec_docs.py).

Fixture-driven: each case builds minimal doc strings and asserts on
`collect_errors(...)`. Case 11 is the drift-guard proper: it reads the real
`docs/spec/*.md` files and the real schema and asserts a clean run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import check_spec_docs
from tools.check_spec_docs import REQUIRED_SECTIONS, collect_errors, main

REPO_ROOT = Path(__file__).resolve().parent.parent

# Buyer property set used by the minimal schema fixture and pinned by the
# minimal PC-01 row below -- kept in sync deliberately, the way the real
# schema and privacy doc are meant to stay in sync.
_BUYER_KEYS = ["commitment", "identifier_type", "pubkey"]
_BUYER_REQUIRED = ["commitment", "identifier_type"]
_BUYER_PATTERN = "^[A-Za-z0-9_-]{43}$"


def _minimal_schema(
    buyer_required: list[str] | None = None,
    commitment_pattern: str = _BUYER_PATTERN,
) -> dict[str, object]:
    if buyer_required is None:
        buyer_required = _BUYER_REQUIRED
    return {
        "properties": {
            "buyer": {
                "required": buyer_required,
                "properties": {
                    "commitment": {"type": "string", "pattern": commitment_pattern},
                    "identifier_type": {"enum": ["issuer-account", "email"]},
                    "pubkey": {"type": ["string", "null"], "pattern": _BUYER_PATTERN},
                },
            },
        },
    }


def _spec_text(version: str, sections: list[int]) -> str:
    """Build a minimal spec doc with one `## N. Title` heading per section."""
    lines = [f"# attest — v{version}", ""]
    for n in sections:
        lines.append(f"## {n}. Section {n}")
        lines.append("")
        lines.append(f"Body text for section {n}.")
        lines.append("")
    return "\n".join(lines)


def _minimal_spec_v01() -> str:
    return _spec_text("0.1", list(range(1, 16)))  # §1..§15


def _minimal_spec_v02() -> str:
    return _spec_text("0.2", list(range(1, 17)))  # §1..§16


def _tm_entry(tm_id: int, verdict_line: str) -> str:
    return (
        f"#### TM-{tm_id:02d} — Example attack\n\n"
        "- **Actor / precondition:** `network attacker` does something.\n"
        "- **Impact:** Something bad would happen.\n"
        f"{verdict_line}\n"
        "- **Residual risk:** None identified.\n\n"
    )


def _minimal_matrix_rows() -> str:
    rows = []
    for section in REQUIRED_SECTIONS:
        rows.append(f"| {section} — Example section | TM-01 |")
    return "\n".join(rows) + "\n"


def _minimal_threat_model(entries: str | None = None, matrix: str | None = None) -> str:
    if entries is None:
        entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example mechanism.")
    if matrix is None:
        matrix = _minimal_matrix_rows()
    return (
        "# attest — Threat Model\n\n"
        "## 1. Status and scope\n\nIntro.\n\n"
        "## 2. System model\n\nIntro.\n\n"
        "## 3. Attacker model\n\nIntro.\n\n"
        "## 4. Attack catalog\n\n"
        f"{entries}"
        "## 5. Traceability\n\n"
        "| Spec feature | TM entries |\n"
        "| --- | --- |\n"
        f"{matrix}"
    )


def _minimal_pc_row() -> str:
    keys = ", ".join(_BUYER_KEYS)
    return (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | schema | `properties.buyer.properties` "
        f"has key set exactly `{{{keys}}}` and `properties.buyer.required` equals "
        '`["commitment", "identifier_type"]`; `commitment` and `pubkey` are '
        "pattern-constrained to 43 base64url characters and `identifier_type` to the "
        'enum `["issuer-account", "email"]`. |'
    )


def _minimal_privacy(pc_rows: str | None = None) -> str:
    if pc_rows is None:
        pc_rows = _minimal_pc_row()
    return (
        "# attest — Privacy Considerations\n\n"
        "## 1. Status and scope\n\nIntro.\n\n"
        "## 7. Testable claims\n\n"
        "| ID | Claim | Check type | Check detail |\n"
        "| --- | --- | --- | --- |\n"
        f"{pc_rows}\n"
    )


def _base_docs() -> dict[str, object]:
    return {
        "threat_model": _minimal_threat_model(),
        "privacy": _minimal_privacy(),
        "spec_v01": _minimal_spec_v01(),
        "spec_v02": _minimal_spec_v02(),
        "schema": _minimal_schema(),
    }


def test_duplicate_tm_id_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.") + _tm_entry(
        1, "- **Verdict:** Mitigated — v0.1 §2.  Example."
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("duplicate" in e.lower() and "TM-01" in e for e in errors)


def test_gap_in_tm_sequence_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.") + _tm_entry(
        3, "- **Verdict:** Mitigated — v0.1 §2.  Example."
    )
    matrix = "\n".join(
        f"| {section} — Example section | TM-01, TM-03 |" for section in REQUIRED_SECTIONS
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries, matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("gap" in e.lower() or "missing" in e.lower() for e in errors)


def test_tm_ids_out_of_ascending_order_are_an_error() -> None:
    entries = (
        _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
        + _tm_entry(3, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
        + _tm_entry(2, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("ascending" in e.lower() and "TM-02" in e for e in errors)


def test_entry_missing_verdict_line_is_an_error() -> None:
    entry = (
        "#### TM-01 — Example attack\n\n"
        "- **Actor / precondition:** `network attacker` does something.\n"
        "- **Impact:** Something bad would happen.\n"
        "- **Residual risk:** None identified.\n\n"
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entry)

    errors = collect_errors(**docs)

    assert any("verdict" in e.lower() and "TM-01" in e for e in errors)


def test_verdict_line_not_matching_grammar_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Sort of mitigated, maybe.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("verdict" in e.lower() and "TM-01" in e for e in errors)


def test_dangling_spec_ref_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.2 §99.  Nonexistent section.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_dangling_spec_ref_after_and_is_an_error() -> None:
    entries = _tm_entry(
        1,
        "- **Verdict:** Mitigated — v0.2 §2 and §99.  Nonexistent section.",
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_matrix_row_citing_nonexistent_tm_is_an_error() -> None:
    matrix = "\n".join(
        f"| {section} — Example section | TM-01, TM-99 |" for section in REQUIRED_SECTIONS
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("TM-99" in e for e in errors)


def test_required_spec_section_absent_from_matrix_is_an_error() -> None:
    sections = [s for s in REQUIRED_SECTIONS if s != "v0.1 §2"]
    matrix = "\n".join(f"| {section} — Example section | TM-01 |" for section in sections)
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("v0.1 §2" in e for e in errors)


def test_matrix_row_without_tm_citation_does_not_cover_section() -> None:
    matrix = _minimal_matrix_rows().replace(
        "| v0.1 §2 — Example section | TM-01 |",
        "| v0.1 §2 — Example section | |",
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_matrix_rows_inside_a_fenced_block_do_not_cover_sections() -> None:
    # An illustrative table in a code fence is not the traceability matrix. If it
    # counted, the real matrix could be emptied without the guard noticing.
    fenced = "```text\n" + _minimal_matrix_rows() + "```\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_malformed_tm_citation_in_matrix_is_an_error() -> None:
    # An en dash instead of a hyphen: reads as a citation, matches nothing.
    matrix = _minimal_matrix_rows().replace(
        "| v0.1 §2 — Example section | TM-01 |",
        "| v0.1 §2 — Example section | TM–999 |",  # noqa: RUF001 - the en dash IS the defect
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix)

    errors = collect_errors(**docs)

    assert any("malformed TM citation" in e for e in errors)


def test_unsupported_spec_version_in_verdict_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.3 §999.  Nonexistent version.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("unsupported spec version v0.3" in e for e in errors)


def test_pc_row_with_invalid_check_type_is_an_error() -> None:
    pc_row = (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | not-a-real-check-type | some detail. |"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "check type" in e.lower() for e in errors)


def test_pc_01_pinned_buyer_set_diverging_from_schema_is_an_error() -> None:
    pc_row = (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | schema | `properties.buyer.properties` "
        "has key set exactly `{commitment, pubkey}`. |"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e for e in errors)


def test_pc_01_absent_from_privacy_doc_is_an_error() -> None:
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows="")

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "missing" in e.lower() for e in errors)


def test_pc_01_required_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(buyer_required=["commitment"])

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "required" in e.lower() for e in errors)


def test_pc_01_pattern_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(commitment_pattern="^[A-Za-z0-9_-]{42}$")

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "pattern" in e.lower() for e in errors)


def test_well_formed_fixtures_are_clean() -> None:
    docs = _base_docs()

    errors = collect_errors(**docs)

    assert errors == []


def test_real_repo_docs_are_clean() -> None:
    threat_model = (REPO_ROOT / "docs/spec/attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (REPO_ROOT / "docs/spec/attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (REPO_ROOT / "docs/spec/attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (REPO_ROOT / "docs/spec/attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (REPO_ROOT / "docs/spec/schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema)

    assert errors == []


def test_main_exits_zero_on_the_real_docs() -> None:
    # The CI gate is the process exit code, not the error list. Every other test
    # calls collect_errors directly, so main() could return 0 unconditionally and
    # they would all still pass.
    assert main() == 0


def test_main_exits_nonzero_when_a_document_drifts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    drifted = tmp_path / "attest-threat-model.md"
    drifted.write_text(_minimal_threat_model(matrix="| v0.1 §2 — Example | TM-99 |\n"), "utf-8")
    monkeypatch.setattr(check_spec_docs, "_THREAT_MODEL_PATH", drifted)
    monkeypatch.setattr(
        check_spec_docs, "_PRIVACY_PATH", _write(tmp_path, "p.md", _minimal_privacy())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SPEC_V01_PATH", _write(tmp_path, "v1.md", _minimal_spec_v01())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SPEC_V02_PATH", _write(tmp_path, "v2.md", _minimal_spec_v02())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SCHEMA_PATH", _write(tmp_path, "s.json", json.dumps(_minimal_schema()))
    )

    assert main() == 1


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path
