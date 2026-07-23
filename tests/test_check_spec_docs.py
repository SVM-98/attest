"""Tests for the spec-docs drift-guard checker (tools/check_spec_docs.py).

Fixture-driven: each case builds minimal doc strings and asserts on
`collect_errors(...)`. Case 11 is the drift-guard proper: it reads the real
`docs/spec/*.md` files and the real schema and asserts a clean run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tools import check_spec_docs
from tools.check_spec_docs import REQUIRED_SECTIONS, collect_errors, main

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "docs/spec"

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
    return (
        _spec_text("0.1", list(range(1, 16)))  # §1..§15
        + "### 5.5 `license`\n\n"
        + "| `not_transferable_before` | string, ISO-8601 UTC | OPTIONAL | Reserved. |\n"
    )


def _minimal_spec_v02() -> str:
    return (
        _spec_text("0.2", list(range(1, 17)))  # §1..§16
        + "## 17. Stage 3: issuer-mediated transfer\n\n"
        + "`Attest-transfer-authorization-v1` `transfer-record` "
        + "`transferred_revocation_unbacked` `transfer_record_unlogged` "
        + "`transfer_not_yet_transferable` `transfer_double_assignment_conflict` "
        + '`revocation: "transferred"`\n'
    )


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


def _minimal_versioning() -> str:
    """A minimal attest-versioning.md fixture carrying every checked property."""
    return (
        "# attest-versioning — Normative Upgrade Policy\n\n"
        "## 1. Scope and authority\n\nIntro.\n\n"
        "## 2. The additive pattern\n\n"
        "One exception exists: a result-classification downgrade mandated by an algorithm "
        "lifecycle transition (§4) is NOT a breaking change and does not require a new "
        "`attest_version`. A lifecycle transition records newly established cryptanalytic "
        "reality about an algorithm; the protocol semantics are unchanged, and eternal "
        "verifiability (§3) is preserved because the artifact remains verifiable — the result "
        "simply reports what its signature is worth today.\n\n"
        "## 3. Eternal verifiability\n\nIntro.\n\n"
        "## 4. Algorithm lifecycle\n\n"
        "| State | Issue | Verify | Verifier obligation |\n"
        "| --- | --- | --- | --- |\n"
        "| `active` | MAY issue | MUST verify | No downgrade. |\n"
        "| `deprecated` | MUST NOT issue | MUST verify | SHOULD warn. |\n"
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n\n"
        "## 5. Amendment procedure\n\nIntro.\n\n"
        "## 6. Registries\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `ed25519` | active | v0.1 | v0.1 §10 |\n"
        "| `ed25519+ml-dsa-65` | active | v0.2 | v0.2 §2 |\n"
        "\n"
        "### 6.3 Revocation classes\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `none` | active | v0.1 | v0.1 §5.5 |\n"
        "| `refund_window` | active | v0.1 | v0.1 §5.5 |\n"
        "| `policy` | active | v0.1 | v0.1 §5.5 |\n"
        "| `transferred` | active | v0.2 §17 | v0.2 §17.3 |\n"
        "\n"
        "### 6.4 Log entry types\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `transfer-record` | active | v0.2 §17 | v0.2 §8, §17.2 |\n"
        "\n"
        "### 6.5 Transfer types\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `issuer-mediated-v1` | active | v0.2 §17 | v0.2 §17 |\n"
        "\n"
        "## Revision log\n\n"
        "- **2026-07-22 (rev 1)**: document introduced — vectors: none\n"
    )


def _base_docs() -> dict[str, object]:
    return {
        "threat_model": _minimal_threat_model(),
        "privacy": _minimal_privacy(),
        "spec_v01": _minimal_spec_v01()
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n",
        "spec_v02": _minimal_spec_v02()
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n",
        "schema": _minimal_schema(),
        "versioning": _minimal_versioning(),
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


def test_tilde_fenced_matrix_rows_do_not_cover_sections() -> None:
    fenced = "~~~text\n" + _minimal_matrix_rows() + "~~~\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_indented_fenced_matrix_rows_do_not_cover_sections() -> None:
    # Up to three leading spaces still opens a fence in CommonMark.
    fenced = "   ```text\n" + _minimal_matrix_rows() + "   ```\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_dangling_spec_ref_after_oxford_comma_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.2 §2, §3, and §99.  Nonexistent.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_non_spec_version_token_is_not_flagged() -> None:
    # A version that is not a spec citation is ordinary prose. Flagging it would
    # fail a legitimate edit, which is worse than the gap it would close.
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Delivery over TLS v1.3.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert not any("unsupported spec version" in e for e in errors)


def test_pc_01_pattern_pin_naming_the_wrong_fields_is_an_error() -> None:
    pc_row = _minimal_pc_row().replace(
        "`commitment` and `pubkey` are", "`commitment` and `commitment` are"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "pubkey" in e for e in errors)


def test_pc_01_identifier_type_enum_drift_is_an_error() -> None:
    schema = _minimal_schema()
    buyer = schema["properties"]["buyer"]  # type: ignore[index]
    buyer["properties"]["identifier_type"] = {"type": "string"}  # type: ignore[index]
    docs = _base_docs()
    docs["schema"] = schema

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "identifier_type" in e for e in errors)


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


def test_pc_08_corpus_pin_includes_json_parsed_chain_payloads() -> None:
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    rows = check_spec_docs.parse_pc_rows(privacy)

    assert check_spec_docs.check_pc08_corpus_claim(rows, SPEC_DIR / "vectors") == []

    drifted_privacy = privacy.replace("166 payload objects", "165 payload objects")
    drifted_rows = check_spec_docs.parse_pc_rows(drifted_privacy)
    errors = check_spec_docs.check_pc08_corpus_claim(drifted_rows, SPEC_DIR / "vectors")

    assert any("PC-08" in error and "count" in error for error in errors)


def test_pc_01_required_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(buyer_required=["commitment"])

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "required" in e.lower() for e in errors)


def test_pc_01_pattern_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(commitment_pattern="^[A-Za-z0-9_-]{42}$")

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "commitment" in e for e in errors)


def test_pc_01_pattern_pin_diverging_on_the_pubkey_leg_is_an_error() -> None:
    # Drifting only the second field: a checker that validated the first name it
    # captured and stopped would pass this.
    schema = _minimal_schema()
    buyer = schema["properties"]["buyer"]  # type: ignore[index]
    buyer["properties"]["pubkey"]["pattern"] = "^[A-Za-z0-9_-]{42}$"  # type: ignore[index]
    docs = _base_docs()
    docs["schema"] = schema

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "pubkey" in e for e in errors)


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
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, versioning)

    assert errors == []


def test_v02_stage3_section_removal_is_flagged_by_collect_errors() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    spec_v02_without_stage3 = re.sub(
        r"^## 17\. Stage 3: issuer-mediated transfer.*?(?=^## Revision log$)",
        "",
        spec_v02,
        flags=re.MULTILINE | re.DOTALL,
    )

    errors = collect_errors(
        threat_model, privacy, spec_v01, spec_v02_without_stage3, schema, versioning
    )

    assert errors


def test_v01_not_transferable_before_row_removal_is_flagged_by_collect_errors() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    spec_v01_without_transfer_floor = re.sub(
        r"^\| `not_transferable_before` \|.*\n",
        "",
        spec_v01,
        flags=re.MULTILINE,
    )

    errors = collect_errors(
        threat_model, privacy, spec_v01_without_transfer_floor, spec_v02, schema, versioning
    )

    assert errors


def test_versioning_transfer_rows_swapped_between_registries_are_flagged() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    swapped_versioning = (
        versioning.replace("`transfer-record`", "`temporary-transfer-row`")
        .replace("`issuer-mediated-v1`", "`transfer-record`")
        .replace("`temporary-transfer-row`", "`issuer-mediated-v1`")
    )

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, swapped_versioning)

    assert errors


def test_versioning_transferred_row_moved_out_of_section_6_3_is_flagged() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    lines = versioning.splitlines(keepends=True)
    row_idx = next(
        i for i, line in enumerate(lines) if line.startswith("| `transferred` | active |")
    )
    row = lines.pop(row_idx)
    anchor_idx = next(
        i for i, line in enumerate(lines) if line.startswith("| `issuer-mediated-v1` | active |")
    )
    lines.insert(anchor_idx + 1, row)
    moved_versioning = "".join(lines)

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, moved_versioning)

    assert errors


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
    monkeypatch.setattr(
        check_spec_docs,
        "_VERSIONING_PATH",
        _write(tmp_path, "versioning.md", _minimal_versioning()),
    )

    assert main() == 1


class TestStage3Transfer:
    def test_v02_has_stage3_sections(self) -> None:
        text = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
        for needle in (
            "## 17. Stage 3: issuer-mediated transfer",
            "`Attest-transfer-authorization-v1`",
            "`transfer-record`",
            "`transferred_revocation_unbacked`",
            "`transfer_record_unlogged`",
            "`transfer_not_yet_transferable`",
            "`transfer_double_assignment_conflict`",
            '`revocation: "transferred"`',
        ):
            assert needle in text

    def test_registry_transferred_is_active(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert "| `transferred` | active" in text
        assert "| `transfer-record` | active" in text
        assert "`issuer-mediated-v1`" in text

    def test_v01_registers_not_transferable_before(self) -> None:
        text = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
        assert "`not_transferable_before`" in text


class TestVersioningDoc:
    def test_versioning_doc_exists_and_has_required_sections(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_sections(text) == []

    def test_both_specs_have_revision_log(self) -> None:
        for name in ("attest-v0.1.md", "attest-v0.2.md"):
            text = (SPEC_DIR / name).read_text(encoding="utf-8")
            assert not check_spec_docs.check_revision_logs(text, text)

    def test_registry_suite_names_match_specs(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_suite_names(text) == []

    def test_lifecycle_states_are_exactly_three(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_lifecycle_states(text) == []


def test_versioning_doc_missing_heading_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace("## 4. Algorithm lifecycle\n\n", "")

    errors = collect_errors(**docs)

    assert any("4. Algorithm lifecycle" in e for e in errors)


def test_versioning_doc_demoted_heading_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "## 4. Algorithm lifecycle", "### 4. Algorithm lifecycle"
    )

    errors = collect_errors(**docs)

    assert any("4. Algorithm lifecycle" in e for e in errors)


def test_versioning_doc_missing_lifecycle_state_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n",
        "",
    )

    errors = collect_errors(**docs)

    assert any("unsafe" in e for e in errors)


def test_versioning_doc_extra_lifecycle_state_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n",
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n"
        "| `frozen` | MUST NOT issue | MUST NOT verify | Reject. |\n",
    )

    errors = collect_errors(**docs)

    assert any("frozen" in e or "exactly" in e for e in errors)


def test_versioning_doc_missing_suite_name_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `ed25519` | active | v0.1 | v0.1 §10 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("ed25519" in e for e in errors)


def test_versioning_doc_missing_policy_revocation_row_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `policy` | active | v0.1 | v0.1 §5.5 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("policy" in e for e in errors)


def test_versioning_doc_transferred_row_not_active_is_flagged() -> None:
    # A regression back to `reserved` (or any state other than `active`) must
    # be caught -- mere row presence is not enough for this specific class,
    # since v0.2 §17 (rev 6) activation is exactly the fact worth guarding.
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `transferred` | active | v0.2 §17 | v0.2 §17.3 |\n",
        "| `transferred` | reserved | — | Future transfer profile |\n",
    )

    errors = collect_errors(**docs)

    assert any("transferred" in e and "active" in e for e in errors)


def test_versioning_doc_transfer_record_row_not_active_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `transfer-record` | active | v0.2 §17 | v0.2 §8, §17.2 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("transfer-record" in e and "active" in e for e in errors)


def test_versioning_doc_issuer_mediated_v1_row_not_active_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `issuer-mediated-v1` | active | v0.2 §17 | v0.2 §17 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("issuer-mediated-v1" in e and "active" in e for e in errors)


def test_versioning_doc_missing_lifecycle_exception_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "One exception exists:", "The exception exists:"
    )

    errors = collect_errors(**docs)

    assert any("One exception exists:" in e for e in errors)


def test_versioning_doc_missing_revision_log_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "\n## Revision log\n\n- **2026-07-22 (rev 1)**: document introduced — vectors: none\n",
        "",
    )

    errors = collect_errors(**docs)

    assert any("attest-versioning.md" in e and "Revision log" in e for e in errors)


def test_missing_revision_log_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01()  # no '## Revision log' section

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "Revision log" in e for e in errors)


def test_revision_log_requires_a_grammar_valid_entry() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01() + "\n## Revision log\n\nIntro.\n"

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "revision-log entry" in e for e in errors)


def test_revision_log_malformed_entry_is_flagged_with_its_line() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01() + (
        "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision; vectors: none\n"
    )

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "line" in e and "revision-log entry" in e for e in errors)


# --- receipt_id §5.1 prose <-> schema.receipt_id.pattern drift guard ---------


def _spec_v01_with_receipt_id_row(prose_pattern: str) -> str:
    """A minimal §5.1 receipt_id table row, injected into a v0.1 fixture doc."""
    base = _minimal_spec_v01()
    row = f"\n\n| `receipt_id` | string, ULID (`{prose_pattern}`) | REQUIRED | ULID. |\n"
    return base + row


def test_receipt_id_prose_pattern_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row("^[0-9A-HJKMNP-TV-Z]{26}$")
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {
        "type": "string",
        "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
    }

    errors = collect_errors(**docs)

    assert any("receipt_id" in e and "diverges from" in e and "attest-v0.1.md" in e for e in errors)


def test_receipt_id_prose_pattern_matching_schema_is_clean() -> None:
    docs = _base_docs()
    pattern = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row(pattern)
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {"type": "string", "pattern": pattern}

    errors = collect_errors(**docs)

    assert not any("receipt_id" in e and "diverges from" in e for e in errors)


def test_receipt_id_row_absent_from_fixture_does_not_error() -> None:
    """Fixture docs where NEITHER side models `receipt_id` at all (the
    common case for every other test in this file, via `_base_docs()`/
    `_minimal_schema()`) are not a drift signal and must not be flagged —
    the check only skips when both sides are simultaneously absent; a
    one-sided absence (M2, 2026-07-22 fix wave 2) is fail-closed instead,
    see `test_receipt_id_schema_pattern_absent_while_prose_present_is_an_error`
    and `test_receipt_id_prose_row_absent_while_schema_pattern_present_is_an_error`."""
    docs = _base_docs()

    errors = collect_errors(**docs)

    assert not any("receipt_id" in e for e in errors)


def test_receipt_id_schema_pattern_absent_while_prose_present_is_an_error() -> None:
    """M2 (2026-07-22 fix wave 2): §5.1 carries a receipt_id ULID prose
    pattern, but the schema has no `properties.receipt_id.pattern` at all —
    previously this fell through the old code's early `if schema_pattern is
    None: return []`, fail-open. Must now be an explicit, fail-closed error."""
    docs = _base_docs()
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row("^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()  # no receipt_id property at all

    errors = collect_errors(**docs)

    assert any(
        "receipt_id" in e and "attest-v0.1.md" in e and "schema" in e.lower() for e in errors
    )


def test_receipt_id_prose_row_absent_while_schema_pattern_present_is_an_error() -> None:
    """M2 companion: the schema defines `receipt_id.pattern`, but §5.1 carries
    no receipt_id prose row at all — previously this fell through the old
    code's early `if match is None: return []`, fail-open. Must now be an
    explicit, fail-closed error."""
    docs = _base_docs()  # spec_v01 has no §5.1 receipt_id row
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {
        "type": "string",
        "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
    }

    errors = collect_errors(**docs)

    assert any("receipt_id" in e and "attest-v0.1.md" in e and "prose" in e.lower() for e in errors)


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path
