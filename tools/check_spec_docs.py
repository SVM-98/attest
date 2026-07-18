"""Drift guard for the threat-model and privacy companion documents.

Cross-checks `docs/spec/attest-threat-model.md` and `docs/spec/attest-privacy.md`
against each other, against `docs/spec/attest-v0.1.md` / `attest-v0.2.md`, and
against the receipt schema: TM-id sequence and uniqueness, the verdict-line
grammar, spec-reference resolution inside verdict lines, traceability-matrix
coverage and TM citations, the PC testable-claims check-type vocabulary, and
the PC-01 buyer-field pin against the schema. Stdlib only; run standalone via
`uv run python tools/check_spec_docs.py` (also wired into CI).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_THREAT_MODEL_PATH = _REPO_ROOT / "docs/spec/attest-threat-model.md"
_PRIVACY_PATH = _REPO_ROOT / "docs/spec/attest-privacy.md"
_SPEC_V01_PATH = _REPO_ROOT / "docs/spec/attest-v0.1.md"
_SPEC_V02_PATH = _REPO_ROOT / "docs/spec/attest-v0.2.md"
_SCHEMA_PATH = _REPO_ROOT / "docs/spec/schema/attest-receipt.schema.json"

# Required traceability-matrix coverage: every numbered section of the two
# normative specs except each document's own §1 (conformance language) and
# v0.2 §5 (a worked example carrying no mechanism of its own).
REQUIRED_SECTIONS: tuple[str, ...] = tuple(f"v0.1 §{n}" for n in range(2, 16)) + tuple(
    f"v0.2 §{n}" for n in range(2, 17) if n != 5
)

_VALID_CHECK_TYPES = frozenset({"schema", "corpus", "spec-text", "manual"})

_TOP_HEADING_RE = re.compile(r"^## (\d+)\.\s")
_SUB_HEADING_RE = re.compile(r"^### (\d+\.\d+)\s")
_TM_HEADING_RE = re.compile(r"^#### TM-(\d+)\b.*$", re.MULTILINE)
_VERDICT_LINE_RE = re.compile(r"^- \*\*Verdict:\*\*.*$", re.MULTILINE)
_VERDICT_GRAMMAR_RE = re.compile(r"^- \*\*Verdict:\*\* (Mitigated|Out of scope) — .+$")
_REF_GROUP_RE = re.compile(r"(v0\.[12]) (§\d+(?:\.\d+)?(?:[,;]\s*§\d+(?:\.\d+)?)*)")
_REF_SECTION_RE = re.compile(r"§\d+(?:\.\d+)?")
_MATRIX_ROW_RE = re.compile(r"^\| (v0\.[12]) §(\d+) — [^|]*\|([^|]*)\|\s*$", re.MULTILINE)
_MATRIX_TM_REF_RE = re.compile(r"TM-(\d+)")
_PC_ROW_RE = re.compile(r"^\| PC-(\d+) \| ([^|]*) \| ([^|]*) \| ([^|]*) \|\s*$", re.MULTILINE)
_PC01_PIN_RE = re.compile(r"key set exactly `?\{([^}]*)\}")


class TmEntry(NamedTuple):
    """One `#### TM-nn` attack-catalog entry and its raw block text."""

    tm_id: int
    block: str


class PcRow(NamedTuple):
    """One row of the privacy doc's `## 7. Testable claims` table."""

    pc_id: int
    claim: str
    check_type: str
    detail: str


def parse_headings(spec_text: str) -> set[str]:
    """Map `## N.` and `### N.M` headings to `§N` / `§N.M`."""
    headings: set[str] = set()
    for line in spec_text.splitlines():
        top = _TOP_HEADING_RE.match(line)
        if top is not None:
            headings.add(f"§{top.group(1)}")
            continue
        sub = _SUB_HEADING_RE.match(line)
        if sub is not None:
            headings.add(f"§{sub.group(1)}")
    return headings


def _parse_tm_entries(threat_model: str) -> list[TmEntry]:
    matches = list(_TM_HEADING_RE.finditer(threat_model))
    entries: list[TmEntry] = []
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(threat_model)
        entries.append(TmEntry(tm_id=int(match.group(1)), block=threat_model[start:end]))
    return entries


def parse_tm_ids(threat_model: str) -> list[int]:
    """Every `#### TM-nn` id, in document order (duplicates preserved)."""
    return [entry.tm_id for entry in _parse_tm_entries(threat_model)]


def parse_pc_rows(privacy: str) -> list[PcRow]:
    """Every row of the `## 7. Testable claims` table, in document order."""
    rows: list[PcRow] = []
    for match in _PC_ROW_RE.finditer(privacy):
        rows.append(
            PcRow(
                pc_id=int(match.group(1)),
                claim=match.group(2).strip(),
                check_type=match.group(3).strip(),
                detail=match.group(4).strip(),
            )
        )
    return rows


def check_ids(tm_ids: list[int]) -> list[str]:
    """Duplicate ids, and gaps in the contiguous-ascending-from-01 sequence."""
    errors: list[str] = []
    seen: set[int] = set()
    duplicates: set[int] = set()
    for tm_id in tm_ids:
        if tm_id in seen:
            duplicates.add(tm_id)
        seen.add(tm_id)
    for tm_id in sorted(duplicates):
        errors.append(f"duplicate TM id TM-{tm_id:02d}")

    if seen:
        missing = sorted(set(range(1, max(seen) + 1)) - seen)
        for tm_id in missing:
            errors.append(f"gap in TM sequence: TM-{tm_id:02d} is missing")

    return errors


def check_verdicts(tm_entries: list[TmEntry]) -> list[str]:
    """Exactly one Verdict line per entry, matching the grammar."""
    errors: list[str] = []
    for entry in tm_entries:
        label = f"TM-{entry.tm_id:02d}"
        lines = _VERDICT_LINE_RE.findall(entry.block)
        if len(lines) != 1:
            errors.append(f"{label}: expected exactly one Verdict line, found {len(lines)}")
            continue
        if not _VERDICT_GRAMMAR_RE.match(lines[0]):
            errors.append(
                f"{label}: Verdict line does not match 'Mitigated — …' or 'Out of scope — …'"
            )
    return errors


def check_spec_refs(
    tm_entries: list[TmEntry], headings_v01: set[str], headings_v02: set[str]
) -> list[str]:
    """Every spec ref in a well-formed Verdict line resolves to a real heading."""
    errors: list[str] = []
    for entry in tm_entries:
        label = f"TM-{entry.tm_id:02d}"
        lines = _VERDICT_LINE_RE.findall(entry.block)
        if len(lines) != 1 or not _VERDICT_GRAMMAR_RE.match(lines[0]):
            continue  # already reported by check_verdicts
        verdict_line = lines[0]
        for group_match in _REF_GROUP_RE.finditer(verdict_line):
            version, group_text = group_match.group(1), group_match.group(2)
            headings = headings_v01 if version == "v0.1" else headings_v02
            for section in _REF_SECTION_RE.findall(group_text):
                if section not in headings:
                    errors.append(f"{label}: dangling spec ref {version} {section}")
    return errors


def check_matrix(threat_model: str, tm_ids: set[int]) -> list[str]:
    """Every required section is covered, and every cited TM id is real."""
    errors: list[str] = []
    covered_sections: set[str] = set()
    for match in _MATRIX_ROW_RE.finditer(threat_model):
        version, number, row_rest = match.group(1), match.group(2), match.group(3)
        covered_sections.add(f"{version} §{number}")
        for tm_ref in _MATRIX_TM_REF_RE.finditer(row_rest):
            cited = int(tm_ref.group(1))
            if cited not in tm_ids:
                errors.append(
                    f"traceability matrix cites unknown TM-{cited:02d} (row {version} §{number})"
                )

    for section in REQUIRED_SECTIONS:
        if section not in covered_sections:
            errors.append(f"required section {section} missing from traceability matrix")

    return errors


def check_claims(pc_rows: list[PcRow]) -> list[str]:
    """Every PC row's check type is one of schema|corpus|spec-text|manual."""
    errors: list[str] = []
    for row in pc_rows:
        if row.check_type not in _VALID_CHECK_TYPES:
            errors.append(
                f"PC-{row.pc_id:02d}: check type {row.check_type!r} is not one of "
                f"{sorted(_VALID_CHECK_TYPES)}"
            )
    return errors


def check_schema_pins(pc_rows: list[PcRow], schema: dict[str, object]) -> list[str]:
    """PC-01's pinned buyer-property set matches the schema's actual set."""
    errors: list[str] = []
    pc01_rows = [row for row in pc_rows if row.pc_id == 1]
    if not pc01_rows:
        return errors  # absence is reported elsewhere (no PC-01 row at all)

    properties = schema.get("properties")
    buyer = properties.get("buyer") if isinstance(properties, dict) else None
    buyer_properties = buyer.get("properties") if isinstance(buyer, dict) else None
    actual = sorted(buyer_properties) if isinstance(buyer_properties, dict) else []

    for row in pc01_rows:
        pin_match = _PC01_PIN_RE.search(row.detail)
        if pin_match is None:
            errors.append("PC-01: no 'key set exactly {...}' pin found in check detail")
            continue
        pinned = sorted(name.strip() for name in pin_match.group(1).split(","))
        if pinned != actual:
            errors.append(
                f"PC-01: pinned buyer-property set {pinned} diverges from "
                f"schema's actual set {actual}"
            )

    return errors


def collect_errors(
    threat_model: str,
    privacy: str,
    spec_v01: str,
    spec_v02: str,
    schema: dict[str, object],
) -> list[str]:
    """Cross-check the two companion docs against each other and the specs.

    Returns one human-readable string per problem found; an empty list means
    the documents are internally consistent and in sync with the specs and
    schema they cite.
    """
    headings_v01 = parse_headings(spec_v01)
    headings_v02 = parse_headings(spec_v02)
    tm_entries = _parse_tm_entries(threat_model)
    tm_ids = [entry.tm_id for entry in tm_entries]
    pc_rows = parse_pc_rows(privacy)

    errors: list[str] = []
    errors += [f"attest-threat-model.md: {e}" for e in check_ids(tm_ids)]
    errors += [f"attest-threat-model.md: {e}" for e in check_verdicts(tm_entries)]
    errors += [
        f"attest-threat-model.md: {e}"
        for e in check_spec_refs(tm_entries, headings_v01, headings_v02)
    ]
    errors += [f"attest-threat-model.md: {e}" for e in check_matrix(threat_model, set(tm_ids))]
    errors += [f"attest-privacy.md: {e}" for e in check_claims(pc_rows)]
    errors += [f"attest-privacy.md: {e}" for e in check_schema_pins(pc_rows, schema)]
    return errors


def main() -> int:
    threat_model = _THREAT_MODEL_PATH.read_text(encoding="utf-8")
    privacy = _PRIVACY_PATH.read_text(encoding="utf-8")
    spec_v01 = _SPEC_V01_PATH.read_text(encoding="utf-8")
    spec_v02 = _SPEC_V02_PATH.read_text(encoding="utf-8")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema)
    for error in errors:
        print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
