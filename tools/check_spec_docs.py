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
_VERSIONING_PATH = _REPO_ROOT / "docs/spec/attest-versioning.md"

# The six normative sections attest-versioning.md's amendment procedure
# requires (§5) every reader be able to find by exact heading.
_VERSIONING_REQUIRED_HEADINGS: tuple[str, ...] = (
    "## 1. Scope and authority",
    "## 2. The additive pattern",
    "## 3. Eternal verifiability",
    "## 4. Algorithm lifecycle",
    "## 5. Amendment procedure",
    "## 6. Registries",
)

# The two signature suites the two normative specs actually define (v0.1 §10,
# v0.2 §2). A registry entry for a suite neither spec defines would register
# nothing real; naming both here keeps that in sync by construction.
_VERSIONING_REQUIRED_SUITES: tuple[str, ...] = ("`ed25519`", "`ed25519+ml-dsa-65`")

# §4's algorithm lifecycle defines exactly these three states.
_VERSIONING_LIFECYCLE_STATES: tuple[str, ...] = ("`active`", "`deprecated`", "`unsafe`")

# §6.3 lists the existing revocation classes, plus the separate reserved
# `transferred` row for the future transfer profile.
_VERSIONING_REQUIRED_REVOCATION_CLASSES: tuple[str, ...] = (
    "`none`",
    "`refund_window`",
    "`policy`",
    "`compromised`",
)

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
_REF_GROUP_RE = re.compile(
    r"(v0\.[12]) (§\d+(?:\.\d+)?(?:(?:[,;]\s*(?:and\s+)?|\s+and\s+)§\d+(?:\.\d+)?)*)"
)
_REF_SECTION_RE = re.compile(r"§\d+(?:\.\d+)?")
_MATRIX_ROW_RE = re.compile(r"^\| (v0\.[12]) §(\d+) — [^|]*\|([^|]*)\|\s*$", re.MULTILINE)
_MATRIX_TM_REF_RE = re.compile(r"TM-(\d+)")
# A cell may name a TM entry only in the canonical form. Anything else that reads
# as a citation — an en dash, an underscore, a missing number — must be reported
# rather than skipped, or a malformed citation silently covers nothing.
_MATRIX_TM_TOKEN_RE = re.compile(r"TM\S*")
_CANONICAL_TM_REF_RE = re.compile(r"TM-\d+")
# Only v0.1 and v0.2 exist, so any other version cited AS A SPEC is drift. The
# lookahead keeps ordinary prose ("TLS v1.3") out of it: without a section sign
# following, a version token is not a citation and flagging it would fail a
# legitimate edit.
_ANY_SPEC_VERSION_RE = re.compile(r"\bv\d+\.\d+(?=\s*§)")
# CommonMark opens a fence with ``` or ~~~, indented up to three spaces.
_FENCED_BLOCK_RE = re.compile(r"^ {0,3}(```|~~~).*?^ {0,3}\1", re.MULTILINE | re.DOTALL)
_PC_ROW_RE = re.compile(r"^\| PC-(\d+) \| ([^|]*) \| ([^|]*) \| ([^|]*) \|\s*$", re.MULTILINE)
_PC01_PIN_RE = re.compile(r"key set exactly `?\{([^}]*)\}")
_PC01_REQUIRED_PIN_RE = re.compile(r"`properties\.buyer\.required` equals `?(\[[^`]*\])`?")
_PC01_PATTERN_PIN_RE = re.compile(
    r"`([^`]+)` and `([^`]+)` are pattern-constrained to (\d+) base64url characters"
)
_PC01_PATTERN_FIELDS = {"commitment", "pubkey"}
_PC01_ENUM_PIN_RE = re.compile(r"`identifier_type` to the\s+enum `?(\[[^`]*\])`?")
_REVISION_LOG_HEADING_RE = re.compile(r"^## Revision log$", re.MULTILINE)
_REVISION_LOG_ENTRY_RE = re.compile(
    r"^- \*\*\d{4}-\d{2}-\d{2} \(rev \d+\)\*\*: .+ — vectors: \S.*$"
)

# §5.1's `receipt_id` row inlines the ULID regex in backticks, e.g.:
# `| \`receipt_id\` | string, ULID (\`^[0-7][0-9A-HJKMNP-TV-Z]{25}$\`) | REQUIRED | ... |`
_RECEIPT_ID_PROSE_ROW_RE = re.compile(r"\| `receipt_id` \| string, ULID \(`([^`]+)`\) \|")


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


def _strip_fenced_blocks(text: str) -> str:
    """Blank out fenced code blocks, preserving line count so nothing shifts."""
    return _FENCED_BLOCK_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


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

    for index, current in enumerate(tm_ids[1:], start=1):
        previous = tm_ids[index - 1]
        if current < previous:
            errors.append(
                f"TM id sequence is not ascending: TM-{current:02d} appears after TM-{previous:02d}"
            )

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
        for version_match in _ANY_SPEC_VERSION_RE.finditer(verdict_line):
            version = version_match.group(0)
            if version not in ("v0.1", "v0.2"):
                errors.append(f"{label}: unsupported spec version {version} in Verdict line")
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
        has_known_tm = False
        for token_match in _MATRIX_TM_TOKEN_RE.finditer(row_rest):
            token = token_match.group(0).rstrip(",;.")
            if not _CANONICAL_TM_REF_RE.fullmatch(token):
                errors.append(f"malformed TM citation {token!r} (row {version} §{number})")
        for tm_ref in _MATRIX_TM_REF_RE.finditer(row_rest):
            cited = int(tm_ref.group(1))
            if cited not in tm_ids:
                errors.append(
                    f"traceability matrix cites unknown TM-{cited:02d} (row {version} §{number})"
                )
            else:
                has_known_tm = True
        if has_known_tm:
            covered_sections.add(f"{version} §{number}")

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
    """PC-01's pinned buyer schema constraints match the actual schema."""
    errors: list[str] = []
    pc01_rows = [row for row in pc_rows if row.pc_id == 1]
    if not pc01_rows:
        errors.append("PC-01: required testable-claim row is missing")
        return errors

    properties = schema.get("properties")
    buyer = properties.get("buyer") if isinstance(properties, dict) else None
    buyer_properties = buyer.get("properties") if isinstance(buyer, dict) else None
    actual = sorted(buyer_properties) if isinstance(buyer_properties, dict) else []
    buyer_required = buyer.get("required") if isinstance(buyer, dict) else None
    actual_required = (
        sorted(item for item in buyer_required if isinstance(item, str))
        if isinstance(buyer_required, list)
        else []
    )

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

        required_match = _PC01_REQUIRED_PIN_RE.search(row.detail)
        if required_match is None:
            errors.append("PC-01: no 'properties.buyer.required' pin found in check detail")
        else:
            pinned_required = json.loads(required_match.group(1))
            if not isinstance(pinned_required, list) or not all(
                isinstance(item, str) for item in pinned_required
            ):
                errors.append("PC-01: invalid 'properties.buyer.required' pin in check detail")
            elif sorted(pinned_required) != actual_required:
                errors.append(
                    f"PC-01: pinned buyer required list {sorted(pinned_required)} diverges from "
                    f"schema's actual list {actual_required}"
                )

        pattern_match = _PC01_PATTERN_PIN_RE.search(row.detail)
        if pattern_match is None:
            errors.append("PC-01: no base64url pattern-constraint pin found in check detail")
            continue
        first_name, second_name, length_text = pattern_match.groups()
        # The names come from prose, so a drifted document could name the same
        # field twice and leave the other unchecked. Require both by name.
        if {first_name, second_name} != _PC01_PATTERN_FIELDS:
            errors.append(
                f"PC-01: pattern pin names {sorted({first_name, second_name})}, "
                f"expected {sorted(_PC01_PATTERN_FIELDS)}"
            )
        expected_pattern = rf"^[A-Za-z0-9_-]{{{length_text}}}$"
        for name in (first_name, second_name):
            field = buyer_properties.get(name) if isinstance(buyer_properties, dict) else None
            actual_pattern = field.get("pattern") if isinstance(field, dict) else None
            if actual_pattern != expected_pattern:
                errors.append(
                    f"PC-01: pinned buyer pattern constraint for {name!r} "
                    f"diverges from schema's actual pattern {actual_pattern!r}"
                )

        enum_match = _PC01_ENUM_PIN_RE.search(row.detail)
        if enum_match is None:
            errors.append("PC-01: no 'identifier_type' enum pin found in check detail")
            continue
        pinned_enum = json.loads(enum_match.group(1))
        identifier_type = (
            buyer_properties.get("identifier_type") if isinstance(buyer_properties, dict) else None
        )
        actual_enum = identifier_type.get("enum") if isinstance(identifier_type, dict) else None
        if actual_enum != pinned_enum:
            errors.append(
                f"PC-01: pinned 'identifier_type' enum {pinned_enum} diverges from "
                f"schema's actual enum {actual_enum!r}"
            )

    return errors


def check_versioning_sections(versioning: str) -> list[str]:
    """Every §1-§6 heading the amendment procedure (§5) requires is present."""
    errors: list[str] = []
    for heading in _VERSIONING_REQUIRED_HEADINGS:
        if re.search(rf"^{re.escape(heading)}$", versioning, re.MULTILINE) is None:
            errors.append(f"missing required heading {heading!r}")
    return errors


def check_versioning_suite_names(versioning: str) -> list[str]:
    """The §6.1 registry names every signature suite the specs actually define."""
    errors: list[str] = []
    for suite in _VERSIONING_REQUIRED_SUITES:
        if re.search(rf"^\| {re.escape(suite)} \|", versioning, re.MULTILINE) is None:
            errors.append(f"§6.1 registry missing suite row {suite}")
    return errors


def check_versioning_lifecycle_states(versioning: str) -> list[str]:
    """§4's algorithm lifecycle names exactly the three defined states."""
    section_match = re.search(
        r"^## 4\. Algorithm lifecycle$([\s\S]*?)(?=^## |\Z)", versioning, re.MULTILINE
    )
    if section_match is None:
        return ["missing required heading '## 4. Algorithm lifecycle'"]

    actual = set(re.findall(r"^\| (`[^`]+`) \|", section_match.group(1), re.MULTILINE))
    expected = set(_VERSIONING_LIFECYCLE_STATES)
    if actual != expected:
        return [
            "§4 algorithm lifecycle states must be exactly "
            f"{sorted(expected)}, found {sorted(actual)}"
        ]
    return []


def check_versioning_revocation_classes(versioning: str) -> list[str]:
    """The §6.3 registry has a table row for every existing class."""
    errors: list[str] = []
    for revocation_class in _VERSIONING_REQUIRED_REVOCATION_CLASSES:
        if re.search(rf"^\| {re.escape(revocation_class)} \|", versioning, re.MULTILINE) is None:
            errors.append(f"§6.3 registry missing revocation-class row {revocation_class}")
    return errors


def check_versioning_lifecycle_exception(versioning: str) -> list[str]:
    """§2 explicitly exempts lifecycle-driven classification downgrades."""
    if re.search(r"^One exception exists:.*$", versioning, re.MULTILINE) is None:
        return ["§2 missing required lifecycle exception paragraph 'One exception exists:'"]
    return []


def _check_revision_log(spec_text: str, filename: str) -> list[str]:
    """Validate the required revision-log heading, entries, and entry grammar."""
    errors: list[str] = []
    heading_match = _REVISION_LOG_HEADING_RE.search(spec_text)
    if heading_match is None:
        return [f"{filename}: missing '## Revision log' section"]

    lines = spec_text.splitlines()
    heading_line = spec_text[: heading_match.start()].count("\n")
    entry_count = 0
    for index in range(heading_line + 1, len(lines)):
        line = lines[index]
        if line.startswith("## "):
            break
        if line.startswith("- "):
            entry_count += 1
            if _REVISION_LOG_ENTRY_RE.fullmatch(line) is None:
                errors.append(
                    f"{filename}: revision-log entry on line {index + 1} does not match "
                    "required grammar"
                )
    if entry_count == 0:
        errors.append(f"{filename}: revision log requires at least one revision-log entry")
    return errors


def check_receipt_id_pattern(spec_v01: str, schema: dict[str, object]) -> list[str]:
    """§5.1's inline `receipt_id` ULID regex MUST equal the schema's own
    `properties.receipt_id.pattern` — the two describe the same wire
    constraint (a Crockford base32 ULID whose leading character is bounded
    to `[0-7]`, since a 26-char ULID otherwise overflows 128 bits) and must
    never drift (2026-07-22 fix: the prose lacked that high-bit guard while
    the schema already had it).

    Skips ONLY when NEITHER side models `receipt_id` at all — most fixture
    docs in this test module carry no full §5.1 table and no `receipt_id`
    schema property, and are not meant to exercise this check; that is not a
    drift signal. A ONE-SIDED absence, though, IS a drift signal (a prose row
    added/removed without touching the schema, or vice versa) and is now an
    explicit, fail-closed error (M2, 2026-07-22 fix wave 2 — this function
    used to `return []` on either side's absence alone, silently blessing
    exactly that drift). The real spec and schema always carry both.
    """
    match = _RECEIPT_ID_PROSE_ROW_RE.search(spec_v01)

    properties = schema.get("properties")
    receipt_id_schema = properties.get("receipt_id") if isinstance(properties, dict) else None
    schema_pattern = (
        receipt_id_schema.get("pattern") if isinstance(receipt_id_schema, dict) else None
    )

    if match is None and schema_pattern is None:
        return []

    if match is None:
        return [
            f"attest-v0.1.md: schema defines receipt_id.pattern {schema_pattern!r} but "
            "§5.1 has no receipt_id prose row (fail-closed: one-sided absence is drift)"
        ]

    prose_pattern = match.group(1)

    if schema_pattern is None:
        return [
            f"attest-v0.1.md: §5.1 receipt_id prose pattern {prose_pattern!r} but schema "
            "defines no receipt_id.pattern (fail-closed: one-sided absence is drift)"
        ]

    if prose_pattern != schema_pattern:
        return [
            f"attest-v0.1.md: §5.1 receipt_id prose pattern {prose_pattern!r} diverges from "
            f"schema pattern {schema_pattern!r}"
        ]
    return []


def check_revision_logs(spec_v01: str, spec_v02: str) -> list[str]:
    """Both normative specs have non-empty revision logs with valid entries."""
    return _check_revision_log(spec_v01, "attest-v0.1.md") + _check_revision_log(
        spec_v02, "attest-v0.2.md"
    )


def collect_errors(
    threat_model: str,
    privacy: str,
    spec_v01: str,
    spec_v02: str,
    schema: dict[str, object],
    versioning: str,
) -> list[str]:
    """Cross-check the two companion docs against each other and the specs.

    Also checks attest-versioning.md's required sections and registries, and
    that both normative specs carry the `## Revision log` section its
    amendment procedure (§5) requires.

    Returns one human-readable string per problem found; an empty list means
    the documents are internally consistent and in sync with the specs and
    schema they cite.
    """
    # Illustrative tables and sample entries live in code fences throughout both
    # documents. They read exactly like the real thing, so scanning them would let
    # a fenced example stand in for a real matrix row or catalog entry.
    threat_model = _strip_fenced_blocks(threat_model)
    privacy = _strip_fenced_blocks(privacy)

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
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_sections(versioning)]
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_suite_names(versioning)]
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_lifecycle_states(versioning)]
    errors += [
        f"attest-versioning.md: {e}" for e in check_versioning_revocation_classes(versioning)
    ]
    errors += [
        f"attest-versioning.md: {e}" for e in check_versioning_lifecycle_exception(versioning)
    ]
    errors += check_revision_logs(spec_v01, spec_v02)
    errors += check_receipt_id_pattern(spec_v01, schema)
    return errors


def main() -> int:
    threat_model = _THREAT_MODEL_PATH.read_text(encoding="utf-8")
    privacy = _PRIVACY_PATH.read_text(encoding="utf-8")
    spec_v01 = _SPEC_V01_PATH.read_text(encoding="utf-8")
    spec_v02 = _SPEC_V02_PATH.read_text(encoding="utf-8")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    versioning = _VERSIONING_PATH.read_text(encoding="utf-8")

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, versioning)
    for error in errors:
        print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
