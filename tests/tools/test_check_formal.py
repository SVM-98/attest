"""Tests for tools/check_formal.py — the fail-closed formal-proof gate.

Every test drives the checker through its injection paths (``--summary-file``,
``--theory-file``, ``--prover``, ``--maude``); the real toolchain is NEVER
invoked from this suite.
"""

import re
from pathlib import Path

import pytest

from tools import check_formal as cf

# --------------------------------------------------------------------------
# parse_summary (plan Task 7 Step 1 — skeleton verbatim)
# --------------------------------------------------------------------------

GREEN = """
summary of summaries:
  sanity_v01_accept (exists-trace): verified (5 steps)
  acceptance_issuer_signed (all-traces): verified (42 steps)
"""


def test_parse_summary_extracts_name_trait_result() -> None:
    got = cf.parse_summary(GREEN)
    assert got["sanity_v01_accept"] == ("exists-trace", "verified")
    assert got["acceptance_issuer_signed"] == ("all-traces", "verified")


def test_parse_summary_rejects_duplicate_lemma() -> None:
    dup = GREEN + "  acceptance_issuer_signed (all-traces): falsified\n"
    with pytest.raises(cf.SummaryError):
        cf.parse_summary(dup)


# Additional parser spec coverage (same public contract as the plan's Step 3).

REAL_SHAPE = """\
==============================================================================
summary of summaries:

analyzed: formal/attest.spthy

  processing time: 23.41s

  sanity_toolchain (exists-trace): analysis incomplete (1 steps)
  no_downgrade_revocation_allhybrid (all-traces): verified (2179 steps)

==============================================================================
"""


def test_parse_summary_handles_real_tamarin_block_shape() -> None:
    got = cf.parse_summary(REAL_SHAPE)
    assert got["sanity_toolchain"] == ("exists-trace", "analysis incomplete")
    assert got["no_downgrade_revocation_allhybrid"] == ("all-traces", "verified")


def test_parse_summary_reports_falsified() -> None:
    text = "summary of summaries:\n  bad_lemma (all-traces): falsified - found trace (7 steps)\n"
    got = cf.parse_summary(text)
    assert got["bad_lemma"] == ("all-traces", "falsified")


def test_parse_summary_rejects_unparseable_status_line() -> None:
    text = "summary of summaries:\n  weird_lemma (all-traces): exploded (7 steps)\n"
    with pytest.raises(cf.SummaryError):
        cf.parse_summary(text)


@pytest.mark.parametrize(
    "suffix",
    ["verifiedXYZ", "falsifiedness", "verified (1 steps) trailing-garbage"],
)
def test_parse_summary_rejects_status_suffixes(suffix: str) -> None:
    text = f"summary of summaries:\n  bad_lemma (all-traces): {suffix}\n"
    with pytest.raises(cf.SummaryError):
        cf.parse_summary(text)


def test_parse_summary_rejects_missing_block() -> None:
    with pytest.raises(cf.SummaryError):
        cf.parse_summary("no summaries here at all\n")


def test_parse_summary_rejects_empty_block() -> None:
    with pytest.raises(cf.SummaryError):
        cf.parse_summary("summary of summaries:\n\n")


# --------------------------------------------------------------------------
# normalize_lemma / lemma_digest
# --------------------------------------------------------------------------

THEORY = """\
theory toy
begin

/* a preamble comment mentioning lemma nowhere relevant */

lemma alpha [reuse, use_induction]:
  all-traces
  "All x #i. Foo(x) @ #i ==> Ex #j. Bar(x) @ #j & #j < #i"

/* comment between lemmas */
lemma beta:
  exists-trace
  /* comment INSIDE the lemma block */
  "Ex x #i. Foo(x) @ #i"

end
"""


def test_normalize_lemma_extracts_named_block_only() -> None:
    norm = cf.normalize_lemma(THEORY, "beta")
    assert norm.startswith("lemma beta:")
    assert "exists-trace" in norm
    assert "Bar" not in norm  # alpha's formula must not leak in
    assert "comment" not in norm  # comments stripped


def test_normalize_lemma_insensitive_to_comment_edits_and_reflow() -> None:
    reflowed = THEORY.replace(
        '  "Ex x #i. Foo(x) @ #i"',
        '  "Ex x #i.\n      Foo(x) @ #i"',
    ).replace("comment INSIDE the lemma block", "a totally different comment")
    assert cf.normalize_lemma(reflowed, "beta") == cf.normalize_lemma(THEORY, "beta")
    assert cf.lemma_digest(reflowed, "beta") == cf.lemma_digest(THEORY, "beta")


def test_lemma_digest_sensitive_to_formula_token_change() -> None:
    mutated = THEORY.replace("#j < #i", "#i < #j")
    assert cf.lemma_digest(mutated, "alpha") != cf.lemma_digest(THEORY, "alpha")


def test_lemma_digest_sensitive_to_trait_change() -> None:
    mutated = THEORY.replace("lemma beta:\n  exists-trace", "lemma beta:\n  all-traces")
    assert cf.lemma_digest(mutated, "beta") != cf.lemma_digest(THEORY, "beta")


def test_lemma_digest_sensitive_to_annotation_change() -> None:
    mutated = THEORY.replace("[reuse, use_induction]", "[reuse]")
    assert cf.lemma_digest(mutated, "alpha") != cf.lemma_digest(THEORY, "alpha")


def test_lemma_digest_is_sha256_hex() -> None:
    digest = cf.lemma_digest(THEORY, "alpha")
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_normalize_lemma_missing_lemma_raises() -> None:
    with pytest.raises(cf.TheoryError):
        cf.normalize_lemma(THEORY, "gamma")


def test_normalize_lemma_duplicate_declaration_raises() -> None:
    dup = THEORY.replace("end\n", 'lemma beta:\n  exists-trace\n  "Ex #i. T() @ #i"\n\nend\n')
    with pytest.raises(cf.TheoryError):
        cf.normalize_lemma(dup, "beta")


def test_lemma_digest_distinguishes_quoted_constants() -> None:
    # Quoted spans are verbatim: two sources differing only INSIDE a quoted
    # constant (spaces included — 'a b' and 'a  b' are distinct, Tamarin-valid
    # names) must digest differently.
    source = """\
theory toy
begin
lemma quoted:
  exists-trace
  "Ex #i. Event('a b') @ #i"
end
"""
    changed = source.replace("'a b'", "'a  b'")
    other = source.replace("'a b'", "'a c'")
    assert cf.lemma_digest(source, "quoted") != cf.lemma_digest(changed, "quoted")
    assert cf.lemma_digest(source, "quoted") != cf.lemma_digest(other, "quoted")


def test_comment_marker_inside_quotes_is_refused() -> None:
    # Comment markers inside quoted constants hit parsec backtracking quirks
    # no scanner can faithfully mirror (probed against the real prover:
    # 'a/*x*/b' verbatim-valid, '/*' eats the file, 'https://one' valid).
    # The normalizer REFUSES them — fail-closed beats a divergent digest.
    for constant in ("'https://one'", "'a/*x*/b'", "'*/'"):
        source = f"""\
theory toy
begin
lemma quoted:
  exists-trace
  "Ex #i. Event({constant}) @ #i"
end
"""
        with pytest.raises(cf.TheoryError):
            cf.normalize_lemma(source, "quoted")


def test_newline_inside_quoted_constant_is_refused() -> None:
    # tamarin-prover --parse-only rejects a newline inside a quoted constant;
    # the normalizer must agree, not silently span lines.
    source = "lemma q:\n  exists-trace\n  \"Ex #i. E('a\nb') @ #i\"\nend\n"
    with pytest.raises(cf.TheoryError):
        cf.normalize_lemma(source, "q")


# --------------------------------------------------------------------------
# CONTRACT + main (plan Task 7 Steps 3-4) — injection paths only
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_THEORY = REPO_ROOT / "formal" / "attest.spthy"
PINNED_VERSION_LINE = "tamarin-prover 1.12.0, (C) David Basin, Cas Cremers, Simon Meier, ETH Zurich"


def real_theory_src() -> str:
    return REAL_THEORY.read_text(encoding="utf-8")


def green_summary(only: set[str] | None = None) -> str:
    """Return a verified full or shard summary in CONTRACT corpus order."""
    lines = ["summary of summaries:", "", "analyzed: formal/attest.spthy", ""]
    for name, entry in cf.CONTRACT.items():
        if only is None or name in only:
            lines.append(f"  {name} ({entry['trait']}): verified (1 steps)")
    return "\n".join(lines) + "\n"


def make_fake_prover(
    tmp_path: Path,
    summary: str = "",
    version_line: str = PINNED_VERSION_LINE,
    exit_code: int = 0,
    sleep: float = 0.0,
) -> str:
    """Write an executable fake tamarin-prover script and return its path."""
    summary_file = tmp_path / "fake-summary.txt"
    summary_file.write_text(summary, encoding="utf-8")
    script = tmp_path / "fake-tamarin-prover"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys, time\n"
        "if '--version' in sys.argv:\n"
        f"    print({version_line!r})\n"
        "    sys.exit(0)\n"
        f"time.sleep({sleep!r})\n"
        f"print(pathlib.Path({str(summary_file)!r}).read_text(), end='')\n"
        f"sys.exit({exit_code!r})\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


def make_fake_maude(
    tmp_path: Path,
    version_line: str = "Maude 3.5.1",
    exit_code: int = 0,
    sleep: float = 0.0,
) -> str:
    """Write an executable fake Maude script and return its path."""
    script = tmp_path / "fake-maude"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        f"time.sleep({sleep!r})\n"
        f"print({version_line!r})\n"
        f"sys.exit({exit_code!r})\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


def run_main(
    tmp_path: Path, summary: str, theory_src: str | None = None, extra: list[str] | None = None
) -> int:
    """Drive main() through the --summary-file/--theory-file injection path."""
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(summary, encoding="utf-8")
    theory_file = REAL_THEORY
    if theory_src is not None:
        theory_file = tmp_path / "theory.spthy"
        theory_file.write_text(theory_src, encoding="utf-8")
    argv = [
        "--summary-file",
        str(summary_file),
        "--theory-file",
        str(theory_file),
        "--prover",
        make_fake_prover(tmp_path),
        "--maude",
        make_fake_maude(tmp_path),
    ]
    return cf.main(argv + (extra or []))


def test_contract_covers_entire_lemma_corpus() -> None:
    declared = re.findall(r"^lemma\s+(\w+)", real_theory_src(), re.MULTILINE)
    assert len(declared) == len(set(declared)), "duplicate lemma declaration in theory"
    assert set(cf.CONTRACT) == set(declared)
    assert len(cf.CONTRACT) == 45


def test_contract_digests_and_traits_match_real_theory() -> None:
    src = real_theory_src()
    for name, entry in cf.CONTRACT.items():
        assert entry["digest"] == cf.lemma_digest(src, name), name
        assert entry["trait"] in ("all-traces", "exists-trace"), name
        assert f"{entry['trait']}" in cf.normalize_lemma(src, name), name


def test_main_green_via_summary_file(tmp_path: Path) -> None:
    assert run_main(tmp_path, green_summary()) == 0


def test_main_green_via_fake_prover_subprocess(tmp_path: Path) -> None:
    prover = make_fake_prover(tmp_path, summary=green_summary())
    rc = cf.main(["--prover", prover, "--maude", make_fake_maude(tmp_path), str(REAL_THEORY)])
    assert rc == 0


def test_main_digest_mismatch_fails_even_when_verified(tmp_path: Path) -> None:
    # Weakened-theorem catch: summary fully green, but a pinned statement changed.
    src = real_theory_src()
    needle = "RevocationIssuedHybrid(I, rid, kid, recTime) @ #s & #s < #a"
    assert needle in src
    mutated = src.replace(needle, "RevocationIssuedHybrid(I, rid, kid, recTime) @ #s")
    assert run_main(tmp_path, green_summary(), theory_src=mutated) == 1


def test_main_trait_flip_fails(tmp_path: Path) -> None:
    flipped = green_summary().replace(
        "no_downgrade_artifact_manifest (all-traces)",
        "no_downgrade_artifact_manifest (exists-trace)",
    )
    assert run_main(tmp_path, flipped) == 1


def test_main_missing_pinned_lemma_fails(tmp_path: Path) -> None:
    lines = [ln for ln in green_summary().splitlines() if not ln.startswith("  sanity_toolchain ")]
    assert run_main(tmp_path, "\n".join(lines) + "\n") == 1


def test_main_unexpected_extra_lemma_fails(tmp_path: Path) -> None:
    extra = green_summary() + "  smuggled_lemma (all-traces): verified (1 steps)\n"
    assert run_main(tmp_path, extra) == 1


def test_main_census_rejects_extra_theory_lemma(tmp_path: Path) -> None:
    extra = real_theory_src().replace(
        "end\n", 'lemma unpinned_theory_lemma:\n  exists-trace\n  "Ex #i. T() @ #i"\n\nend\n'
    )
    assert run_main(tmp_path, green_summary(), theory_src=extra) == 1


def test_main_falsified_result_fails(tmp_path: Path) -> None:
    bad = green_summary().replace(
        "rotation_no_hijack (all-traces): verified (1 steps)",
        "rotation_no_hijack (all-traces): falsified - found trace (7 steps)",
    )
    assert run_main(tmp_path, bad) == 1


def test_main_prover_crash_fails(tmp_path: Path) -> None:
    prover = make_fake_prover(tmp_path, summary=green_summary(), exit_code=2)
    rc = cf.main(["--prover", prover, "--maude", make_fake_maude(tmp_path), str(REAL_THEORY)])
    assert rc == 1


def test_main_empty_summary_fails(tmp_path: Path) -> None:
    prover = make_fake_prover(tmp_path, summary="")
    rc = cf.main(["--prover", prover, "--maude", make_fake_maude(tmp_path), str(REAL_THEORY)])
    assert rc == 1


def test_main_prover_timeout_fails(tmp_path: Path) -> None:
    prover = make_fake_prover(tmp_path, summary=green_summary(), sleep=20.0)
    rc = cf.main(
        [
            "--prover",
            prover,
            "--maude",
            make_fake_maude(tmp_path),
            "--timeout",
            "1",
            str(REAL_THEORY),
        ]
    )
    assert rc == 1


def test_main_missing_prover_binary_fails(tmp_path: Path) -> None:
    rc = cf.main(
        [
            "--prover",
            str(tmp_path / "does-not-exist"),
            "--maude",
            make_fake_maude(tmp_path),
            str(REAL_THEORY),
        ]
    )
    assert rc == 1


# --only sharding (T8): results scoped to the shard, digests always global.

SHARD = {"no_downgrade_revocation_allhybrid", "acceptance_issuer_signed"}


def test_main_only_subset_passes_when_unscoped_lemmas_are_absent(tmp_path: Path) -> None:
    rc = run_main(
        tmp_path,
        green_summary(only=SHARD),
        extra=["--only", ",".join(sorted(SHARD))],
    )
    assert rc == 0


def test_main_only_does_not_excuse_failed_shard_lemma(tmp_path: Path) -> None:
    bad = green_summary(only=SHARD).replace(
        "acceptance_issuer_signed (all-traces): verified (1 steps)",
        "acceptance_issuer_signed (all-traces): analysis incomplete (1 steps)",
    )
    rc = run_main(tmp_path, bad, extra=["--only", ",".join(sorted(SHARD))])
    assert rc == 1


def test_main_only_name_absent_from_contract_is_an_error(tmp_path: Path) -> None:
    rc = run_main(tmp_path, green_summary(), extra=["--only", "no_such_lemma"])
    assert rc == 2


def test_main_only_empty_shard_is_an_error(tmp_path: Path) -> None:
    assert run_main(tmp_path, green_summary(), extra=["--only", ","]) == 2


def test_main_only_does_not_launder_non_scoped_falsification(tmp_path: Path) -> None:
    summary = green_summary(only=SHARD)
    summary += "  rotation_no_hijack (all-traces): falsified - found trace (7 steps)\n"
    rc = run_main(tmp_path, summary, extra=["--only", ",".join(sorted(SHARD))])
    assert rc == 1


def test_main_theory_file_requires_summary_file(tmp_path: Path) -> None:
    rc = cf.main(["--theory-file", str(REAL_THEORY), "--prover", make_fake_prover(tmp_path)])
    assert rc == 2


RECORDED_SUMMARY = Path(__file__).parent / "fixtures" / "formal" / "green-summary-recorded.txt"


def test_main_green_on_recorded_summary_fixture(tmp_path: Path) -> None:
    """Reality check: the committed summary assembled from the recorded T5/T6
    per-lemma runs passes the real CONTRACT against the real theory source."""
    rc = cf.main(
        [
            "--summary-file",
            str(RECORDED_SUMMARY),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path),
        ]
    )
    assert rc == 0


# Toolchain pins are fail-closed on every valid invocation. Matching versions
# are exercised by every green test; these cases target Maude specifically.


def test_main_version_mismatch_fails(tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    prover = make_fake_prover(
        tmp_path, version_line="tamarin-prover 1.10.6, (C) David Basin, ETH Zurich"
    )
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            prover,
            "--maude",
            make_fake_maude(tmp_path),
        ]
    )
    assert rc == 1


def test_main_version_unparseable_fails(tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    prover = make_fake_prover(tmp_path, version_line="no version to be found here")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            prover,
            "--maude",
            make_fake_maude(tmp_path),
        ]
    )
    assert rc == 1


@pytest.mark.parametrize("version_line", ["Maude 3.4.0", "no version to be found here"])
def test_main_maude_version_mismatch_or_unparseable_fails(
    tmp_path: Path, version_line: str
) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path, version_line=version_line),
        ]
    )
    assert rc == 1


def test_main_missing_maude_binary_fails(tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            str(tmp_path / "does-not-exist-maude"),
        ]
    )
    assert rc == 1


def test_main_only_digest_check_still_global(tmp_path: Path) -> None:
    # Mutate a lemma OUTSIDE the shard subset: the shard run must still fail.
    src = real_theory_src()
    needle = "ArtifactManifestIssued(I, aid, kid2) @ #s"
    assert needle in src
    mutated = src.replace(needle, "ArtifactManifestIssued(I, aid, kid2) @ #s & #s < #a")
    rc = run_main(
        tmp_path,
        green_summary(only=SHARD),
        theory_src=mutated,
        extra=["--only", ",".join(sorted(SHARD))],
    )
    assert rc == 1


def test_maude_bare_version_line_accepted(tmp_path: Path) -> None:
    # The REAL `maude --version` prints ONLY "3.5.1" (no tool name). The pin
    # must accept that form, not just the "Maude 3.5.1" prefix form.
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path, version_line="3.5.1"),
        ]
    )
    assert rc == 0


def test_summary_file_without_theory_file_digests_positional_theory(tmp_path: Path) -> None:
    # --summary-file alone is legal: digests/census run on the positional theory.
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            str(REAL_THEORY),
            "--summary-file",
            str(summary_file),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path, version_line="3.5.1"),
        ]
    )
    assert rc == 0


def test_nested_block_comment_unterminated_is_theory_error(tmp_path: Path) -> None:
    # Tamarin 1.12.0 NESTS /* */ comments: `/* outer /* inner */` is an
    # UNTERMINATED comment to Tamarin. The normalizer must agree, not accept.
    src = real_theory_src() + "\n/* outer /* inner */\n"
    rc = run_main(tmp_path, green_summary(), theory_src=src)
    assert rc == 1


def test_nested_block_comment_terminated_strips_whole_span() -> None:
    # A properly nested comment is ONE comment to Tamarin: `tail` inside the
    # outer span must not leak into the normalized lemma text.
    plain = 'lemma demo:\n  exists-trace\n  "Ex #i. A() @ #i"\nend\n'
    nested = (
        'lemma demo:\n  /* outer /* inner */ tail */\n  exists-trace\n  "Ex #i. A() @ #i"\nend\n'
    )
    assert cf.normalize_lemma(plain, "demo") == cf.normalize_lemma(nested, "demo")


def test_maude_wrong_tool_name_rejected(tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path, version_line="NotMaude 3.5.1"),
        ]
    )
    assert rc == 1


def test_maude_stray_version_line_in_junk_rejected(tmp_path: Path) -> None:
    summary_file = tmp_path / "summary.txt"
    summary_file.write_text(green_summary(), encoding="utf-8")
    rc = cf.main(
        [
            "--summary-file",
            str(summary_file),
            "--theory-file",
            str(REAL_THEORY),
            "--prover",
            make_fake_prover(tmp_path),
            "--maude",
            make_fake_maude(tmp_path, version_line="wrong-wrapper 9.9.9\n3.5.1"),
        ]
    )
    assert rc == 1


def test_verified_found_trace_is_contradictory_and_rejected(tmp_path: Path) -> None:
    # `- found trace` is a falsified suffix; `verified - found trace` is a
    # contradictory line and must be a SummaryError, not a green verdict.
    bad = green_summary().replace(
        "sanity_toolchain (exists-trace): verified (1 steps)",
        "sanity_toolchain (exists-trace): verified - found trace (1 steps)",
    )
    assert "verified - found trace" in bad
    rc = run_main(tmp_path, bad)
    assert rc == 1


def test_round3_repro_quoted_comment_opener_rejected(tmp_path: Path) -> None:
    # Round-3 reviewer repro: `Out('/*') /* outer /* inner */ tail */` before
    # the first lemma. Tamarin --parse-only rejects the file; the gate must
    # NOT return OK on it (quoted span containing a comment marker ⇒ refusal).
    src = real_theory_src().replace(
        "rule Admit_Revocation_Record_hybrid:",
        "rule Poison: [ ] --> [ Out('/*') ]\n/* outer /* inner */ tail */\n"
        "rule Admit_Revocation_Record_hybrid:",
        1,
    )
    assert "Poison" in src
    rc = run_main(tmp_path, green_summary(), theory_src=src)
    assert rc == 1
