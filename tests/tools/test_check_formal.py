"""Tests for tools/check_formal.py — the fail-closed formal-proof gate.

Every test drives the checker through its injection paths (``--summary-file``,
``--theory-file``, ``--prover``, ``--maude``); the real toolchain is NEVER
invoked from this suite.
"""

import re
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]  # dev-only; PyYAML ships no py.typed

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


def green_summary(only: set[str] | None = None, rest_status: str | None = None) -> str:
    """Return a verified full or shard summary in CONTRACT corpus order.

    With ``rest_status``, non-``only`` lemmas are emitted with that status —
    a real ``--prove=<name>`` run reports every unproved lemma as
    ``analysis incomplete``, so shard-shaped fixtures need the full corpus.
    """
    lines = ["summary of summaries:", "", "analyzed: formal/attest.spthy", ""]
    for name, entry in cf.CONTRACT.items():
        if only is None or name in only:
            lines.append(f"  {name} ({entry['trait']}): verified (1 steps)")
        elif rest_status is not None:
            lines.append(f"  {name} ({entry['trait']}): {rest_status}")
    return "\n".join(lines) + "\n"


def make_fake_prover(
    tmp_path: Path,
    summary: str = "",
    version_line: str = PINNED_VERSION_LINE,
    exit_code: int = 0,
    sleep: float = 0.0,
    args_log: Path | None = None,
) -> str:
    """Write an executable fake tamarin-prover script and return its path.

    With ``args_log``, every non-``--version`` invocation appends its full
    argv (one line, space-joined) so tests can assert on the exact command
    the checker constructs.
    """
    summary_file = tmp_path / "fake-summary.txt"
    summary_file.write_text(summary, encoding="utf-8")
    record = (
        f"with open({str(args_log)!r}, 'a') as fh:\n    fh.write(' '.join(sys.argv) + '\\n')\n"
        if args_log is not None
        else ""
    )
    script = tmp_path / "fake-tamarin-prover"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys, time\n"
        "if '--version' in sys.argv:\n"
        f"    print({version_line!r})\n"
        "    sys.exit(0)\n"
        f"{record}"
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


def test_prover_invocation_pins_derivcheck_timeout(tmp_path: Path) -> None:
    """The prove command must carry the pinned --derivcheck-timeout.

    Tamarin's default derivation-check timeout (5s) expires on this theory,
    which emits a wellformedness warning. --quit-on-warning turns any such
    warning into a non-zero prover exit, so the gate fails closed. Every
    T3-T6 measurement ran with an explicit timeout. The checker must pin it,
    not inherit the default.
    """
    args_log = tmp_path / "prover-args.log"
    prover = make_fake_prover(tmp_path, summary=green_summary(), args_log=args_log)
    rc = cf.main(["--prover", prover, "--maude", make_fake_maude(tmp_path), str(REAL_THEORY)])
    assert rc == 0
    recorded = args_log.read_text(encoding="utf-8")
    assert f"--derivcheck-timeout={cf.DERIVCHECK_TIMEOUT_S}" in recorded
    assert "--quit-on-warning" in recorded
    assert cf.DERIVCHECK_TIMEOUT_S >= 20  # the empirically WF-clean floor


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


def test_main_only_accepts_real_shard_shape(tmp_path: Path) -> None:
    """A real ``--prove=<name>`` summary lists every unproved lemma as
    ``analysis incomplete`` — out-of-scope incompleteness is the expected
    shard shape, not a failure. Caught by the first full-prove run against
    the real prover (2026-07-22): injected fixtures never had this shape."""
    summary = green_summary(only=SHARD, rest_status="analysis incomplete (1 steps)")
    rc = run_main(tmp_path, summary, extra=["--only", ",".join(sorted(SHARD))])
    assert rc == 0


def test_main_only_fails_scoped_lemma_not_verified(tmp_path: Path) -> None:
    """In-scope lemmas must still be verified — scoping the blanket check
    must not drop the result assertion for the shard's own lemmas."""
    scoped = sorted(SHARD)
    verified_part = {n for n in SHARD if n != scoped[0]}
    summary = green_summary(only=verified_part, rest_status="analysis incomplete (1 steps)")
    rc = run_main(tmp_path, summary, extra=["--only", ",".join(scoped)])
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


# --------------------------------------------------------------------------
# CI shard anti-drift (Task 8): the `formal` job's five `--only` lists in
# .github/workflows/ci.yml must partition CONTRACT exactly. A lemma added to
# CONTRACT without a shard assignment (or assigned twice) must turn CI red
# HERE, in pytest, before any prover minute is spent.
# --------------------------------------------------------------------------

CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# Deliberately shape-coupled to the matrix layout in ci.yml (a comment there
# points back here): each shard is a `- shard: <name>` entry followed by
# `timeout:` and `checker_timeout:` lines and a SINGLE-LINE double-quoted
# `lemmas:` list. Stdlib parsing is fine — the YAML is ours and this test owns
# its shape.
_SHARD_RE = re.compile(
    r"^\s+-\s+shard:\s+(?P<shard>[A-Za-z0-9_-]+)\s*\n"
    r"\s+timeout:\s+\d+\s*\n"
    r"\s+checker_timeout:\s+\d+\s*\n"
    r'\s+lemmas:\s+"(?P<lemmas>[^"\n]*)"',
    re.MULTILINE,
)
_FORMAL_JOB_RE = re.compile(r"^  formal:\s*$", re.MULTILINE)
_TOP_LEVEL_JOB_RE = re.compile(r"^  [A-Za-z0-9_-]+:\s*$", re.MULTILINE)
_INCLUDE_RE = re.compile(r"^(?P<indent>\s+)include:\s*$", re.MULTILINE)


def ci_formal_job_block(workflow: Path | None = None) -> str:
    """Return the real formal CI job block, or fail if it is absent."""
    workflow = workflow or CI_WORKFLOW
    text = workflow.read_text(encoding="utf-8")
    formal = _FORMAL_JOB_RE.search(text)
    if formal is None:
        raise AssertionError(f"formal job block absent from {workflow}")
    next_job = _TOP_LEVEL_JOB_RE.search(text, formal.end())
    return text[formal.start() : next_job.start() if next_job else len(text)]


def assert_ci_formal_job_executes_matrix(workflow: Path | None = None) -> None:
    """Assert the formal job is configured to run the checker on its matrix.

    THREAT MODEL (declared boundary, settled in branch-review round 5): this
    is a static guard against ACCIDENTAL drift — a renamed job, an edited or
    hard-coded run step, a decoupled matrix, an inadvertently ``if:``-gated
    job, a commented-out command line, a soft-failing step. It does NOT — and
    no in-repo static test can — prove that CI will *execute* anything
    against an adversary with write access to the repository: such an
    adversary can remove this very test in the same commit. Execution
    enforcement against tampering belongs to repository configuration AND
    process: branch protection marking the ``formal`` shards as required
    status checks, plus mandatory review of workflow changes — required
    checks alone do not help if a writer keeps the check names and no-ops
    their commands.

    Within that boundary the check is SEMANTIC (rounds 2-4 defeated three
    line-based scanners): the workflow is parsed with a real YAML parser and
    only ``jobs.formal.steps[].run`` values count, with shell comments (full
    lines and trailing ``#`` fragments) stripped from each script. The job
    and its checker steps must carry no ``if:`` gate and no
    ``continue-on-error``; the checker scripts must contain no ``||``
    fallback; at least one step must invoke the checker; every invoking step
    must carry both matrix placeholders.
    """
    workflow = workflow or CI_WORKFLOW
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    try:
        formal = doc["jobs"]["formal"]
        steps = formal["steps"]
    except (KeyError, TypeError) as exc:
        raise AssertionError(f"formal job with steps absent from {workflow}: {exc!r}") from None
    assert "if" not in formal, (
        "formal job carries an if: gate — accidental skip conditions are not "
        "allowed on the proof job"
    )
    assert "continue-on-error" not in formal, (
        "formal job carries continue-on-error — failed proofs must never produce a green gate"
    )
    live_runs: list[tuple[dict[str, object], str]] = []
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            # Strip full-line comments AND trailing ` #` fragments: a command
            # surviving only inside a comment must never satisfy the guard.
            # Crude for pathological quoting, but no legitimate checker
            # invocation here contains '#'; fail direction stays loud.
            script = "\n".join(
                line.split(" #", 1)[0]
                for line in step["run"].splitlines()
                if not line.lstrip().startswith("#")
            )
            live_runs.append((step, script))
    checker_runs = [
        (step, script) for step, script in live_runs if "tools/check_formal.py" in script
    ]
    assert checker_runs, "formal job has no live run step invoking tools/check_formal.py"
    for step, script in checker_runs:
        assert "if" not in step, (
            "formal job's checker step carries an if: gate — accidental skip "
            "conditions are not allowed on the proof step"
        )
        assert "continue-on-error" not in step, (
            "formal job's checker step carries continue-on-error — failed "
            "proofs must never produce a green gate"
        )
        assert "||" not in script, (
            "formal job's checker script contains a '||' fallback — a failing "
            "checker must fail the step: " + script
        )
        assert (
            '--only "${{ matrix.lemmas }}"' in script
            and "--timeout ${{ matrix.checker_timeout }}" in script
        ), (
            "formal job's run step does not execute the matrix entries "
            '(--only "${{ matrix.lemmas }}" / --timeout ${{ matrix.checker_timeout }}): ' + script
        )


def _matrix_list_item_count(formal_block: str) -> int:
    """Count YAML list items under the matrix ``include:`` — any spelling.

    Every shard is exactly one block-sequence item (``- ...`` or a standalone
    ``-``) more indented than ``include:``; blank and comment lines are
    skipped. Counting the dashes rather than the literal ``shard:`` key catches
    a fifth entry written ``shard :``, ``"shard":``, or any other key spelling
    — the loudness guard must not depend on how the key is typed.
    """
    inc = _INCLUDE_RE.search(formal_block)
    if inc is None:
        raise AssertionError("formal job matrix has no 'include:' block")
    base = len(inc.group("indent"))
    tail = formal_block[inc.end() :]
    count = 0
    for line in tail.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.lstrip()
        if indent <= base and not stripped.startswith("-"):
            break  # dedented out of the include block
        if indent > base and re.match(r"^-(\s|$)", stripped):
            count += 1
    return count


def ci_formal_shards(workflow: Path | None = None) -> dict[str, list[str]]:
    """Extract the formal job's five shard -> lemma-list mappings from ci.yml."""
    formal_block = ci_formal_job_block(workflow)
    entries = [
        (match.group("shard"), match.group("lemmas").split(","))
        for match in _SHARD_RE.finditer(formal_block)
    ]
    # LOUDNESS GUARD: the strict entry regex is field-order- AND spelling-
    # sensitive, so a matrix entry in a different shape would silently not
    # match. Count matrix list ITEMS independently (any key spelling / field
    # order — see _matrix_list_item_count) and require every item to have
    # parsed. A fifth entry in ANY YAML form fails here, never hides.
    item_count = _matrix_list_item_count(formal_block)
    if item_count != len(entries):
        raise AssertionError(
            f"formal job matrix has {item_count} list items but only "
            f"{len(entries)} parse as shard entries — fix ci.yml or this "
            "parser, do not let entries go dark"
        )
    if len(entries) != 5:
        raise AssertionError(
            f"formal job must declare exactly 5 shard entries, found {len(entries)}"
        )
    shard_names = [name for name, _ in entries]
    if len(set(shard_names)) != 5:
        raise AssertionError(f"formal job shard names must be distinct, found {shard_names}")
    return dict(entries)


def test_ci_formal_matrix_declares_exactly_the_five_shards() -> None:
    assert set(ci_formal_shards()) == {
        "heavy-revdowngrade",
        "heavy-acceptance",
        "revocation-core",
        "revocation-classes",
        "rest",
    }


def test_ci_formal_job_executes_matrix_shard_checker() -> None:
    assert_ci_formal_job_executes_matrix()


def test_ci_formal_job_rejects_hard_coded_shard_execution(tmp_path: Path) -> None:
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        "run: python3 tools/check_formal.py formal/attest.spthy "
        "--only sanity_toolchain --timeout ${{ matrix.checker_timeout }}",
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"matrix\.lemmas"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_expected_command_hidden_in_comment(tmp_path: Path) -> None:
    """Round-2 review probe: the expected matrix command kept in a YAML COMMENT
    while the live step hard-codes a shard must fail — the assertion must read
    only live (non-comment) lines."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        "# " + expected + "\n        run: python3 tools/check_formal.py "
        "formal/attest.spthy --only sanity_toolchain "
        "--timeout ${{ matrix.checker_timeout }}",
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"matrix\.lemmas"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_expected_command_hidden_in_env_value(tmp_path: Path) -> None:
    """Round-3 review probe: the expected matrix command parked in an unused
    folded ``env:`` value while the live run step hard-codes a shard must fail —
    only ``run:`` scalars count, never other keys' values."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        "env:\n          UNUSED_NOTE: >-\n            "
        + expected
        + "\n        run: python3 tools/check_formal.py formal/attest.spthy "
        "--only sanity_toolchain --timeout ${{ matrix.checker_timeout }}",
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"matrix\.lemmas"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_check_survives_block_scalar_run(tmp_path: Path) -> None:
    """A refactor to ``run: |`` must not blind the check: the command body on
    continuation lines is still the step's executable scalar."""
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "jobs:\n"
        "  formal:\n"
        "    steps:\n"
        "      - name: proofs\n"
        "        run: |\n"
        "          python3 tools/check_formal.py formal/attest.spthy"
        ' --only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}\n',
        encoding="utf-8",
    )
    assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_disabled_step_with_command_in_env(tmp_path: Path) -> None:
    """Round-4 review probe: the expected command parked inside an env folded
    scalar (its body itself spelling ``run: ...``) while the REAL step runs a
    bare ``echo`` must fail — only ``jobs.formal.steps[].run`` values count."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        "env:\n          UNUSED_NOTE: >-\n            "
        + expected
        + '\n        run: echo "formal checker disabled"',
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"check_formal\.py"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_if_gated_job(tmp_path: Path) -> None:
    """Round-5 review probe: an ``if:`` gate on the formal job (e.g. only on
    workflow_dispatch, which push/PR triggers never fire) silently skips every
    proof. Accidental gating must fail loudly."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "\n  formal:\n" in source
    poisoned = source.replace(
        "\n  formal:\n",
        "\n  formal:\n    if: github.event_name == 'workflow_dispatch'\n",
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"if: gate"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_command_only_in_shell_comment(tmp_path: Path) -> None:
    """Round-5 review probe: a ``run: |`` whose only mention of the expected
    command is a SHELL comment line, followed by a bare echo, must fail —
    comment lines are stripped from the script before the assertions."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        "run: |\n          # "
        + expected.removeprefix("run: ")
        + '\n          echo "formal checker disabled"',
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"check_formal\.py"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_command_in_trailing_shell_comment(tmp_path: Path) -> None:
    """Round-6 review probe (I7): the expected command surviving only as a
    TRAILING shell comment after a live echo must fail — trailing ``#``
    fragments are stripped too, not just full comment lines. The probe needs
    a ``run: |`` BLOCK scalar: in a plain scalar ``#`` already starts a YAML
    comment and never reaches the run value."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(
        expected,
        'run: |\n          echo "disabled" # ' + expected.removeprefix("run: "),
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"check_formal\.py"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_continue_on_error(tmp_path: Path) -> None:
    """Round-6 review probe (I8): ``continue-on-error: true`` on the formal
    job would let failed proofs produce a green gate — must fail loudly."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "\n  formal:\n" in source
    poisoned = source.replace(
        "\n  formal:\n",
        "\n  formal:\n    continue-on-error: true\n",
        1,
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"continue-on-error"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_job_rejects_or_true_fallback(tmp_path: Path) -> None:
    """Round-6 review probe (I8): a ``|| true`` suffix on the checker command
    would swallow its exit code — no ``||`` fallback is allowed in the
    checker script."""
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "run: python3 tools/check_formal.py formal/attest.spthy "
        '--only "${{ matrix.lemmas }}" --timeout ${{ matrix.checker_timeout }}'
    )
    assert expected in source
    poisoned = source.replace(expected, expected + " || true", 1)
    workflow = tmp_path / "ci.yml"
    workflow.write_text(poisoned, encoding="utf-8")

    with pytest.raises(AssertionError, match=r"\|\|"):
        assert_ci_formal_job_executes_matrix(workflow)


def test_ci_formal_shard_lists_are_pairwise_disjoint() -> None:
    shards = ci_formal_shards()
    names = [name for lemmas in shards.values() for name in lemmas]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    assert not duplicated, f"lemmas assigned to more than one CI shard: {duplicated}"


def test_ci_formal_shard_union_equals_contract() -> None:
    shards = ci_formal_shards()
    union = {name for lemmas in shards.values() for name in lemmas}
    missing = sorted(set(cf.CONTRACT) - union)
    extra = sorted(union - set(cf.CONTRACT))
    assert union == set(cf.CONTRACT), (
        f"CI shard union != CONTRACT — missing from shards: {missing}; not in CONTRACT: {extra}"
    )


def test_ci_formal_shards_rejects_duplicate_entry(tmp_path: Path) -> None:
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    duplicate = (
        "          - shard: heavy-revdowngrade\n"
        "            timeout: 120\n"
        "            checker_timeout: 6900\n"
        '            lemmas: "no_downgrade_revocation_allhybrid"\n'
    )
    needle = '            lemmas: "no_downgrade_revocation_allhybrid"\n'
    mutated = source.replace(needle, needle + duplicate, 1)
    workflow = tmp_path / "ci.yml"
    workflow.write_text(mutated, encoding="utf-8")

    with pytest.raises(AssertionError, match="exactly 5 shard entries"):
        ci_formal_shards(workflow)


def test_ci_formal_shards_rejects_missing_formal_job(tmp_path: Path) -> None:
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    source = source.replace("  formal:\n", "  formal_renamed:\n", 1)
    workflow = tmp_path / "ci.yml"
    workflow.write_text(source, encoding="utf-8")

    with pytest.raises(AssertionError, match="formal job block absent"):
        ci_formal_shards(workflow)


def test_ci_parser_counts_raw_markers_against_parsed_entries(tmp_path: Path) -> None:
    # A fifth matrix entry with a DIFFERENT field order must fail loudly, not
    # silently vanish from the strict entry regex (round-2 reviewer probe).
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    reordered = (
        "          - shard: sneaky-fifth\n"
        '            lemmas: "sanity_toolchain"\n'
        "            timeout: 90\n"
        "            checker_timeout: 5100\n"
    )
    # Insert INSIDE the formal job block (a bare `steps:` anchor would hit the
    # FIRST job in the file, leaving the formal block untouched).
    head, formal_tail = text.split("\n  formal:\n", 1)
    poisoned = (
        head + "\n  formal:\n" + formal_tail.replace("    steps:\n", reordered + "    steps:\n", 1)
    )
    assert "sneaky-fifth" in poisoned
    bad = tmp_path / "ci.yml"
    bad.write_text(poisoned, encoding="utf-8")
    with pytest.raises(AssertionError, match="list items"):
        ci_formal_shards(bad)


@pytest.mark.parametrize(
    "fifth",
    [
        # Alternative YAML spellings the strict entry regex does NOT match —
        # each is still one matrix list item, so the item-count guard fires
        # (round-3 reviewer probe: `shard :`, quoted key, flow map).
        "          - shard : sneaky-fifth\n            timeout: 90\n"
        '            checker_timeout: 5100\n            lemmas: "sanity_toolchain"\n',
        '          - "shard": sneaky-fifth\n            timeout: 90\n'
        '            checker_timeout: 5100\n            lemmas: "sanity_toolchain"\n',
        "          - {shard: sneaky-fifth, timeout: 90, checker_timeout: 5100,"
        ' lemmas: "sanity_toolchain"}\n',
        '          -\n            "shard": sneaky-fifth\n            timeout: 90\n'
        '            checker_timeout: 5100\n            lemmas: "sanity_toolchain"\n',
        "          -\n            shard: sneaky-fifth\n            timeout: 90\n"
        '            checker_timeout: 5100\n            lemmas: "sanity_toolchain"\n',
        pytest.param(
            "        # comment\n"
            '            -\n              "shard": sneaky-fifth\n              timeout: 90\n'
            '              checker_timeout: 5100\n              lemmas: "sanity_toolchain"\n',
            id="comment-then-quoted",
        ),
        pytest.param(
            "          - shard: sneaky-fifth\n"
            "            timeout: 90\n"
            "        # note\n"
            '            checker_timeout: 5100\n            lemmas: "sanity_toolchain"\n',
            id="comment-inside-entry",
        ),
    ],
)
def test_ci_parser_catches_fifth_shard_in_any_spelling(tmp_path: Path, fifth: str) -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    head, formal_tail = text.split("\n  formal:\n", 1)
    poisoned = (
        head + "\n  formal:\n" + formal_tail.replace("    steps:\n", fifth + "    steps:\n", 1)
    )
    assert "sneaky-fifth" in poisoned
    bad = tmp_path / "ci.yml"
    bad.write_text(poisoned, encoding="utf-8")
    with pytest.raises(AssertionError):
        ci_formal_shards(bad)
