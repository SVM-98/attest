"""Fail-closed gate for the Tamarin formal-verification corpus.

Pins the ENTIRE lemma corpus of ``formal/attest.spthy`` by *statement digest*
(sha256 of the quote-aware comment-stripped, whitespace-collapsed lemma block), not by
name: a renamed, weakened, trait-flipped or annotation-edited lemma fails the
gate even when the prover reports ``verified``. Also pins its toolchain
(fail-closed ``tamarin-prover --version`` and ``maude --version`` assertions)
— a digest contract is worthless if the interpreters underneath it can drift.
Valid invocations assert both versions before inspecting a theory or summary;
argparse usage errors return exit 2 before those assertions.

Stdlib only. Run: ``python tools/check_formal.py formal/attest.spthy``.
Tests inject ``--summary-file`` / ``--theory-file`` / ``--prover`` / ``--maude``
and never touch the real prover or Maude binary.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path


class TheoryError(Exception):
    """Raised when a lemma block cannot be extracted from theory source.

    Covers a lemma name that is missing from the theory and a lemma name
    declared more than once — both gate failures in ``main`` (fail closed).
    """


class SummaryError(Exception):
    """Raised when a Tamarin ``summary of summaries`` block cannot be trusted.

    Covers: missing block, empty block, a duplicate lemma name, or a status
    line inside the block that does not parse — all treated as gate failures
    by ``main`` (fail closed, never a skip).
    """


# One Tamarin result line: ``  name (trait): status (N steps)``.
# `- found trace` is a FALSIFIED suffix only: `verified - found trace` is a
# contradictory line and must be a SummaryError, never a green verdict.
_STATUS_RE = re.compile(
    r"^\s*(\w+)\s*\((all-traces|exists-trace)\):\s*"
    r"(verified|falsified(?:\s+-\s+found\s+trace)?|analysis incomplete)"
    r"(?:\s+\(\d+\s+steps?\))?\s*$"
)
# Non-result lines that legitimately appear inside the summary block.
_SUMMARY_NOISE_RE = re.compile(r"^\s*$|^analyzed:|^\s*processing time:|^=+$")
# Anything else inside the block is an unparseable status line -> SummaryError.


def parse_summary(text: str) -> dict[str, tuple[str, str]]:
    """Parse a Tamarin ``summary of summaries`` block.

    Returns a mapping ``lemma name -> (trait, result)`` where trait is
    ``all-traces``/``exists-trace`` and result is ``verified``/``falsified``/
    ``analysis incomplete``.

    Raises:
        SummaryError: if the block is missing or empty, a lemma name appears
            twice, or any non-noise line inside the block fails to parse.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == "summary of summaries:")
    except StopIteration:
        raise SummaryError("no 'summary of summaries:' block found") from None

    results: dict[str, tuple[str, str]] = {}
    for line in lines[start + 1 :]:
        if _SUMMARY_NOISE_RE.match(line):
            continue
        m = _STATUS_RE.match(line)
        if m is None:
            raise SummaryError(f"unparseable status line in summary: {line!r}")
        name, trait, result = m.group(1), m.group(2), m.group(3)
        if result.startswith("falsified"):
            result = "falsified"  # collapse the optional `- found trace` suffix
        if name in results:
            raise SummaryError(f"duplicate lemma in summary: {name}")
        results[name] = (trait, result)

    if not results:
        raise SummaryError("empty 'summary of summaries' block")
    return results


def _normalize_source(src: str) -> str:
    """Strip comments and normalize outside-quote whitespace in ``src``.

    Tamarin single-quoted constants are copied verbatim, including whitespace
    and comment-looking text. Outside them, ``/* ... */`` and ``// ...``
    comments are removed and every whitespace run becomes one space.

    Raises:
        TheoryError: if a quote or block comment is unterminated.
    """
    out: list[str] = []
    index = 0
    in_quote = False
    pending_space = False

    def emit(char: str) -> None:
        nonlocal pending_space
        if pending_space and out:
            out.append(" ")
        out.append(char)
        pending_space = False

    quote_span: list[str] = []
    while index < len(src):
        char = src[index]
        if in_quote:
            # Empirically pinned against tamarin-prover 1.12.0 --parse-only
            # (2026-07-22 probes): a newline inside a quoted constant is
            # rejected by Tamarin; comment markers inside quotes interact
            # with parsec backtracking in ways no scanner can faithfully
            # replicate ('a/*x*/b' parses VERBATIM, '/*' makes the comment
            # skipper eat the rest of the file, 'https://one' is valid).
            # REFUSE both cases outright: a loud TheoryError is fail-closed;
            # a silently divergent digest is not. No real theory quotes
            # comment markers (the shipped corpus has 43 quoted constants,
            # all plain identifiers) — this conservatively rejects some
            # Tamarin-valid oddities, and says so, rather than guessing.
            if char == "\n":
                raise TheoryError("newline inside quoted constant in theory source")
            if char == "'":
                span = "".join(quote_span)
                if "/*" in span or "*/" in span or "//" in span:
                    raise TheoryError(
                        "comment marker inside quoted constant -- refusing to "
                        "normalize (Tamarin lexer ambiguity): '" + span + "'"
                    )
                out.append(char)
                in_quote = False
            else:
                quote_span.append(char)
                out.append(char)
            index += 1
            continue
        if char == "'":
            emit(char)
            in_quote = True
            quote_span = []
            index += 1
            continue
        if src.startswith("/*", index):
            # Tamarin 1.12.0 NESTS block comments (Haskell lexer heritage):
            # `/* a /* b */ c */` is ONE comment, and `/* a /* b */` is
            # UNTERMINATED. The scanner must agree with the prover's lexer,
            # or a file Tamarin rejects could normalize green.
            pending_space = pending_space or bool(out)
            depth = 1
            index += 2
            while index < len(src) and depth:
                if src.startswith("/*", index):
                    depth += 1
                    index += 2
                elif src.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise TheoryError("unterminated block comment in theory source")
            continue
        if src.startswith("//", index):
            pending_space = pending_space or bool(out)
            index += 2
            while index < len(src) and src[index] != "\n":
                index += 1
            if index < len(src):
                index += 1
            continue
        if char.isspace():
            pending_space = pending_space or bool(out)
            index += 1
            continue
        emit(char)
        index += 1
    if in_quote:
        raise TheoryError("unterminated quote in theory source")
    return "".join(out)


def _is_word_char(char: str) -> bool:
    """Return whether ``char`` can occur in a Tamarin declaration name."""
    return char == "_" or char.isalnum()


def _outside_keyword_positions(src: str, keywords: set[str]) -> list[tuple[str, int]]:
    """Return keyword positions in normalized ``src``, excluding quoted spans."""
    positions: list[tuple[str, int]] = []
    index = 0
    in_quote = False
    while index < len(src):
        if src[index] == "'":
            in_quote = not in_quote
            index += 1
            continue
        if in_quote or not (index == 0 or not _is_word_char(src[index - 1])):
            index += 1
            continue
        for keyword in keywords:
            end = index + len(keyword)
            if src.startswith(keyword, index) and (end == len(src) or not _is_word_char(src[end])):
                positions.append((keyword, index))
                index = end
                break
        else:
            index += 1
    return positions


def _lemma_declarations(src: str) -> list[tuple[str, int]]:
    """Return ``(name, offset)`` pairs for lemma declarations outside quotes."""
    declarations: list[tuple[str, int]] = []
    for keyword, start in _outside_keyword_positions(src, {"lemma"}):
        assert keyword == "lemma"
        name_start = start + len(keyword)
        while name_start < len(src) and src[name_start].isspace():
            name_start += 1
        name_end = name_start
        while name_end < len(src) and _is_word_char(src[name_end]):
            name_end += 1
        if name_end > name_start:
            declarations.append((src[name_start:name_end], start))
    return declarations


def normalize_lemma(src: str, name: str) -> str:
    """Return the canonical text of the named lemma block from theory source.

    Comments are stripped and all whitespace is collapsed to single spaces, so
    the result is INSENSITIVE to comment edits and reflow but SENSITIVE to any
    token change in the formula, the trait (``all-traces``/``exists-trace``)
    or the annotations (``[reuse]``, ``[use_induction]``).

    Raises:
        TheoryError: if the lemma is missing or declared more than once.
    """
    normalized = _normalize_source(src)
    matches = [start for declared, start in _lemma_declarations(normalized) if declared == name]
    if not matches:
        raise TheoryError(f"lemma {name!r} not found in theory source")
    if len(matches) > 1:
        raise TheoryError(f"lemma {name!r} declared {len(matches)} times in theory source")
    start = matches[0]
    anchors = _outside_keyword_positions(normalized, {"lemma", "rule", "restriction", "end"})
    end = next((offset for _, offset in anchors if offset > start), len(normalized))
    return normalized[start:end].rstrip()


def lemma_digest(src: str, name: str) -> str:
    """Return the sha256 hex digest of the named lemma's normalized text.

    Raises:
        TheoryError: if the lemma is missing or declared more than once.
    """
    return hashlib.sha256(normalize_lemma(src, name).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The pinned contract: the ENTIRE lemma corpus of formal/attest.spthy at
# branch feature/p1.3-formal-verification HEAD 87a234d (T6 final) -- 45 lemma
# declarations, name -> {trait, digest}. Digests are sha256 of the quote-aware
# normalized statement (this module's own lemma_digest over the real theory source).
# Regenerate after an INTENDED statement change with:
#   python -c "from tools import check_formal as cf; import pathlib; \
#     src=pathlib.Path('formal/attest.spthy').read_text(); \
#     [print(n, cf.lemma_digest(src,n)) for n, _ in \
#      cf._lemma_declarations(cf._normalize_source(src))]"
# ---------------------------------------------------------------------------
CONTRACT: dict[str, dict[str, str]] = {
    "sanity_toolchain": {
        "trait": "exists-trace",
        "digest": "0f505dd5175dfc17d8c7e2057088734f27ad353cebe06d8f106fb4ef2e84d827",
    },
    "sanity_v01_accept": {
        "trait": "exists-trace",
        "digest": "76ec4cd52f9e05c5d02c71da5a948e7d4188833fc5156dbe7562b333ccc0a6c2",
    },
    "sanity_rotate_then_accept": {
        "trait": "exists-trace",
        "digest": "3cec007420f73f02ae79cd15527897f46bed128f7c78049b32596fd462b32af7",
    },
    "sanity_mixed_keyset": {
        "trait": "exists-trace",
        "digest": "4ebeb34537fdeb5e3083f8d71cb428c2b0bd3bb94b3423c7571a6fe73d0bec59",
    },
    "sanity_kid_bound_accept": {
        "trait": "exists-trace",
        "digest": "061507ffad72f3e7106031010adf6a02a45d88252d8e73b04c24715a120b8e18",
    },
    "sanity_retired_key_receipt_still_accepts": {
        "trait": "exists-trace",
        "digest": "0bc27236a5ef93f7e59f030ee725b14afefb0bc15b1a21fd1d0e66510e27ccd3",
    },
    "sanity_slot2_issue_and_compromise": {
        "trait": "exists-trace",
        "digest": "a610db52c87a0df0c4bd4c46cccf086fc9bde3a76527088bc95de5f59f655bec",
    },
    "sanity_attacker_distinct_mid": {
        "trait": "exists-trace",
        "digest": "a4892ef487ee682b536c6eeb2d551b05919a9b3170b01c3f8240f3040c169251",
    },
    "sanity_same_version_conflict": {
        "trait": "exists-trace",
        "digest": "db7127907d95f596f52bab13e1abb15ff8afa2ed340e5b9d755c7f38bfb7bcc4",
    },
    "sanity_continuity_advance": {
        "trait": "exists-trace",
        "digest": "fff830800d001020431cb1b88899159c0123b74d9a0d79ad66b8413a8baab194",
    },
    "sanity_accept_after_advance": {
        "trait": "exists-trace",
        "digest": "4a6a78a55fb520b2997308b1e15b983cd72425f19b13cd20e72ea9c7b6e9898f",
    },
    "sanity_multihop_advance_compromise": {
        "trait": "exists-trace",
        "digest": "623ff83f5c89188bc8f9639d89d09554a22f91edeca076ff2de9cd2fd018718f",
    },
    "sanity_hybrid_accept": {
        "trait": "exists-trace",
        "digest": "af9ad16f5af95da8b257628fae7ffa4d712fc59da26e5a863c48d19d211a98f5",
    },
    "reach_rotation_nonactive_signer_flagged": {
        "trait": "exists-trace",
        "digest": "9c89002063f1a3a6e620cc3f91d2ed8b995ab7e7de7b290bc34fe8608b8cd414",
    },
    "reach_rotation_same_version_flagged": {
        "trait": "exists-trace",
        "digest": "7dd974baf18834986212f228f497ed9914721ad14a5a91b18b3afbb3662af1d1",
    },
    "reach_rotation_gap_flagged": {
        "trait": "exists-trace",
        "digest": "6a9f715bcf52f98b6e89e73f7e3703984a5ad037e7cd0854cf8afd5ab466145d",
    },
    "reach_compromised_receipt_submitted": {
        "trait": "exists-trace",
        "digest": "0ebe5a124ee69f07e5d92629494f7c30ce30a52e1410c285397ca42fadf9baae",
    },
    "verified_clean_head_honest": {
        "trait": "all-traces",
        "digest": "7f8a5df28db63b8e1cbc77a1eb54cb7fbadde63b1934f199616a0e39fd26ae34",
    },
    "rotation_no_hijack": {
        "trait": "all-traces",
        "digest": "25974c3ff111b35658b9bd838823b1d7f656284a7bb2ba47d9abcc6d7d03647b",
    },
    "compromised_key_rejected": {
        "trait": "all-traces",
        "digest": "e2f3ddd9f4b0f351d4e2b59e316cac7c2d6e6806244af8b2a74daa4020a07c61",
    },
    "acceptance_issuer_signed": {
        "trait": "all-traces",
        "digest": "9946f6ba019a6d058c353ac3469f008040b510fd41b0a6407c6616974a1cbbf7",
    },
    "old_key_powerless": {
        "trait": "all-traces",
        "digest": "a039d2a38f73c0b62ed5ebc69cc8419b985640780841dad8dad4304fa65f9cbd",
    },
    "sanity_revocation_honored": {
        "trait": "exists-trace",
        "digest": "92727dbf51b7c53d836b5b25f0e684c98077333d1c89fa5710df90a2c7897627",
    },
    "sanity_none_ignored": {
        "trait": "exists-trace",
        "digest": "0dcb3e020ad42c03c394ad9ff45532ae12bf23faee87f20df7fb9d141ac8484e",
    },
    "sanity_issued_receipt_revoked": {
        "trait": "exists-trace",
        "digest": "d7c54864cf3d44b810f509383be329125760f61346fcaca457f5e71f8a3a79d3",
    },
    "reach_refund_window_honored": {
        "trait": "exists-trace",
        "digest": "24beee27dfb02677c5bbcdbb7a2746cea5002e6b8da20dee7828aacdd698f3f3",
    },
    "reach_revocation_out_of_window": {
        "trait": "exists-trace",
        "digest": "21a625642b13c3214a509847fe2082a35b646b75b52e9de81eeeebe2022a6202",
    },
    "rev_record_authentic": {
        "trait": "all-traces",
        "digest": "839067e74de8d17d6d4bbb31d29b95eefaeb31d614ec47e646908f9692998b18",
    },
    "revocation_auth_soundness": {
        "trait": "all-traces",
        "digest": "64085f87a9eb88ceda7f1751dbf66068978149b90c9a94b9f39c9809763c2d94",
    },
    "revocation_effectiveness": {
        "trait": "all-traces",
        "digest": "b12b159688c58a04d328d2c08053a934110a219db4c6547ae53c8dffc50f83a1",
    },
    "irrevocability_none": {
        "trait": "all-traces",
        "digest": "32642d434fec768a7cc7776fbbe7fb94cb038322049cfcceb829e0ad104074b6",
    },
    "refund_window_bound": {
        "trait": "all-traces",
        "digest": "f49f41908ccb324605adb6dc4afc61a328a32f9378a9e821c2823ede327df4f8",
    },
    "revoked_view_never_ok": {
        "trait": "all-traces",
        "digest": "96f5025ffdb804b751f577d8148c58167a6b71201f7e1183017e5289338d5826",
    },
    "attack_tofu_revocation_forgery": {
        "trait": "exists-trace",
        "digest": "860d78a4e03be6962264d234fe77d0e63101bb855820f1d210fb561ce3bd4c19",
    },
    "pq_receipt_sig_source": {
        "trait": "all-traces",
        "digest": "39b63c408b48897a0d8fa2e60da8856adfc973c6c67849a5e8b1c9094c49f139",
    },
    "no_cross_version_confusion": {
        "trait": "all-traces",
        "digest": "4f08a53ba5b14f35b1510dfa2ce6d975eb6140c6351898d8e14fe43cc7704fdd",
    },
    "attack_v01_post_crqc": {
        "trait": "exists-trace",
        "digest": "3e6ad998159728743515b2835f67dfafbeece586e9e4ec1e9d71dcbcf4730a8e",
    },
    "attack_tofu_forgery": {
        "trait": "exists-trace",
        "digest": "992f062411779a31c65dd05e7437baec294d3c8dd30e0a5c5288603dec4c1dcc",
    },
    "attack_mixed_keyset_hijack": {
        "trait": "exists-trace",
        "digest": "566b95782599869855d9afd3213cfc2777a7d67251de53ad681f4d030a5b2216",
    },
    "sanity_artifact_manifest_accept": {
        "trait": "exists-trace",
        "digest": "a953c7a9d8a4a9b278b9d2168ab373df2392ae388aa5ea0ed44cf0a03af3e5cf",
    },
    "am_pq_sig_source": {
        "trait": "all-traces",
        "digest": "a50e01dc4d1e0934412f543618269b5a6005ce7816cf232c0eb08d92e5d0db67",
    },
    "no_downgrade_artifact_manifest": {
        "trait": "all-traces",
        "digest": "69e04a84eb2c98407bc49006d1bb04ce99d08398bc72ab52b093773341696e73",
    },
    "sanity_hybrid_revocation_admitted": {
        "trait": "exists-trace",
        "digest": "adebbffb7fac732246e682b151a19aa930ac937f446cd648c22a5089f10e97e7",
    },
    "rev_pq_sig_source": {
        "trait": "all-traces",
        "digest": "13693f1c22dc40dd2d48d9f5da8851c465273427fb492bcac24b6f66c62cb1cf",
    },
    "no_downgrade_revocation_allhybrid": {
        "trait": "all-traces",
        "digest": "0c22355bf2ea8e96e5e3de6ad0b31c9ebe8453c11294e3912489fddb70faaf3f",
    },
}


# Pinned toolchain — the SINGLE source of truth for the required prover
# versions (formal/README.md documents them, CI installs them, nothing else
# restates them). The statement digests above are only meaningful under this
# exact interpreter: the same theory under a different Tamarin can yield a
# different verdict, so a version drift is the same failure class as a digest
# mismatch.
TAMARIN_VERSION = "1.12.0"
MAUDE_VERSION = "3.5.1"

# Tamarin's default derivation-check timeout (5s) expires on this theory: the
# summary then carries "WARNING: 1 wellformedness check failed!" and the gate
# fails closed (measured 2026-07-22: default → WF warning; 20s → all checks
# pass). Every T3-T6 measurement ran with an explicit timeout, so the gate
# pins one too. 60s = 3x the empirically clean 20s, headroom for slower CI
# runners; derivation checks are deterministic, a larger timeout only adds
# margin, never weakens the check.
DERIVCHECK_TIMEOUT_S = 60

_TAMARIN_VERSION_RE = re.compile(r"tamarin-prover\s+(\d+(?:\.\d+)+)")
_BARE_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)+)")


def _parse_tamarin_version(stdout: str) -> str | None:
    """Extract the Tamarin version from multi-line ``--version`` output."""
    m = _TAMARIN_VERSION_RE.search(stdout)
    return m.group(1) if m else None


def _parse_maude_version(stdout: str) -> str | None:
    """Extract the Maude version, accepting ONLY the two known shapes.

    The real ``maude --version`` prints the bare version string and nothing
    else ("3.5.1"); a hypothetical verbose form ``maude X.Y.Z`` (exact tool
    token) is also accepted. Anything looser — a stray version-looking line
    inside junk, a different tool name wrapping a version — must stay
    unparseable: a wrong binary must never false-green the pin.
    """
    text = stdout.strip()
    m = _BARE_VERSION_RE.fullmatch(text)
    if m:
        return m.group(1)
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) == 2 and tokens[0].lower() == "maude":
            m = _BARE_VERSION_RE.fullmatch(tokens[1])
            if m:
                return m.group(1)
    return None


def _fail(msg: str) -> None:
    """Print a gate failure line to stderr."""
    print(f"check_formal: FAIL: {msg}", file=sys.stderr)


def _assert_version(
    binary: str, timeout: float, expected: str, parse: Callable[[str], str | None], tool: str
) -> bool:
    """Fail-closed assertion that ``binary --version`` reports ``expected``.

    Returns True only when the reported version equals the requested pin.
    A missing binary, a non-zero exit, or unparseable output is a failure,
    never a skip.
    """
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
            [binary, "--version"], capture_output=True, text=True, timeout=timeout, check=False
        )
    except OSError as exc:
        _fail(f"cannot run {binary!r} --version: {exc}")
        return False
    except subprocess.TimeoutExpired:
        _fail(f"{binary!r} --version timed out after {timeout}s")
        return False
    if proc.returncode != 0:
        _fail(f"{binary!r} --version exited {proc.returncode}")
        return False
    found = parse(proc.stdout)
    if found is None:
        _fail(f"unparseable {binary!r} --version output: {proc.stdout[:200]!r}")
        return False
    if found != expected:
        _fail(f"{tool} version mismatch: pinned {expected}, installed {found}")
        return False
    return True


def _assert_prover_version(prover: str, timeout: float) -> bool:
    """Assert that the configured Tamarin binary reports the pinned version."""
    return _assert_version(prover, timeout, TAMARIN_VERSION, _parse_tamarin_version, "prover")


def _assert_maude_version(maude: str, timeout: float) -> bool:
    """Assert that the configured Maude binary reports the pinned version."""
    return _assert_version(maude, timeout, MAUDE_VERSION, _parse_maude_version, "maude")


def _run_prover(prover: str, theory: str, only: list[str] | None, timeout: float) -> str | None:
    """Run the prover and return its stdout, or None on any failure.

    Without a shard, proves the whole theory (``--prove``); with a shard,
    proves only the named lemmas (``--prove=<name>`` per lemma). A missing
    binary, non-zero exit, or timeout all return None (fail closed in main).
    """
    prove_args = [f"--prove={n}" for n in only] if only else ["--prove"]
    cmd = [prover, *prove_args, f"--derivcheck-timeout={DERIVCHECK_TIMEOUT_S}", theory]
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except OSError as exc:
        _fail(f"cannot run prover {prover!r}: {exc}")
        return None
    except subprocess.TimeoutExpired:
        _fail(f"prover timed out after {timeout}s: {' '.join(cmd)}")
        return None
    if proc.returncode != 0:
        _fail(f"prover exited {proc.returncode}: {' '.join(cmd)}")
        return None
    return proc.stdout


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed formal-proof gate. Returns a process exit code.

    0 = every scoped lemma is present and ``verified`` with the pinned trait,
    AND every CONTRACT lemma's statement digest matches the theory source.
    1 = any gate failure (mismatch, missing, extra, prover error, bad summary).
    2 = usage error (invalid ``--only`` scope or injection-only option use).
    """
    parser = argparse.ArgumentParser(
        prog="check_formal",
        description="Fail-closed Tamarin proof gate: pins lemma statement digests.",
    )
    parser.add_argument("theory", nargs="?", default="formal/attest.spthy")
    parser.add_argument("--summary-file", help="parse this summary instead of running the prover")
    parser.add_argument(
        "--theory-file",
        help="injection-only theory source (requires --summary-file)",
    )
    parser.add_argument("--prover", default="tamarin-prover", help="prover command to invoke")
    parser.add_argument("--maude", default="maude", help="Maude command to version-check")
    parser.add_argument(
        "--only",
        help="comma-separated shard: restrict RESULT assertions to these lemmas "
        "(statement digests are always checked over the full contract)",
    )
    parser.add_argument("--timeout", type=float, default=3600.0, help="prover timeout, seconds")
    args = parser.parse_args(argv)

    if args.theory_file is not None and args.summary_file is None:
        _fail("--theory-file is only valid together with --summary-file")
        return 2

    if args.only is not None:
        scope = [n.strip() for n in args.only.split(",") if n.strip()]
        if not scope:
            _fail("--only must name at least one CONTRACT lemma")
            return 2
        unknown = sorted(set(scope) - set(CONTRACT))
        if unknown:
            _fail(f"--only names not in CONTRACT: {', '.join(unknown)}")
            return 2
    else:
        scope = list(CONTRACT)

    # Toolchain pins come first: no result below is meaningful under a
    # different interpreter. Both assertions run on every valid invocation,
    # including the --summary-file injection path.
    version_timeout = min(args.timeout, 60.0)
    prover_ok = _assert_prover_version(args.prover, timeout=version_timeout)
    maude_ok = _assert_maude_version(args.maude, timeout=version_timeout)
    if not prover_ok or not maude_ok:
        return 1

    # --theory-file is injection-only (guarded above to require --summary-file);
    # --summary-file WITHOUT --theory-file digests the positional theory.
    theory_path = Path(args.theory_file) if args.theory_file is not None else Path(args.theory)
    try:
        src = theory_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot read theory source {str(theory_path)!r}: {exc}")
        return 1

    failures = 0
    try:
        theory_declarations = {name for name, _ in _lemma_declarations(_normalize_source(src))}
    except TheoryError as exc:
        _fail(str(exc))
        return 1
    theory_only = sorted(theory_declarations - set(CONTRACT))
    contract_only = sorted(set(CONTRACT) - theory_declarations)
    if theory_only:
        _fail(f"theory declares lemmas not in CONTRACT: {', '.join(theory_only)}")
        failures += 1
    if contract_only:
        _fail(f"CONTRACT declares lemmas absent from theory: {', '.join(contract_only)}")
        failures += 1

    # Statement pinning is GLOBAL: every contract lemma, regardless of shard.
    for name, entry in CONTRACT.items():
        try:
            digest = lemma_digest(src, name)
        except TheoryError as exc:
            _fail(str(exc))
            failures += 1
            continue
        if digest != entry["digest"]:
            _fail(
                f"statement digest mismatch for {name}: pinned {entry['digest']} != actual {digest}"
            )
            failures += 1

    if args.summary_file is not None:
        try:
            summary_text = Path(args.summary_file).read_text(encoding="utf-8")
        except OSError as exc:
            _fail(f"cannot read summary file {args.summary_file!r}: {exc}")
            return 1
    else:
        maybe = _run_prover(
            args.prover, str(theory_path), scope if args.only is not None else None, args.timeout
        )
        if maybe is None:
            return 1
        summary_text = maybe

    try:
        results = parse_summary(summary_text)
    except SummaryError as exc:
        _fail(str(exc))
        return 1

    # Drift: a lemma the contract does not know about is a failure, always.
    for name in results:
        if name not in CONTRACT:
            _fail(f"summary reports lemma not in CONTRACT: {name}")
            failures += 1

    # A summary may include results beyond a shard's required presence set,
    # but none of those results may be non-verified contract lemmas.
    for name, (_, result) in results.items():
        if name in CONTRACT and result != "verified":
            _fail(f"lemma {name} is not verified: {result}")
            failures += 1

    # Result assertions, scoped to the shard (or the whole corpus).
    for name in scope:
        if name not in results:
            _fail(f"pinned lemma missing from summary: {name}")
            failures += 1
            continue
        trait, result = results[name]
        if trait != CONTRACT[name]["trait"]:
            _fail(f"trait mismatch for {name}: pinned {CONTRACT[name]['trait']}, summary {trait}")
            failures += 1

    if failures:
        _fail(f"{failures} assertion(s) failed")
        return 1
    print(f"check_formal: OK ({len(scope)}/{len(CONTRACT)} lemmas verified, all digests pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
