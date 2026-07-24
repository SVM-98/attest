# attest Internet-Draft — build toolchain

This directory carries the IETF Internet-Draft source for attest:
`draft-martinalli-open-purchase-receipts.xml` (docname
`draft-martinalli-open-purchase-receipts-00`). This document is a
**snapshot profile**: it distills the core receipt format and hybrid
signature profile from the living, normative specification
(`docs/spec/attest-v0.1.md`, `docs/spec/attest-v0.2.md`) into Internet-Draft
form. The living specification remains the normative source of truth; the
draft's own "Relationship to the living specification" subsection (§1.1)
declares exactly which revision of each file it mirrors.

## Toolchain decision: xml2rfc v3 XML, hand-authored (fallback path)

The plan's primary path was `kramdown-rfc` (Ruby) generating xml2rfc v3 XML,
which `xml2rfc` then builds to text/HTML. That path is **unavailable in this
local sandbox**: the system Ruby is `2.6.10` (`ruby -v`) and `gem install` is
blocked by the sandbox's network/filesystem policy — there is no path to
install `kramdown-rfc` here. Per the plan's own fallback clause, the draft is
therefore **hand-authored directly as xml2rfc v3 XML**
(`draft-martinalli-open-purchase-receipts.xml`), and only the `xml2rfc` pin
remains in the toolchain. There is no `.md` source for this draft; the `.xml`
file is authoritative.

**Pinned builder: `xml2rfc==3.34.0`**, run via `uvx` (no separate install
step; `uvx` resolves and caches the pinned version on first use). Verified
live end-to-end, twice, in this sandbox — see "Build" below.

## Inline references, not `xi:include` — deliberately

Every citation in the draft (`RFC2119`, `RFC8174`, `RFC8785`, `RFC8032`,
`RFC4648`, `RFC9334`, `RFC9943`, `RFC7515`, `RFC9052`, `FIPS204`,
`W3C.VC-DATA-MODEL`, `C2PA`, `ATTEST-REPO`) is a full inline `<reference>`
element inside `<references>` — never an `xi:include` pulling from
`bib.ietf.org`. `bib.ietf.org` is outside the network this sandbox allows,
and inline references make the RENDER step deterministic and reproducible
with no network access at all, in any environment — distinct from the
one-time pinned-toolchain install above (`uvx --from xml2rfc==3.34.0`),
which MAY fetch the package from PyPI the first time it runs in a given
environment (cached thereafter, per `uv`'s own resolver, and not repeated
on a subsequent invocation). The build command below passes `--no-network`
to the `xml2rfc` render step itself to make that narrower claim a verified
property, not an assumption: both local builds below completed with
`--no-network` and zero network calls made *by xml2rfc's own reference
resolution* — the property inline references exist to guarantee.

## Build

The local sandbox's default `uv` tool/cache directory is not writable
("Operation not permitted"), so export these before every `uvx` call in this
sandbox (not needed on a CI runner with a normal writable home — see the CI
step below):

```sh
export UV_CACHE_DIR="$TMPDIR/uv-cache" UV_TOOL_DIR="$TMPDIR/uv-tools"
```

**The build command** (produces both `.txt` and `.html`):

```sh
mkdir -p ietf/build
cp ietf/draft-martinalli-open-purchase-receipts.xml \
   ietf/build/draft-martinalli-open-purchase-receipts-00.xml
uvx --from xml2rfc==3.34.0 xml2rfc \
    ietf/build/draft-martinalli-open-purchase-receipts-00.xml \
    --text --html --path ietf/build --no-network
```

This produces `ietf/build/draft-martinalli-open-purchase-receipts-00.txt`
and `...-00.html` (git-ignored; `ietf/build/` is not committed).

### Why the `cp` step: a naming quirk in xml2rfc 3.34.0

`xml2rfc`'s output filename tracks the **source file's own basename**, not
the `docName` attribute declared inside the `<rfc>` element — building
`draft-martinalli-open-purchase-receipts.xml` directly (the committed
source's actual name, with no `-00` suffix) produces
`draft-martinalli-open-purchase-receipts.txt`, not the `-00`-suffixed name
the docname implies. The CLI's own `-b`/`--basename` flag, which the
`--help` text describes as "specify the base name for output files", does
**not** do that in this pinned version: reading the installed
`xml2rfc/run.py`, `--basename` is aliased directly to `--path`
(`options.output_path = options.basename`) — a real quirk/regression in
3.34.0, not a documentation issue on our end. `-o`/`--out` sets an exact
filename but only for a single output format, so it cannot produce both
`.txt` and `.html` from one invocation either.

The one clean way to get the correctly-named files from the
committed source (which is deliberately named without `-00`, matching the
plan's fixed literal path) in a single `xml2rfc` invocation is the `cp` step
above: copy the source to a `-00`-suffixed name in the build directory
first, then build that copy with `--path`. This was verified live, twice,
in this sandbox (see below), and is exactly what the CI step
(`.github/workflows/ci.yml`, `python` job) does with `$RUNNER_TEMP` in place
of `ietf/build/`.

### Verification (local, twice)

Both runs below completed cleanly (`--no-network`, zero warnings or errors)
and produced a non-empty `.txt` with zero `ERROR`/`TODO` occurrences:

```sh
grep -c 'ERROR\|TODO' ietf/build/draft-martinalli-open-purchase-receipts-00.txt
# 0
```

## Snapshot-profile drift detection

The draft's §1.1 ("Relationship to the living specification") states, in
two dedicated sentences, exactly which revision of each living-spec file it
mirrors:

- `attest-v0.1.md` at **revision 5**
- `attest-v0.2.md` at **revision 6** (hybrid signature profile only —
  Stage 2/Stage 3 material is a non-normative pointer only, §12)

`tools/check_spec_docs.py`'s `check_internet_draft_snapshot()` (wired into
`main()`, CI-gated) parses those two declarations and asserts each declared
revision integer **exists** as `(rev N)` in the corresponding spec's own
`## Revision log` section — existence, not latest-equality, so a later spec
revision landing on `main` does **not** by itself turn this check red. To
detect drift, a reader (or reviewer) compares the declared revision against
the *latest* entry in the living file's revision log: if they differ, this
draft has fallen behind the living specification and should be refreshed
(a new `-01` draft, an updated `-00` before submission, or a superseding
note) before being treated as current.

## Submission (out of scope for this repository's automation)

Submission to the IETF Datatracker is a **manual action** for Samu:
creating a Datatracker account, choosing the public author email (the
`SVM-98@users.noreply.github.com` address in the draft front matter is a
real, GitHub-associated placeholder swapped at submission time — not an
invented mailbox), uploading the built draft, and checking the
current post-meeting submission window live at submission time. None of
this is automated by CI or by any tooling in this repository; the CI step
only proves the draft **builds cleanly**, not that it has been submitted.
