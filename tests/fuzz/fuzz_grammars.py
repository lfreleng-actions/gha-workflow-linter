# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz harness: the ``allow_list_spec`` and ``directives`` grammars.

Run from the repository root::

    python tests/fuzz/fuzz_grammars.py [libFuzzer options] [dir ...]
    python tests/fuzz/fuzz_grammars.py <file> [<file> ...]

An input is UTF-8 text in up to three NUL-separated fields: the text
both grammars parse, a replacement ref, and a replacement version.
The contracts, in the words of the code they check:

- ``resolve_spec``: "Raises: SpecError: The spec is empty or violates
  the grammar", and nothing else.
- ``render_spec``: "Round-tripping a valid spec with its own
  ``ResolvedSpec.ref`` therefore reproduces its source form character
  for character", less "Any trailing comment" and "Whitespace around
  the spec". With a new ref, "Remediation rewrites the ref and nothing
  else", and a ref that "is not a valid git ref" raises SpecError. So
  what renders resolves back to the same value, with the new ref.
- ``render_comment``: "Preserves directives, unrecognised tokens and
  reason text, so a version bump never loses author content". So a
  rendered comment parses back to the same value, with the new
  version.
- ``parse_preceding_directive``: the line ``# gha-workflow-linter:``
  followed by the directives and `` -- <reason>`` declares that
  suppression; each directive and the reason it reports appear in the
  line it read.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for _entry in (ROOT / "src", ROOT):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from gha_workflow_linter.allow_list_spec import (  # noqa: E402
    ResolvedSpec,
    SpecError,
    render_spec,
    resolve_spec,
)
from gha_workflow_linter.directives import (  # noqa: E402
    Directive,
    ParsedComment,
    Suppression,
    parse_preceding_directive,
    parse_trailing_comment,
    render_comment,
)
from tests.fuzz._common import ContractBreach, ensure, run  # noqa: E402

WORKFLOW_ORG = "lfit"
MARKER = "# gha-workflow-linter: "
KEYWORDS = frozenset(directive.value for directive in Directive)


def verify_source_form(spec: str, source: str) -> None:
    """``source`` is ``spec`` less its surrounding blanks and comment."""
    stripped = spec.strip()
    ensure(source != "", "render_spec returned an empty source form")
    ensure(stripped.startswith(source), "render_spec changed the source")
    rest = stripped[len(source) :]
    ensure(
        rest == "" or (rest[0] in " \t" and rest.lstrip(" \t")[0] == "#"),
        f"render_spec dropped {rest!r}, which is not a comment",
    )


def resolve_again(rendered: str) -> ResolvedSpec:
    """Resolve what ``render_spec`` emitted; failing to is a breach."""
    try:
        return resolve_spec(rendered, workflow_org=WORKFLOW_ORG)
    except SpecError as error:
        raise ContractBreach(f"{rendered!r} does not resolve") from error


def verify_ref_bump(
    resolved: ResolvedSpec, ref: str, again: ResolvedSpec
) -> None:
    """``again`` is ``resolved`` with only its ref changed to ``ref``."""
    ensure(again.ref == ref, f"rendered ref {again.ref!r} is not {ref!r}")
    kept = resolved.source.ref == "" and ref == "HEAD"
    expected = replace(
        resolved,
        ref=ref,
        comment="",
        source=replace(resolved.source, ref="" if kept else ref),
    )
    ensure(again == expected, "a ref bump changed more than the ref")


def check_spec(spec: str, ref: str) -> None:
    """Resolve ``spec``, then render it with its own ref and with ``ref``."""
    try:
        resolved = resolve_spec(spec, workflow_org=WORKFLOW_ORG)
    except SpecError:
        return  # documented: the spec violates the grammar
    source = render_spec(resolved, ref=resolved.ref)
    verify_source_form(spec, source)
    ensure(
        resolve_again(source) == replace(resolved, comment=""),
        "the source form resolves to a different spec",
    )
    try:
        rendered = render_spec(resolved, ref=ref)
    except SpecError:
        return  # documented: not a valid git ref
    verify_ref_bump(resolved, ref, resolve_again(rendered))


def verify_comment(
    parsed: ParsedComment, version: str | None, again: ParsedComment
) -> None:
    """``again`` is ``parsed`` with its version set to ``version``."""
    ensure(
        again == replace(parsed, version=version),
        f"render_comment lost content: {parsed!r} became {again!r}",
    )


def is_version_token(text: str) -> bool:
    """Whether ``text`` can stand as the comment's first token."""
    return (
        text.split() == [text]
        and not text.startswith("#")
        and text not in KEYWORDS
    )


def check_comment(comment: str, version: str) -> None:
    """Render a parsed comment with its version and with ``version``."""
    parsed = parse_trailing_comment(comment)
    same = render_comment(parsed, version=parsed.version)
    verify_comment(parsed, parsed.version, parse_trailing_comment(same))
    if is_version_token(version):
        bumped = render_comment(parsed, version=version)
        verify_comment(parsed, version, parse_trailing_comment(bumped))


def preceding_line(found: Suppression) -> str:
    """A directive comment line declaring ``found``."""
    words = sorted(directive.value for directive in found.directives)
    reason = "" if found.reason is None else f" -- {found.reason}"
    return MARKER + " ".join(words) + reason


def verify_preceding(line: str, found: Suppression) -> None:
    """What the line declared appears in it, and declares it again."""
    words = line.split()
    ensure(
        all(directive.value in words for directive in found.directives),
        "a directive the line does not name",
    )
    ensure(
        found.reason is None or found.reason in line,
        "a reason the line does not hold",
    )
    ensure(
        parse_preceding_directive(preceding_line(found)) == found,
        "the rebuilt directive line declares something else",
    )


def check(data: bytes) -> None:
    """Run one input through both grammars."""
    fields = data.decode("utf-8", errors="replace").split("\x00")
    text = fields[0]
    ref = fields[1] if len(fields) > 1 else "v2.0.0"
    version = fields[2] if len(fields) > 2 else "v1.2.3"
    check_spec(text, ref)
    check_comment(text, version)
    found = parse_preceding_directive(text)
    if found is not None:
        verify_preceding(text, found)


SEEDS: tuple[bytes, ...] = (
    b"",
    b"lfit",
    b"@8f4f0cf8bd2c1e8a2f6d4e5b6a7c8d9e0f1a2b3c",
    b"lfreleng-actions/.github//.github/harden-runner/list.txt@main",
    b"lfit// # v0.5.1 allow-list-pin-ok -- upstream is broken",
    b"//team_list.txt@HEAD\x00HEAD",
    b"lfit@main\x00v3\x00v9.9.9",
    # A ref ending in a newline: render_spec accepted it.
    b"lfit/repo@v1 #c\x00main\n",
    b"# v0.5.1 allow-list-pin-ok stderr-merge-ok extra -- why -- not",
    b"python-path-ok --fix a--b --",
    b"   # gha-workflow-linter: allow-list-pin-ok -- waiting for a release",
    b"# gha-workflow-linter: stderr-merge-ok python-path-ok junk",
    b"## v1\t--\treason\x00--\x00v2",
)


def main() -> None:
    """Fuzz ``check`` from the seeds, or replay the files named."""
    import atheris  # type: ignore[import-not-found, import-untyped, unused-ignore]

    def fuzz(args: list[str]) -> None:
        atheris.Setup(args, check)
        atheris.instrument_all()  # pyright: ignore[reportAttributeAccessIssue]
        atheris.Fuzz()

    run(sys.argv, SEEDS, fuzz)


if __name__ == "__main__":
    main()
