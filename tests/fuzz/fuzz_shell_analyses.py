# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz harness: the shell analyses, ``python_path`` and ``stderr_merge``.

Run from the repository root::

    python tests/fuzz/fuzz_shell_analyses.py [libFuzzer options] [dir ...]
    python tests/fuzz/fuzz_shell_analyses.py <file> [<file> ...]

Each input is read as a scan reads a shell script and handed to both
analyses as one, which is how they see a ``run:`` text too. The
contracts, in the words of the code they check:

- ``python_path`` ``scan_text``: "Every finding in one file's text;
  ValueError when it cannot be read." So ValueError is the only
  exception, and every finding's ``line`` is a line of the text.
- ``stderr_merge`` ``scan_repository``: "Scan a repository, or the
  files named in it, for stderr merges. [...] Files named with
  ``files`` are always scanned." Its result holds "What one scan
  found, and what it could not read". The caller catches what
  ``scan_text`` raises by design, so the harness drives the caller,
  naming the input written to a temporary directory: the scan raises
  nothing, scans that one file, reports at most one problem, which
  names it, and every finding's ``line`` is a line of the text.

Both read a tree-sitter-bash parse. A crash inside the parser itself
kills the process, which the fuzzer reports with its input.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
for _entry in (ROOT / "src", ROOT):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from gha_workflow_linter import stderr_merge  # noqa: E402
from gha_workflow_linter.python_path import _engine  # noqa: E402
from tests.fuzz._common import as_read, ensure, run  # noqa: E402

PATH = "fuzz.sh"


def verify_lines(text: str, lines: list[int], analysis: str) -> None:
    """Every finding names a line inside ``text``."""
    count = text.count("\n") + 1
    for line in lines:
        ensure(
            1 <= line <= count,
            f"{analysis} reported line {line} of a {count}-line text",
        )


def verify_paths(paths: list[str], analysis: str) -> None:
    """Every finding names the path the text was scanned as."""
    ensure(
        all(path == PATH for path in paths),
        f"{analysis} reported a path other than {PATH}",
    )


def verify_repository(result: stderr_merge.StderrMergeResult) -> None:
    """The scan read the one file named, and names it in any problem."""
    ensure(result.files_scanned == 1, "stderr_merge did not scan one file")
    ensure(len(result.problems) <= 1, "stderr_merge reported many problems")
    ensure(
        all(problem.startswith(f"{PATH}: ") for problem in result.problems),
        f"stderr_merge reported a problem not naming {PATH}",
    )


def scan_named(data: bytes) -> stderr_merge.StderrMergeResult:
    """``scan_repository`` over ``data``, written to a file it is told to scan."""
    with tempfile.TemporaryDirectory(prefix="fuzz-scan-") as root:
        (Path(root) / PATH).write_bytes(data)
        return stderr_merge.scan_repository(Path(root), files=[PATH])


def check(data: bytes) -> None:
    """Run one input through both analyses and check their findings."""
    text = as_read(data)
    result = scan_named(data)
    verify_repository(result)
    verify_lines(text, [f.line for f in result.findings], "stderr_merge")
    verify_paths([f.path for f in result.findings], "stderr_merge")
    try:
        paths = _engine.scan_text(text, "script", "repo", PATH)
    except ValueError:
        pass  # documented: the text cannot be read
    else:
        verify_lines(text, [f.line for f in paths], "python_path")
        verify_paths([f.path for f in paths], "python_path")


SEEDS: tuple[bytes, ...] = (
    b"",
    b"gh api x 2>&1 | jq .\n",
    b'out="$(git describe 2>&1)"\necho "v=$out" >> "$GITHUB_OUTPUT"\n',
    b'exec 2>&1\nversion=$(tool --version)\n[ "$version" = 1 ] && exit\n',
    b"cmd |& grep -q ok\ncmd &> log && cat log | sed s/a/b/\n",
    b"cd src\npython3 -m pkg\n",
    b"export PYTHONPATH=.:$PYTHONPATH\npython -c 'import x'\n",
    b"uv run --directory sub pytest\nuvx ruff check .\n",
    b"cat <<EOF\n$(python3 -m tool 2>&1)\nEOF\n"
    b"case $x in a) python a.py;; esac\n",
    b'f() { python3 "$@"; }\nf -m mod # gha-workflow-linter: python-path-ok\n',
    b"\x00\xff\r\n\t$((1+\n",
    # Nested past the walks' limit: python_path reports PPA010.
    b"echo " + b"${x:-" * 300 + b"$(python3 -m x)" + b"}" * 300 + b"\n",
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
