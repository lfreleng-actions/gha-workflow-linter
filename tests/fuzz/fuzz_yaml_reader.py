# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz harness: the workflow and action file reader, ``shell._yaml``.

Run from the repository root::

    python tests/fuzz/fuzz_yaml_reader.py [libFuzzer options] [dir ...]
    python tests/fuzz/fuzz_yaml_reader.py <file> [<file> ...]

Each input is read as a scan reads a file, then run through these
contracts, each in the words of the code it checks:

- ``scrub``: "Replace the scan's marker characters in authored text.
  U+FFFD keeps each one a single character, so offsets and byte
  lengths stay as they were". The marker characters are "The
  private-use characters the scan uses as markers", U+E000 to U+E00F.
- ``find_expressions``: "Each ``${{ }}`` expression: its start, end
  and body. [...] ends at the first ``}}`` outside a single-quoted
  string (``''`` is a quote). Read once, left to right [...]; an
  unterminated expression is text." The oracle checks each span
  against the raw text, not against the scanner's own loop.
- ``mark_expressions`` and ``restore_expressions``: marking swaps
  each expression "for a marker indexing ``table``", after "Marker
  characters already in the text are scrubbed first"; restoring puts
  "the original ``${{ }}`` text back in place of each marker". So the
  round trip gives back the scrubbed text.
- ``read``: "Raises ValueError if it is not YAML", and nothing else.
  For each POSIX-style step, ``Block.text`` is its ``run:`` value
  with expressions marked, and ``starts`` maps "where each source
  line's text starts, with the line's 1-based number, in order".
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for _entry in (ROOT / "src", ROOT):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from gha_workflow_linter.shell import _yaml  # noqa: E402
from tests.fuzz._common import as_read, ensure, run  # noqa: E402

MARKERS = range(0xE000, 0xE010)
# The line breaks PyYAML counts, after read_text has turned \r into \n.
LINE_BREAKS = "\n\x85\u2028\u2029"


def scrubbed(text: str) -> str:
    """``text`` with each marker character replaced by U+FFFD."""
    return "".join("\ufffd" if ord(c) in MARKERS else c for c in text)


def verify_scrub(text: str, result: str) -> None:
    """``result`` is ``text`` with only its marker characters replaced."""
    ensure(len(result) == len(text), "scrub changed the text's length")
    for before, after in zip(text, result, strict=True):
        expected = "\ufffd" if ord(before) in MARKERS else before
        ensure(after == expected, f"scrub turned {before!r} into {after!r}")


def outside_quotes(text: str) -> list[str]:
    """The stretches of ``text`` outside single-quoted strings."""
    return text.split("'")[::2]


def verify_expressions(text: str, found: list[tuple[int, int, str]]) -> None:
    """Each span is the next complete ``${{ }}`` in ``text``, and no more."""
    previous = 0
    for start, end, body in found:
        ensure(previous <= start < end <= len(text), "span out of order")
        ensure(text.startswith("${{", start), "span does not open ${{")
        ensure(text.startswith("}}", end - 2), "span does not close }}")
        ensure(
            "${{" not in text[previous : start + 2],
            "an earlier ${{ was skipped",
        )
        raw = text[start + 3 : end - 2]
        ensure(raw.count("'") % 2 == 0, "closing }} sits inside quotes")
        ensure(
            all("}}" not in part for part in outside_quotes(raw + "}")),
            "span runs past an earlier }}",
        )
        ensure(body == raw.strip(), "body is not the stripped inner text")
        previous = end
    rest = text[previous:]
    opening = rest.find("${{")
    if opening >= 0:
        ensure(
            all(
                "}}" not in part for part in outside_quotes(rest[opening + 3 :])
            ),
            "a terminated expression was missed",
        )


def verify_round_trip(text: str, restored: str) -> None:
    """Restoring the marked text gives back the scrubbed original."""
    ensure(restored == scrubbed(text), "mark then restore lost text")


def line_count(text: str) -> int:
    """How many lines PyYAML counts in ``text``."""
    return sum(text.count(brk) for brk in LINE_BREAKS) + 1


def verify_read(text: str, found: _yaml.YamlFile) -> None:
    """Each block is its step's ``run:`` value, mapped to real lines."""
    lines = line_count(text)
    values = dict(found.runs)
    for block in found.blocks:
        ensure(block.step in values, "a block has no run: value")
        value = values[block.step]
        restored = _yaml.restore_expressions(block.text, found.expressions)
        ensure(restored == scrubbed(value), "block text is not its value")
        ensure(bool(block.starts), "a block maps no line")
        offsets = [offset for offset, _number in block.starts]
        numbers = [number for _offset, number in block.starts]
        ensure(offsets == sorted(offsets), "line starts out of order")
        ensure(numbers == sorted(numbers), "line numbers out of order")
        ensure(
            all(0 <= offset <= len(value) for offset in offsets),
            "a line starts outside the value",
        )
        # A marker at the value's end holds no shell text, so it may
        # name the line after a file that ends without a line break.
        ensure(
            all(
                1 <= number <= lines
                or (number == lines + 1 and offset == len(value))
                for offset, number in block.starts
            ),
            f"a line number is outside the file's {lines} lines",
        )


def check(data: bytes) -> None:
    """Run one input through every contract this harness checks."""
    text = as_read(data)
    verify_scrub(text, _yaml.scrub(text))
    verify_expressions(text, _yaml.find_expressions(text))
    table = [_yaml.Expression("other", "seeded", "${{ seeded }}")]
    marked = _yaml.mark_expressions(text, table)
    verify_round_trip(text, _yaml.restore_expressions(marked, table))
    for kind in ("workflow", "action"):
        try:
            found = _yaml.read(text, kind)
        except ValueError:
            continue  # documented: the text is not YAML
        verify_read(text, found)


SEEDS: tuple[bytes, ...] = (
    b"",
    b"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    b"    env:\n      PYTHONPATH: ${{ github.workspace }}/src\n"
    b"    steps:\n      - uses: actions/checkout@v4\n"
    b"      - run: |\n          echo ${{ github.action_path }}\n"
    b"          python -m pip install .\n"
    b"      - run: echo one  # trailing\n"
    b"      - shell: python\n        run: print(1)\n",
    b"runs:\n  using: composite\n  steps:\n"
    b"    - uses: astral-sh/setup-uv@v6\n"
    b"      with:\n        working-directory: ${{ inputs.dir }}\n"
    b"    - run: >\n        uv run\n        pytest\n      shell: bash\n",
    b"jobs: {a: {steps: [{run: 'it''s ${{ x }}'}, {run: \"a\\tb\"}]}}\n",
    b"jobs:\n  a:\n    steps:\n      - run: |+\n          a\n\n\n",
    b"x: ${{ 'a}}b' }} and ${{ unterminated\n",
    b"x: \xee\x80\x80other:0\xee\x80\x81 ${{ env.PYTHONPATH }}\n",
    b"a0: &a0 [x, y]\na1: &a1 [*a0, *a0]\na2: &a2 [*a1, *a1]\n",
    b'jobs:\r\n  a:\r\n    steps:\r\n      - run: "one\r\n        two"\r\n',
    # An empty block value at the end of a file with no final newline.
    b"- run: |",
    # Nested past the recursion limit: read raised RecursionError.
    b"[" * 600,
    b"- " * 600 + b"a\n",
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
