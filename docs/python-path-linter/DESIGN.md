<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Python import-path linter: design

## Purpose

Report where a workflow, composite action or shell script starts Python
or `uv` so that files in the working directory take part in what runs:
`python -m`, `-c` or code from stdin without `-I`; a `PYTHONPATH` value
that can hold an empty or workspace entry; a `uv` command that reads
`.python-version` or a `.venv` from the workspace; a `setup-uv` step that
works in the workspace. A `run:` step's working directory is the
workspace, which holds the checkout under test in most jobs, so the
scan treats files there as untrusted input.

This document describes the replacement for the engine on
lfreleng-actions/gha-workflow-linter PR #434, and why its shape
differs.

## What the first design got wrong

The engine on #434 interprets bash: it walks each block in execution
order, tracks the working directory, every variable's possible values,
exports and functions, merges branches, and follows `set -e`. Its
contract says an unknown value never proves safety, so staying quiet
about an invocation means *proving* it safe: proving the cwd is the
action's directory, proving `-I` is present, proving the uv flags hold.

Each proof is as good as the model of bash beneath it, and bash is
large. Seven review rounds each produced ten to eighteen genuine gaps
(`shift`, `set --`, `pushd -n`, `env -S` with clustered options, array
subscripts holding substitutions, folded YAML line maps...), and the
count never fell. The model reached 5,300 lines and kept growing.
Measured over 157 repositories it changed 12 of 462 findings against
the regex scan it replaced.

The structural flaw: the engine establishes trust far from the thing
it judges (a `cd` fifty lines earlier, a variable assigned in another
function, an `export` on one branch). Connecting them needs the whole
interpreter. The rule logic itself is small and stable.

## The linter model

The replacement is a linter, not a prover. It judges each command from
what the author wrote in it, trusts a block on conditions bash cannot
alter, and reports anything it cannot read as a finding of its own
instead of a pass. The design accepts false positives and handles them
with the ignore mark (`python-path-audit: ignore`) or the linter's
allowlist; it does not accept a silent pass on a construct the tool did
not model.

Rules:

1. **Parse, do not interpret.** `tree-sitter-bash` parses the shell.
   The scan judges each simple command from its own literal words,
   with no state machine over the block.
2. **A non-literal word in a deciding position is PPA009
   "unresolved".** That covers: a program name that is a variable,
   when the command looks like a Python invocation; an option word
   before Python's mode settles; `uv --python`, `--directory` or
   `--project` with an unknown value; a `PYTHONPATH` value built from
   something the scan cannot read. A word after the mode settles (a
   script's own arguments) does not matter, and the scan reads a word
   ending in `.py` as the script.
3. **Trust is syntactic.** A block earns trust in two ways. Either the
   step's YAML `working-directory` is `${{ github.action_path }}` (with
   an optional literal subpath that does not climb), which bash cannot
   change; or the block's first statement (after an optional `set -e`)
   is `cd "$GITHUB_ACTION_PATH[/sub]"`, under a shell that starts with
   `-e` or guarded by `|| exit`, and the block holds no other `cd`,
   `pushd`, `popd`, `exec`, `eval`, `source`, `.`, and no command whose
   name is not a literal word. A `cd "$GITHUB_ACTION_PATH" && a && b`
   list earns trust for the length of the list under the same
   condition. Workflows never earn trust this way (there is no action
   path).
4. **A variable substitutes under single assignment.** That means
   one assignment in the block, at top level (not in a
   function, loop, branch, subshell, pipeline or substitution), not
   `+=` or indexed, and no `read`, `export`, `declare`, `unset` or
   similar naming the variable. The scan substitutes the assigned words
   as written, so `PY_RUN=(uv run --no-config python)` works and
   anything cleverer does not. `"$(command -v X)"` stands for the
   program X.
5. **uv settings come from the step's YAML `env:` and the command's
   own prefix assignments.** The scan does not follow `export`; a
   reader can move the setting to `env:`.
6. **A parse error anywhere in a block is PPA010 "not fully
   scanned"** on that block, never a clean result. The reader replaces
   `${{ }}` expressions with same-length markers before parsing (the
   reader on #434 does this).
7. **`$GITHUB_ENV` writes** come from `echo`, `printf`, a heredoc into
   `cat`, or a pipe into `tee` naming the file, as `NAME=value` lines
   and `NAME<<DELIMITER` records.

The design keeps these parts of #434 unchanged: the rules PPA001–PPA008
and their texts, the `PYTHONPATH` token model (`_pythonpath.py`: values
judged with `PYTHONPATH` unset, set but empty, and set, with
`:+`/`:-`/`+`/`-` operators), the Python and uv argument tables, the
YAML reader (`_yaml.py`), file discovery, and the oracle test corpus.

## Dependencies

`tree-sitter` (py-tree-sitter 0.26, MIT) and `tree-sitter-bash` (0.25,
MIT). Both ship binary wheels: py-tree-sitter for CPython 3.10–3.14 on
manylinux x86_64/aarch64, musllinux, macOS x86_64/arm64 and Windows
amd64/arm64; tree-sitter-bash as `cp310-abi3` wheels (one build serves
every later CPython) for the same platforms. Both carry an sdist as a
fallback. The linter requires Python >= 3.10, which matches. The
pre-commit hook and the GitHub Action install the package from PyPI, so
both pick the wheels up.

Measured cost: 3,460 shell blocks across 157 repositories parse in 6 s;
a full estate scan takes 8–9 s against 35 s for the interpreter. The
parser read 25 of those files (0.7 %) with an error node, all on known
grammar gaps (`$((10#...))`, `jq ... <<<` after a heredoc, `[[ =~ \ ]]`
continuations, `${x//$'\n'/}`), and the scan reports each as PPA010.

## Behaviour change against #434

Over the same 157 repositories (see ESTATE.md): the linter reports 436
of the interpreter's 462 findings identically, and 20 of the remaining
26 as PPA009 on the same line (the program is a variable); it adds 59
PPA009 and 50 PPA010 findings. Of the 112 bash oracle cases, 92 agree,
13 become PPA009 (every one a construct the interpreter needed a review
round to model), 4 are "finding plus PPA009", and 3 are false positives
the design accepts:

- `export PYTHONPATH="$T"; PYTHONPATH+=":$T"`: PPA004 when `PYTHONPATH`
  is unset. The linter does not know about the `export` two commands
  earlier; the fix (`${PYTHONPATH:+:$PYTHONPATH}`) is the one the rule
  recommends anyway.
- `f() { return 1; }; cd "$GITHUB_ACTION_PATH"; f && cd "$OLDPWD"`: a
  second `cd` in the block ends syntactic trust, run or not.

## Module layout for the implementation

| Module | Role |
| --- | --- |
| `_parse.py` | Over tree-sitter: blocks, commands, words, redirects, lines. |
| `_words.py` | Literal text of a word; constants; `$(command -v X)`. |
| `_commands.py` | Per-command judgement: wrappers, arguments, trust, PPA009. |
| `_pythonpath.py` | As on #434. |
| `_envfile.py` | `$GITHUB_ENV` lines and records. |
| `_yaml.py` | As on #434 (reader, env scopes, directory, setup-uv). |
| `_engine.py` | Rules, findings, discovery, entry point (exit 0/1/2). |

Target size: about a quarter of #434. Nothing in `_commands.py` should
need to know about any command other than the one it judges, plus the
block-level facts (trusted, constants, step env).
