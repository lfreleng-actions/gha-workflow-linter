<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Feat: Add the Python import-path check on a tree-sitter linter

## Summary

Add a check that reports where a workflow, composite action or shell
script starts Python or `uv` so that files in the working directory take
part in what runs. A `run:` step's working directory is the workspace,
which holds the checkout under test in most jobs.

This supersedes PR #434, whose engine modelled bash as an interpreter
and did not converge under review (seven rounds, ten to eighteen
findings each, all genuine, all edge cases of bash). The replacement is
a linter: it judges each command from what the author wrote in it,
trusts a block on conditions bash cannot alter, and reports what it
cannot read as a finding instead of a pass.

A working prototype, the design, and the measurement behind it live on
the branch
`modeseven-lfreleng-actions/gha-workflow-linter@feat/python-path-linter-prototype`,
under `docs/python-path-linter/`:

- `DESIGN.md`: the rules of the linter model, the module layout, and the
  behaviour change against #434.
- `ESTATE.md`: results over 157 repositories, side by side with #434.
- `prototype/`: the working prototype (`scan.py` is the entry point;
  `linter.py`, `pythonpath_checks.py`, `words.py`, `args.py`,
  `tables.py` hold the logic; `yaml_steps.py`, `pythonpath_tokens.py`
  and `discovery.py` come from #434 verbatim), a functional reference
  rather than the implementation.
- `prototype/oracle_check.py` and `reference/test_python_path_engine.py`:
  the oracle test corpus from #434 (each case run under bash, Python and
  uv, recording whether planted code ran) and a runner that tabulates
  the prototype against it.

Read `DESIGN.md` first. The prototype shows one way to meet it; the
implementation should follow the module layout in the design, not the
prototype's shape.

## Rules

| Rule | Reports |
| --- | --- |
| PPA001 | `python -m` without `-I` |
| PPA002 | `python -c` without `-I` |
| PPA003 | code from stdin (`python -`, heredoc, pipe, `<`) without `-I` |
| PPA004 | a `PYTHONPATH` value that can hold an empty entry |
| PPA005 | in actions, a relative or workspace `PYTHONPATH` entry |
| PPA006 | a `uv` command that reads `.python-version` from the workspace |
| PPA007 | a `uv` command that uses a `.venv` in the workspace or a parent |
| PPA008 | an `astral-sh/setup-uv` step working in the workspace |
| PPA009 | unresolved: the outcome depends on a value the scan cannot read |
| PPA010 | not fully scanned: shell the parser could not read |

PPA001–PPA008 keep their meaning and detail texts from #434. PPA009 and
PPA010 are new: they stand where #434 would have had to prove something
about bash.

## Scope of this issue

1. The engine package `src/gha_workflow_linter/python_path/` with the
   modules named in `DESIGN.md`: `_parse.py` (thin over
   `tree-sitter-bash`), `_words.py`, `_commands.py`, `_pythonpath.py`
   (from #434), `_envfile.py`, `_yaml.py` (from #434), `_engine.py`.
2. Dependencies `tree-sitter>=0.25` and `tree-sitter-bash>=0.25` in
   `pyproject.toml` (both ship wheels for every platform and CPython the
   linter supports; see `DESIGN.md`).
3. Tests: port the oracle corpus from
   `reference/test_python_path_engine.py` (`OracleTest`, `UvOracleTest`,
   `EnvWriteTest`, `YamlTest`, `PythonpathTest`, `DiscoveryTest`),
   adjusting expectations where `DESIGN.md` says a case becomes PPA009
   or an accepted false positive. `prototype/oracle-comparison.txt`
   lists which. The oracle tests must keep running bash, Python and uv:
   a case where planted code ran must never come out clean.
4. A `scan_text(text, kind, repo, relpath)` and `scan(roots)` API with
   the same `Finding` shape as #434, and the standalone entry point
   (exit 0 clean, 1 findings, 2 the scan skipped a file).
5. Nothing wired to the CLI, configuration or action yet: that is #435,
   to be re-scoped onto this engine once it lands.

## Acceptance

- Over the 157-repository estate snapshot the result must match
  `ESTATE.md` within the tolerances it describes (the reviewer runs it;
  the numbers specify the behaviour change).
- Every parse error, unknown program in a Python-looking command,
  unknown deciding uv option, and unreadable `PYTHONPATH` value is a
  finding. No construct the engine does not model may produce a pass.
- No shell interpretation: no tracking of the working directory, of
  variable values beyond single assignment, of exports, functions or
  control flow. A reviewer should read `_commands.py` and see every
  input to a decision in the command itself plus the block-level facts
  (trusted, constants, step env).
- `prek` hooks and `aislop ci --changes --base main` clean; no module
  over 600 lines.
- Commit subject: `Feat: Add the Python import-path scan engine`, body
  per the repository's conventions.

## Out of scope

- CLI, configuration, JSON section, action inputs, annotations,
  pre-commit hook, README (#435).
- Closing #434: a maintainer does that once this PR is open.
