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
what the author wrote in it, and reports anything it cannot read as a
finding of its own instead of a pass. Nothing outside the command
grants an exemption, except the step's YAML `env:` for uv settings. The
design accepts false positives and handles them with the ignore mark
(`python-path-audit: ignore`) or the linter's allowlist; it does not
accept a silent pass on a construct the tool did not model, short of
the known limits listed below. The ignore mark applies to every rule,
PPA008 included, on the finding's line or the line above. Where a case
raises a question, the answer that reports PPA009 is the right one.

Rules:

1. **Parse, do not interpret.** `tree-sitter-bash` parses the shell.
   The scan judges each simple command from its own literal words,
   with no state machine over the block: no working directory, no
   variable values, no exports, functions or control flow.
2. **A non-literal word in a deciding position is PPA009
   "unresolved".** That covers: a program name the scan cannot read,
   provided the command looks like a Python or uv invocation: its
   first argument is `-m`, `-c`, `-`, `-I`, `-E`, `-B`, `-u`, `-s`, a
   combined short option containing `m`, `c` or `I`, or Python or uv
   itself (`$SUDO python3`), since Python's own options precede
   everything else; or any of its first four arguments ends in `.py`;
   or the name matches `py|python|uv` in any case (`$PY`, `"$Python"`,
   `"$UV"`). `$K exec "$BP" -c bridge`, `"$@"`, `"${arr[@]}"` and
   `$cmd` with no such signal are not reported (see Known limits).
   It also covers an option word before Python's mode settles; a uv
   subcommand, or `--python`, `--directory` or `--project` with a
   value the scan cannot read or no value at all (`-pPATH`,
   `-p=PATH` and `-qpPATH` carry their value in the word, as uv reads
   them; `--python="$PY"` is unread; uvx's options end at its
   program, so `uvx virtualenv --python "$PY"` belongs to the tool); a
   `PYTHONPATH` value with an expansion other than
   `$PYTHONPATH`/`${PYTHONPATH...}`, `$GITHUB_WORKSPACE`,
   `$PWD`/`$(pwd)`, a `~` (a home directory; `~user` is PPA009, as
   bash leaves an unknown user's as text), or one of the runner
   variables known to be absolute (`GITHUB_ACTION_PATH`, `RUNNER_TEMP`, `RUNNER_TOOL_CACHE`,
   `HOME`, `pythonLocation`); literal text after one of those that
   climbs with `..` (`$RUNNER_TEMP/../repo`) is PPA009 too. A word after
   the mode settles (a script's
   own arguments) does not matter, and the scan reads a word ending in
   `.py` as the script, unless bash would decode it (`$'...'`, a
   backslash). A `${{ }}` expression anywhere in the program word
   makes it unread. The program `uv run` starts goes through the
   same wrapper and name checks as any other, and an unread word where
   `uv run` expects its program is PPA009 unless a literal `--` comes
   before it, since it may hold uv options; so is a `${{ }}` expression
   there, unless it names the workspace, the action path or
   `runner.temp`. `"$(command -v X)"` as a
   program stands for X.
3. **No block-level trust.** No `cd`, `pushd`, `&&` list, `env -C`,
   `--chdir` or YAML `working-directory` exempts anything. A command
   earns its exemption from its own words: `-I` for Python (the scan
   reports `-P` or `PYTHONSAFEPATH` as a partial fix); for uv, `--python`
   (or `UV_PYTHON`) set to a literal absolute path outside the
   workspace together with `--no-project` or an absolute
   `UV_PROJECT_ENVIRONMENT`, plus `--no-config`, or `--system` where
   the subcommand takes it. `--directory` and `--project` exempt
   nothing.
4. **No constants.** The scan never reads a variable's value: an
   assignment earlier in the block changes nothing, so
   `flags=-I; python3 "$flags" -c ...` is PPA009.
5. **Wrappers: table or unresolved.** The scan reads the options in
   each wrapper's table (`command`, `exec`, `time`, `nice`, `sudo`,
   `timeout`, `xargs`, `env` and the like) and no others. Any other
   option word, any word the scan cannot read, and `env -S` in any
   spelling are PPA009: an unknown option never "consumes no
   operand". On `env`, `-u`, `-i`, `-` and a `NAME=value` word the scan
   cannot read are PPA009 before a uv command (they change its
   settings) and the scan skips them before Python (they cannot add to
   `sys.path`). uv settings come from the step's YAML `env:`, the
   command's own prefix assignments and its `env` or `sudo` wrapper's
   `NAME=value` words, read in order, the last one winning. Like env
   and sudo, the scan takes any literal word holding `=` there as an
   assignment, its name as written after the shell removes its quotes:
   `"'UV_PYTHON=..."` sets a name starting with `'`. After the bash
   keywords `time` and `coproc` a word is a prefix assignment when,
   as written, it opens with an unquoted name and `=` or `+=`, as
   bash reads one, and otherwise the program:
   `time /opt/runtime=3/bin/python3` runs that path. After any other
   wrapper, or as the first word, a word holding `=` names the
   program. Where a wrapper reads assignments, a word that is one is
   never taken for a wrapper: `sudo PYTHONPATH=src/env python3` sets
   `PYTHONPATH` and runs no `env`. A prefix
   `NAME+=value` appends to a value the scan does not follow and stays
   unread. A wrapper option's operand (`exec -a NAME=1`) sets nothing,
   `PYTHONPATH` included. `sudo`
   without `-E` or `--preserve-env` (which may name the settings it
   keeps) and `exec -c` drop the step's settings and the prefix
   assignments before the program sees them. A `--python` or
   `UV_PYTHON` request, read or not, wins over `VIRTUAL_ENV`. The scan
   does not follow `export`; a reader can move the setting to `env:`.
6. **Unusual spellings: unresolved, not decoded.** A backslash in
   an unquoted word, an ANSI-C string (`$'...'`), a `printf`
   conversion other than `%s` and `%%`, and an `echo -e` escape other
   than `\n` make the word or line PPA009 when it sits in a deciding
   position (program, option, `PYTHONPATH` value, `$GITHUB_ENV`
   line). A literal absolute path outside the workspace starts with a
   single `/`, equals its `posixpath.normpath` form, holds no
   expression, and does not lie under a runner's workspace
   (`/home/runner/work`, `/Users/runner/work`, `/__w`,
   `/github/workspace`). In an action, a literal `PYTHONPATH` entry
   under one of those roots, after the same normalisation, is PPA005
   like a relative one; before an expansion, the literal's complete
   directory components go through the same normalisation and an
   absolute expansion (`$HOME`) counts as starting with `/`. The scan
   judges `export 'PYTHONPATH=...'` and `export "PYTHONPATH+=..."` like
   the unquoted forms. The scan matches `astral-sh/setup-uv` in any
   case, as GitHub does. A `setup-uv` `working-directory` lies outside
   when it names such a path, or `${{ runner.temp }}` (or, in an action,
   `${{ github.action_path }}`) alone or followed by a `/` subpath
   that does not climb.
7. **A parse error anywhere in a block is PPA010 "not fully
   scanned"** on that block, never a clean result, and so is a command
   nested past the walk's depth limit. The reader replaces `${{ }}`
   expressions, whose bodies may span lines and end at the first
   `}}` outside a single-quoted string, with plain words before
   parsing and maps line numbers back through the byte offsets of the
   swapped text; a line that starts inside an expression starts where
   its word ends, so a command after the expression is on its closing
   line. Each such word is the expression's kind (`TEMP`,
   `WORKSPACE`, `OTHER`...) between two Unicode private-use
   characters, so no literal text in a `run:` block, such as
   `export PYTHONPATH=GHEXPR_TEMP/lib`, reads as an expression.
   The reader takes `PYTHONPATH` in YAML `env:` from the scopes that
   reach a shell (the file, a job, a step), not from matrix data or
   inputs. An
   expression is unknown: PPA009 as a Python option word, and never a
   path outside
   the workspace for uv, `${{ env.PYTHONPATH }}` included; in a
   `PYTHONPATH` value, and nowhere else, `${{ env.PYTHONPATH }}`
   reads as `PYTHONPATH` itself, `${{ github.workspace }}` as the
   workspace, the action path and `runner.temp` as absolute paths, and
   any other expression is PPA009. A YAML `env:` value keeps each
   expression as the reader found it, so its literal text stays
   text, even where it looks like a swapped word.
8. **`$GITHUB_ENV` writes** come from `echo`, `printf`, a heredoc or
   here-string into `cat` or `tee`, or a pipe whose output reaches the
   file, as
   `NAME=value` lines and `NAME<<DELIMITER` records (blank lines in a
   record are part of its value; the scan skips another name's record
   to its delimiter). `tee`, and `cat` with no file operand or with
   `-` among them, copy their input; a heredoc into any other program
   the scan can name writes nothing. A pipe's output reaches the file
   from the last stage back: through `tee` naming the file, or through
   each later stage that is `cat` or `tee` (alone or as the one command
   of a group or subshell) up to one whose output goes there; any other
   stage, or one reading other input (`< file`), stops it. The scan
   knows each program by its basename (`/usr/bin/printf`, `'tee'`). A
   redirect of standard output (`>`, `>>`, `>|`, `&>`, `&>>`, `>&`,
   with or without `1`) counts wherever it stands among the words, the
   last one winning; one to a literal file other than `$GITHUB_ENV`
   takes a command in a redirected group away from it, and one to a
   destination the scan cannot read changes nothing. Redirects after
   a pipeline (`true | cat <<EOF >> "$GITHUB_ENV"`) are its last
   stage's. The shell captures a command substitution's output, so it
   never reaches the file its command's output goes to. The scan reads
   `printf --` as `printf`. A line that starts with a `${{ }}`
   expression could set `PYTHONPATH` and is PPA009; one that starts
   with a shell expansion (`echo "$line"`), or an unread `printf`
   format, is PPA009 when its text mentions `PYTHONPATH`, and clean
   otherwise (see Known limits).

The design keeps these parts of #434 unchanged: the rules PPA001–PPA010
and their texts, the `PYTHONPATH` token model (`_pythonpath.py`: values
judged with `PYTHONPATH` unset, set but empty, and set, with
`:+`/`:-`/`+`/`-` operators), the Python and uv argument tables, the
YAML reader (`_yaml.py`), file discovery, and the oracle test corpus.
Discovery reads every YAML file directly in `.github/workflows` as a
workflow, an `action.yml` there included, and an extensionless file
as a script when its shebang names a shell, by name or path, quoted
or not, after `env` options such as `-S`, `-u NAME`, `-C DIR` and
`NAME=value` words too,
or attached to `-S` or `--split-string=` (cut to any prefix getopt
accepts). The probe reads the line word by word, once, with env's
own quoting rules for a `-S` operand, and up to 512 bytes of it. A
file the probe cannot read makes the scan incomplete.

### Why rules 3 to 6 are this strict

Three review rounds on #447 fixed 43 findings, and each round found
the next gap: `trap 'flags=-E' DEBUG`, `command -p -- cd`,
`sudo --chdir`, `unset "flags"`, `${flags:+}`, `printf '%.7s'`,
`\x3a`, `/home/runner//work`. Measured on the 157-repository estate,
the mechanisms that drew them earned almost nothing:

| Exemption | Findings it suppressed on the estate | Review findings it drew |
| --- | --- | --- |
| Leading `cd "$GITHUB_ACTION_PATH"` block trust | 0 | ~12 |
| YAML `working-directory` trust | 0 | 3 |
| Single-assignment constants | 7 | ~10 |
| Permissive wrapper option modelling | – | ~10 |

The scan keeps literal, per-command facts and nothing else.

## Known limits

The scan does not see an interpreter reached through a variable
without a Python-looking signal, code run by `eval`, `source`,
`bash -c`, `trap` or a `$@` rebound by `set --`, or a glob that
expands to an option. These are the same limits #434 documented and
the same ones every static linter of shell has.

Under the same limits fall a wrapper operand or substituted word that
splits or vanishes (`exec -a $args`, `env -u $args`, or an unquoted
`$(command -v X)` that finds nothing before Python's options), and a
whole line written to `$GITHUB_ENV` from a variable. The scan does not
track values, so it cannot see how a word splits or what a line holds.
For the same reason an unread word where a wrapper takes its options
(`nice "$option" 5 python3 -m x`) reads as the wrapper's program, and
`xargs -I`/`--replace`/`-i` replacement text in a Python command's
options (`xargs -I TOKEN python3 TOKEN -c ...`) reads as written.
An unread uv word not written as an option (`uv pip list "$pkg"`)
reads as an operand, though the variable could hold `-p.venv/...`.

A heredoc or here-string feeds a command as the last stdin redirect in
source order; a later `< file` replaces it. Unescaped
backslash-newlines join an unquoted heredoc's lines, as bash does.

The scan follows a write to `$GITHUB_ENV` through stdout redirects,
pipes into `cat` or `tee`, and groups and subshells (rule 8), and
nothing else. It does not follow descriptor duplication (`>&2`,
`2>&1`) onto an env-file redirect, as in
`echo 'PYTHONPATH=...' 2>> "$GITHUB_ENV" >&2`.

A review finding whose example needs one of these limits to fire gets
an answer, not a fix: the scan does not widen PPA009, add tracking or
add a table entry for it. A wrong table entry, a missed env-file form,
a missed `--` terminator, an ignore mark the scan does not apply, a
setting it does not override or a normalisation gap gets a fix.

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

- `export PYTHONPATH="$RUNNER_TEMP"; PYTHONPATH+=":$RUNNER_TEMP"`: PPA004 when `PYTHONPATH`
  is unset. The linter does not know about the `export` two commands
  earlier; the fix (`${PYTHONPATH:+:$PYTHONPATH}`) is the one the rule
  recommends anyway.
- `f() { return 1; }; cd "$GITHUB_ACTION_PATH"; f && cd "$OLDPWD"`: a
  `cd` earns no trust (rule 3), so the scan reports `python3 -c` after
  it wherever it runs.

The figures above predate the review rounds, which made the scan
stricter. Rules 3 to 6 above (round 3) removed directory trust,
constants and expression exemptions for uv paths: a `cd` into the
action path, a `working-directory` or a variable holding `-I` no
longer passes, and `--python ${{ ... }}` is PPA007. They add findings
(about seven constant-backed passes on the estate become PPA009) and
remove none; the oracle cases that relied on trust or constants now
expect a finding or PPA009, with the reason beside each. Round 3 also
reported every program named by a variable, which took PPA009 on the
estate from 69 to 262 findings (`"${PUBLISH[@]}"`, `${compose_cmd}`,
none of them Python); round 4 limits that to commands that look like
Python or uv, as rule 2 says, and round 5 reads Python's options from
the first argument alone and drops unread `$GITHUB_ENV` lines that do
not mention `PYTHONPATH`. Over the 157-repository estate, PPA009
should stay within 60–100 findings; a count outside that range means a
rule has drifted. The estate figures need a fresh run against this
version.

## Module layout

The package is `gha_workflow_linter.python_path`; the tests are in
`tests/test_python_path_engine.py`.

| Module | Role |
| --- | --- |
| `_block.py` | Over tree-sitter: block walk, redirects, lines. |
| `_words.py` | Literal text of a word; the block's facts. |
| `_invocation.py` | Python argument tables; wrappers; paths. |
| `_commands.py` | Per-command judgement: wrappers, arguments, PPA009. |
| `_uv.py` | uv argument tables and judgement: settings, inner program. |
| `_pythonpath.py` | As on #434. |
| `_envfile.py` | `$GITHUB_ENV` lines and records. |
| `_yaml.py` | As on #434 (reader, env scopes, directory, setup-uv). |
| `_engine.py` | Rules, findings, discovery, entry point (exit 0/1/2). |

Target size: about a quarter of #434. Nothing in `_commands.py` should
need to know about any command other than the one it judges, plus the
step's YAML `env:`.
