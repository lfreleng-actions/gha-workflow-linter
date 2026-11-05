<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Estate measurement

Prototype `linter.py` against the interpreter engine on PR #434 (its
round-7 working copy), both run over the same local snapshot of 157
lfreleng-actions repositories. Matching tolerates a line shift of up to
four lines, since the two attribute multi-line commands differently.

| | Interpreter (#434) | Prototype |
| --- | --- | --- |
| Findings | 462 | 573 |
| Scan time | 35 s | 9 s |
| PPA001 `python -m` | 128 | 136 |
| PPA002 `python -c` | 76 | 72 |
| PPA003 stdin | 63 | 63 |
| PPA004 empty PYTHONPATH entry | 4 | 3 |
| PPA006 uv .python-version | 47 | 52 |
| PPA007 uv .venv | 88 | 82 |
| PPA008 setup-uv | 56 | 56 |
| PPA009 unresolved | – | 59 (22 repos) |
| PPA010 not fully scanned | – | 50 lines in 25 files |

Of the interpreter's 462: 436 match; the prototype does not report 26,
and about 20 of those appear as PPA009 on the same line
(`"$PYTHON_BIN" -c`, `"${PY_RUN[@]}" -`, `"$python" -m`: the program is
a variable the interpreter resolved through assignments the linter
does not follow). The rest come from `export`/`cd` tracking the design
dropped.

Of the prototype's 573: 28 real-rule findings the interpreter did not
make. Checked against the source, these are commands the interpreter
cleared through an `export` or a `cd` elsewhere in the block
(`rtd-build-action`, `gerrit-docker-k8s`, `github2gerrit-action`'s demo
script, `python-nss-ng`, `project-reporting-tool`). Under the linter
model the scan reports them until the author moves the setting to
`env:` or the step's `working-directory`, or ignores them.

PPA009 by kind: 44 variable-named programs, 11 uv option values
(`--python "$py"`, and `--directory "$GITHUB_ACTION_PATH"` inside a
`--directory=` form the parser does not read), 3 option words before
Python's mode settles, 1 `$GITHUB_ENV` line.

Bash oracle cases from the #434 suite (what bash did): 92 same, 13
finding becomes PPA009, 4 finding plus PPA009, 3 false positives (see
DESIGN.md). No case where planted code ran comes out clean.

The full comparison output is in `prototype/estate-comparison.txt` and
`prototype/oracle-comparison.txt`.
