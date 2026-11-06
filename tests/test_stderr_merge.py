# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the stderr-merge analysis: merges whose output is data."""

from __future__ import annotations

import os
import textwrap
from typing import TYPE_CHECKING

import pytest

from gha_workflow_linter.stderr_merge import (
    RULES,
    StderrMergeFinding,
    StderrMergeResult,
    file_tags,
    scan_repository,
    scan_text,
)

if TYPE_CHECKING:
    from pathlib import Path

WORKFLOW_HEAD = """\
name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: under test
        run: |
"""


def as_workflow(body: str) -> str:
    """A workflow whose one ``run:`` step is ``body``."""
    return WORKFLOW_HEAD + textwrap.indent(textwrap.dedent(body), " " * 10)


def rules_in(body: str) -> list[str]:
    """The rules a ``run:`` body reports, with ``!`` when suppressed."""
    found = scan_text(as_workflow(body), "workflow", "w.yml")
    return [f.rule + ("!" if f.suppressed else "") for f in found]


def script_rules(text: str) -> list[str]:
    """The rules a shell script reports."""
    found = scan_text(textwrap.dedent(text), "script", "s.sh")
    return [f.rule for f in found]


# The issue's table: each run: body with the rules it reports.
TABLE = [
    pytest.param(
        """\
        json=$(ssh -p 29418 "$host" gerrit query --format JSON "$q" 2>&1)
        jq empty <<< "$json"
        """,
        ["SEM002"],
        id="ssh-capture-parsed",
    ),
    pytest.param(
        """\
        json=$(timeout 30 ssh "$host" gerrit query "$q" 2>"$err")
        jq -r .project <<< "$json"
        """,
        [],
        id="stderr-to-file",
    ),
    pytest.param("gh api x 2>&1 | jq -r .z\n", ["SEM001"], id="pipe-to-jq"),
    pytest.param(
        """\
        out=$(gh release view "$T" --json isDraft 2>&1)
        jq -r .isDraft <<< "$out"
        """,
        ["SEM002"],
        id="release-view-parsed",
    ),
    pytest.param(
        """\
        if ! out=$(gh release view "$T" 2>&1); then
          echo "::error::$out"
          exit 1
        fi
        """,
        [],
        id="failure-path-only",
    ),
    pytest.param(
        """\
        if ! out=$(gh release view "$T" --json body 2>&1); then
          echo "$out"
          exit 1
        fi
        v=$(jq -r .a <<< "$out")
        """,
        ["SEM002"],
        id="use-after-fi",
    ),
    pytest.param(
        """\
        output="$(gh api r --jq .private 2>&1)"
        status=$?
        if [ "$status" -eq 0 ]; then
          [ "$output" = false ] && echo public
        fi
        """,
        ["SEM002"],
        id="status-zero-branch",
    ),
    pytest.param(
        """\
        output="$(gh api r 2>&1)"; status=$?
        if [ "$status" -eq 0 ]; then
          echo 'exists=true' >> "$GITHUB_OUTPUT"
        elif grep -q 'HTTP 404' <<< "$output"; then
          echo 'exists=false' >> "$GITHUB_OUTPUT"
        fi
        """,
        [],
        id="status-elif-failure",
    ),
    pytest.param(
        """\
        err=$(git fetch origin main 2>&1 >/dev/null)
        jq -n --arg e "$err" '$e'
        """,
        [],
        id="stderr-only-capture",
    ),
    pytest.param("jq -e . f >/dev/null 2>&1\n", [], id="both-discarded"),
    pytest.param('cmd 2>&1 | tee "$log"\n', [], id="tee-to-log"),
    pytest.param("docker logs c 2>&1 | tail -20\n", [], id="tail-to-log"),
    pytest.param(
        "v=$(python3 --version 2>&1 | awk '{print $2}')\n",
        ["SEM004"],
        id="python-version-by-design",
    ),
    pytest.param(
        """\
        JV=$("$JAVA" -XshowSettings:properties -version 2>&1 \\
          | sed -n 's/^ *java\\.version = //p')
        """,
        ["SEM004"],
        id="java-by-design",
    ),
    pytest.param(
        """\
        push=$(helm push "$f" "oci://r" 2>&1)
        digest=$(awk '/^Pushed:/ {print $2}' <<< "$push")
        """,
        ["SEM004"],
        id="anchored-awk",
    ),
    pytest.param(
        """\
        OUTPUT=$(./tool 2>&1)
        echo "x=$OUTPUT" >> "$GITHUB_OUTPUT"
        """,
        ["SEM002"],
        id="written-to-github-output",
    ),
    pytest.param(
        """\
        exec 2>&1
        v=$(cmd)
        jq . <<< "$v"
        """,
        ["SEM002"],
        id="exec-merge",
    ),
    pytest.param(
        """\
        # gha-workflow-linter: stderr-merge-ok -- tool prints its result on stderr
        OUTPUT=$(./tool 2>&1)
        echo "x=$OUTPUT" >> "$GITHUB_OUTPUT"
        """,
        ["SEM002!"],
        id="suppressed-preceding",
    ),
]


@pytest.mark.parametrize(("body", "expected"), TABLE)
def test_issue_table(body: str, expected: list[str]) -> None:
    """Every case in the issue's table reports exactly its rules."""
    assert rules_in(body) == expected


MORE = [
    pytest.param("a |& jq .\n", ["SEM001"], id="pipe-ampersand"),
    pytest.param("a &>/dev/null | jq .\n", [], id="amp-discard"),
    pytest.param('v=$(a &>> "$log")\njq . <<< "$v"\n', [], id="amp-append"),
    pytest.param("a 2>/dev/null | jq .\n", [], id="stderr-discarded"),
    pytest.param('a 2>>"$log" | jq .\n', [], id="stderr-appended"),
    pytest.param("a 2>&1 1>/dev/null | jq .\n", [], id="stderr-only-pipe"),
    pytest.param("a >&2 2>&1 | jq .\n", [], id="stdout-to-stderr"),
    pytest.param("a 2>&1 | grep -q ready\n", ["SEM004"], id="grep-q"),
    pytest.param("a 2>&1 | grep -o 'v[0-9.]*'\n", ["SEM003"], id="grep-o"),
    pytest.param("a 2>&1 | cut -d: -f1\n", ["SEM003"], id="cut"),
    pytest.param("a 2>&1 | base64 -d\n", ["SEM001"], id="base64-decode"),
    pytest.param("a 2>&1 | python3 -m json.tool\n", ["SEM001"], id="json-tool"),
    pytest.param("a 2>&1 | node -e 'x'\n", ["SEM001"], id="node-eval"),
    pytest.param("a 2>&1 | sed 's/^/  /'\n", [], id="sed-indent"),
    pytest.param("a 2>&1 | head -1\n", [], id="head-to-log"),
    pytest.param("v=$(a 2>&1 | head -1)\n", ["SEM003"], id="head-captured"),
    pytest.param(
        'v=$(a 2>&1 | tee x)\njq . <<< "$v"\n', ["SEM002"], id="tee-captured"
    ),
    pytest.param(
        'a 2>&1 | tee -a "$GITHUB_OUTPUT"\n', ["SEM001"], id="tee-github-output"
    ),
    pytest.param(
        'a 2>&1 | while read -r l; do echo "  $l"; done\n',
        [],
        id="while-read-logs",
    ),
    pytest.param(
        'a 2>&1 | while read -r l; do push "$l"; done\n',
        ["SEM003"],
        id="while-read-uses",
    ),
    pytest.param('v=$(a 2>&1)\ndeploy "$v"\n', ["SEM003"], id="argument"),
    pytest.param('v=$(a 2>&1)\necho "$v"\n', [], id="echoed"),
    pytest.param('v=$(a 2>&1)\nlog_info "$v"\n', [], id="log-function"),
    pytest.param(
        'v=$(a 2>&1)\necho "$v" | jq .\n', ["SEM002"], id="echo-into-jq"
    ),
    pytest.param(
        'v=$(a 2>&1) || { echo "$v"; exit 1; }\njq . <<< "$v"\n',
        ["SEM002"],
        id="or-block-then-use",
    ),
    pytest.param(
        'v=$(a 2>&1) || { jq . <<< "$v"; exit 1; }\n',
        [],
        id="or-block-only",
    ),
    pytest.param(
        'if v=$(a 2>&1); then jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="if-capture-then",
    ),
    pytest.param(
        'if v=$(a 2>&1); then :; else jq . <<< "$v"; fi\n',
        [],
        id="if-capture-else",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?\nif [ "$s" -ne 0 ]; then jq . <<< "$v"; fi\n',
        [],
        id="status-nonzero-then",
    ),
    pytest.param(
        'v=$(a 2>&1)\ncase "$v" in ok) :;; esac\n',
        ["SEM002"],
        id="case",
    ),
    pytest.param(
        "v=$(a 2>&1)\nif [[ $v == *ok* ]]; then :; fi\n",
        ["SEM002"],
        id="double-bracket",
    ),
    pytest.param(
        "v=$(a 2>&1)\nfor x in $v; do :; done\n",
        ["SEM003"],
        id="for-loop",
    ),
    pytest.param(
        'v=$(a 2>&1)\nv=$(b)\njq . <<< "$v"\n',
        [],
        id="reassigned",
    ),
    pytest.param(
        'v=$(a 2>&1)\n{ v=clean; }\njq . <<< "$v"\n',
        [],
        id="reassigned-in-group",
    ),
    pytest.param(
        'if ! v=$(a 2>&1); then v=fallback; fi\njq . <<< "$v"\n',
        ["SEM002"],
        id="reassigned-on-failure-only",
    ),
    pytest.param(
        'v=$(a 2>&1)\n(v=clean)\njq . <<< "$v"\n',
        ["SEM002"],
        id="reassigned-in-subshell",
    ),
    pytest.param(
        'v=$(a 2>&1)\ntrue && v=clean\njq . <<< "$v"\n',
        ["SEM002"],
        id="reassigned-conditionally",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?\nif ! [ "$s" -eq 0 ]; then :; else jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="status-negated-else",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?\nif ! [ "$s" -eq 0 ]; then jq . <<< "$v"; fi\n',
        [],
        id="status-negated-then",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?\nif [ "$s" -eq 0 ] && b; then :; else jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="status-joined-unclassified",
    ),
    pytest.param("(exec 2>&1); a | jq .\n", [], id="exec-in-subshell"),
    pytest.param(
        "(exec 2>&1; a | jq .)\n", ["SEM001"], id="exec-same-subshell"
    ),
    pytest.param(
        "v=$(exec 2>&1; b); a | jq .\n", [], id="exec-in-substitution"
    ),
    pytest.param("exec 2>&1\na | jq .\n", ["SEM001"], id="exec-block"),
    pytest.param("a >/dev/null |& jq .\n", [], id="pipe-ampersand-discard"),
    pytest.param(
        "a 2>/dev/null |& jq .\n", ["SEM001"], id="pipe-ampersand-late"
    ),
    pytest.param("a |& b |& jq .\n", ["SEM001"], id="pipe-ampersand-chain"),
    pytest.param(
        "python3 --version 2>&1 | b 2>&1 | jq .\n",
        ["SEM001"],
        id="later-merge-in-chain",
    ),
    pytest.param(
        'a 2>&1 | while read -r l; do echo "v=$l" >> "$GITHUB_OUTPUT"; done\n',
        ["SEM001"],
        id="while-read-exports",
    ),
    pytest.param(
        'v=$(a 2>&1)\nwhile read -r l; do echo "v=$l" >> "$GITHUB_ENV"; done <<< "$v"\n',
        ["SEM002"],
        id="while-read-exports-capture",
    ),
    pytest.param(
        'local v=`a 2>&1`\njq . <<< "$v"\n',
        ["SEM002"],
        id="backticks-local",
    ),
    pytest.param(
        'v=$(timeout 5 ssh -V 2>&1)\njq . <<< "$v"\n',
        ["SEM004"],
        id="ssh-version-through-timeout",
    ),
    pytest.param(
        'v=$(nc -zv host 22 2>&1)\n[ -n "$v" ]\n',
        ["SEM004"],
        id="nc-by-design",
    ),
    pytest.param(
        'cat > "$GITHUB_ENV" <<EOF\nV=$(a 2>&1)\nEOF\n',
        ["SEM002"],
        id="heredoc-into-github-env",
    ),
    pytest.param(
        'exec 2>&1; exec 2>/dev/null; v=$(a); jq . <<< "$v"\n',
        [],
        id="exec-merge-ended",
    ),
    pytest.param(
        'exec 2>/dev/null; exec 2>&1; v=$(a); jq . <<< "$v"\n',
        ["SEM002"],
        id="exec-merge-restarted",
    ),
    pytest.param(
        "a |& awk '/^[{]/' |& jq .\n",
        ["SEM004", "SEM001"],
        id="every-merge-in-chain",
    ),
    pytest.param(
        'a |& cat >> "$GITHUB_OUTPUT"\n', ["SEM001"], id="cat-into-github"
    ),
    pytest.param(
        'a 2>&1 | sort > "$GITHUB_ENV"\n', ["SEM001"], id="picker-into-github"
    ),
    pytest.param("a 2>&1 | cat >&2\n", [], id="cat-to-stderr"),
    pytest.param(
        'v=$(a 2>&1 | cat >/dev/null); jq . <<< "$v"\n',
        [],
        id="captured-pipe-discarded",
    ),
    pytest.param(
        "v='{}'; (v=$(a 2>&1)); jq . <<< \"$v\"\n",
        [],
        id="assigned-in-subshell",
    ),
    pytest.param(
        'x=$(v=$(a 2>&1); echo hi); jq . <<< "$v"\n',
        [],
        id="assigned-in-substitution",
    ),
    pytest.param(
        'v=$(a 2>&1); (jq . <<< "$v")\n',
        ["SEM002"],
        id="used-in-child-shell",
    ),
    pytest.param(
        'v=$(a 2>&1); tee -a "$GITHUB_OUTPUT" <<< "$v"\n',
        ["SEM002"],
        id="tee-herestring-github",
    ),
    pytest.param(
        'v=$(a 2>&1)\ncat <<EOF >> "$GITHUB_OUTPUT"\nx=$v\nEOF\n',
        ["SEM002"],
        id="heredoc-then-github-redirect",
    ),
    pytest.param(
        'if v=$(a 2>&1) && b; then :; else jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="if-capture-joined",
    ),
    pytest.param(
        'if ! v=$(a 2>&1) || b; then jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="if-negated-capture-joined",
    ),
    pytest.param(
        '! v=$(a 2>&1) || jq . <<< "$v"\n', ["SEM002"], id="negated-or"
    ),
    pytest.param(
        'v=$(a 2>&1) && b || jq . <<< "$v"\n', ["SEM002"], id="and-then-or"
    ),
    pytest.param('v=$(a 2>&1) || b || jq . <<< "$v"\n', [], id="or-chain"),
    pytest.param(
        'v=$(a 2>&1); echo "$v" 2>>"$GITHUB_OUTPUT"\n',
        [],
        id="stderr-to-github-file",
    ),
    pytest.param(
        'v=$(a 2>&1); echo "$v" >>"$GITHUB_OUTPUT" >/dev/null\n',
        [],
        id="github-redirect-overridden",
    ),
    pytest.param(
        'v=$(python3 --version 2>&1; gh api x 2>&1); jq . <<< "$v"\n',
        ["SEM002"],
        id="grouped-producers-surest",
    ),
    pytest.param(
        'v=$(python3 --version 2>&1); jq . <<< "$v"\n',
        ["SEM004"],
        id="by-design-producer-alone",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?; s=1; if [ "$s" -ne 0 ]; then jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="saved-status-overwritten",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?; if [ "$s" -ne 0 ]; then jq . <<< "$v"; fi\n',
        [],
        id="saved-status-failure-branch",
    ),
    pytest.param(
        'v=$(a 2>&1); v+=" x"; jq . <<< "$v"\n',
        ["SEM002"],
        id="append-keeps-value",
    ),
    pytest.param(
        'v=$(a 2>&1); head -1 <<< "$v"\n', [], id="picker-herestring-log"
    ),
    pytest.param(
        'v=$(a 2>&1); x=$(head -1 <<< "$v")\n',
        ["SEM002"],
        id="picker-herestring-captured",
    ),
    pytest.param(
        'v=$(a 2>&1); head -1 <<< "$v" | jq .\n',
        ["SEM002"],
        id="picker-herestring-piped-to-parser",
    ),
    pytest.param(
        'v=$(a 2>&1); echo "$v" >/dev/null | jq .\n',
        [],
        id="feeder-discarded",
    ),
    pytest.param(
        'v=$(a 2>&1); cat <<< "$v" >/dev/null | jq .\n',
        [],
        id="herestring-feeder-discarded",
    ),
    pytest.param(
        'v=$(a 2>&1); s=$?; if [ "$s" -eq 0 ]; b; then :; '
        'else jq . <<< "$v"; fi\n',
        ["SEM002"],
        id="status-test-not-last-condition",
    ),
    pytest.param(
        "a 2>&1 | grep -o -- '-query=[a-z]+'\n",
        ["SEM003"],
        id="grep-options-end-at-double-dash",
    ),
    pytest.param(
        "a 2>&1 | grep -o -e -q\n", ["SEM003"], id="grep-pattern-operand"
    ),
    pytest.param(
        'v="$(python3 -V 2>&1)$(gh api x 2>&1)"; jq . <<< "$v"\n',
        ["SEM002"],
        id="shared-offset-keeps-surest",
    ),
    pytest.param(
        "json=$(if ready; then gh api x 2>&1; else printf '{}'; fi)\n"
        'jq . <<< "$json"\n',
        ["SEM002"],
        id="capture-of-if-body",
    ),
    pytest.param(
        'json=$(case "$x" in a) gh api x 2>&1;; esac); jq . <<< "$json"\n',
        ["SEM002"],
        id="capture-of-case-body",
    ),
    pytest.param(
        'json=$(for i in 1; do gh api x 2>&1; done); jq . <<< "$json"\n',
        ["SEM002"],
        id="capture-of-loop-body",
    ),
    pytest.param(
        'json=$(if c; then gh api x 2>&1; fi >/dev/null); jq . <<< "$json"\n',
        [],
        id="capture-of-discarded-if",
    ),
    pytest.param("a 2>&1 | jq . <<< '{}'\n", [], id="herestring-replaces-pipe"),
    pytest.param("a 2>&1 | jq . <clean.json\n", [], id="file-replaces-pipe"),
    pytest.param(
        "a 2>&1 | jq . <<EOF\n{}\nEOF\n", [], id="heredoc-replaces-pipe"
    ),
    pytest.param(
        "a 2>&1 | cat <clean.json | jq .\n",
        [],
        id="middle-stage-replaces-pipe",
    ),
    pytest.param(
        'v=$(a 2>&1); echo "$v" | jq . <clean.json\n',
        [],
        id="feeder-pipe-replaced",
    ),
    pytest.param(
        'out=$(gh api x 2>&1); jq . <<< "$(printf \'%s\' "$out")"\n',
        ["SEM002"],
        id="feeder-in-substitution",
    ),
    pytest.param(
        'out=$(gh api x 2>&1); y=$(echo "$out"); jq . <<< "$y"\n',
        ["SEM002"],
        id="feeder-captured-then-parsed",
    ),
    pytest.param(
        'out=$(gh api x 2>&1); y=$(echo "$out" >/dev/null); jq . <<< "$y"\n',
        [],
        id="feeder-in-substitution-discarded",
    ),
    pytest.param(
        'v=$(python3 api.py --version 2>&1); jq . <<< "$v"\n',
        ["SEM002"],
        id="python-script-version",
    ),
    pytest.param(
        'v=$(python3 -c "x" --version 2>&1); jq . <<< "$v"\n',
        ["SEM002"],
        id="python-c-version",
    ),
    pytest.param(
        'v=$(python3 -m tool -V 2>&1); jq . <<< "$v"\n',
        ["SEM002"],
        id="python-m-version",
    ),
    pytest.param(
        'v=$(python3 -W ignore --version 2>&1); jq . <<< "$v"\n',
        ["SEM004"],
        id="python-option-operand-then-version",
    ),
    pytest.param(
        'v=$({ tool 2>/dev/null; } 2>&1); jq . <<< "$v"\n',
        [],
        id="group-merge-command-discards",
    ),
    pytest.param(
        'v=$( (tool 2>/dev/null) 2>&1); jq . <<< "$v"\n',
        [],
        id="subshell-merge-command-discards",
    ),
    pytest.param(
        'v=$({ a; b 2>/dev/null; } 2>&1); jq . <<< "$v"\n',
        ["SEM002"],
        id="group-merge-one-command-keeps",
    ),
    pytest.param(
        'v=$({ java -version; b 2>/dev/null; } 2>&1); jq . <<< "$v"\n',
        ["SEM004"],
        id="group-merge-cap-per-command",
    ),
    pytest.param(
        "{ gh api x 2>&1; } | jq .\n", ["SEM001"], id="brace-stage-merges"
    ),
    pytest.param(
        "(gh api x 2>&1) | jq .\n", ["SEM001"], id="subshell-stage-merges"
    ),
    pytest.param(
        "{ gh api x 2>&1; } >/dev/null | jq .\n",
        [],
        id="brace-stage-stdout-away",
    ),
    pytest.param(
        "{ java -version 2>&1; } | awk '{print $3}'\n",
        ["SEM004"],
        id="brace-stage-by-design",
    ),
    pytest.param("{ a; b; } |& jq .\n", ["SEM001"], id="brace-stage-pipe-both"),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        y=$(true | printf '%s' "$out")
        jq . <<< "$y"
        """,
        ["SEM002"],
        id="last-stage-feeds-capture",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        y=$(true | printf '%s' "$out" >/dev/null)
        jq . <<< "$y"
        """,
        [],
        id="last-stage-to-null-feeds-nothing",
    ),
    pytest.param(
        'out=$(tool 2>&1); echo "$out" > logs/GITHUB_OUTPUT.log\n',
        [],
        id="runner-name-in-log-file",
    ),
    pytest.param(
        'out=$(tool 2>&1); echo "$out" | tee logs/GITHUB_OUTPUT.log\n',
        [],
        id="runner-name-in-tee-file",
    ),
    pytest.param(
        "tool 2>&1 | tee '$GITHUB_OUTPUT'\n",
        [],
        id="single-quoted-runner-name-is-literal",
    ),
    pytest.param(
        'out=$(tool 2>&1); echo "x=$out" >> "${GITHUB_OUTPUT}"\n',
        ["SEM002"],
        id="braced-runner-file",
    ),
    pytest.param(
        'tool 2>&1 | tee -a "$GITHUB_ENV"\n',
        ["SEM001"],
        id="tee-runner-file",
    ),
    pytest.param(
        "tool 2>&1 | sudo -n jq .\n", ["SEM001"], id="sudo-n-is-a-flag"
    ),
    pytest.param(
        "tool 2>&1 | sudo -u bob -E jq .\n",
        ["SEM001"],
        id="sudo-u-takes-operand",
    ),
    pytest.param(
        "tool 2>&1 | nice -n 5 jq .\n", ["SEM001"], id="nice-n-takes-operand"
    ),
    pytest.param(
        "tool 2>&1 | timeout -k 5 30 jq .\n",
        ["SEM001"],
        id="timeout-k-takes-operand",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        if true; then echo "$out"; fi >> "$GITHUB_OUTPUT"
        """,
        ["SEM002"],
        id="if-redirect-exports",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        for i in 1; do echo "$out"; done >> "$GITHUB_ENV"
        """,
        ["SEM002"],
        id="loop-redirect-exports",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        case x in x) echo "$out" ;; esac > "$GITHUB_OUTPUT"
        """,
        ["SEM002"],
        id="case-redirect-exports",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        if true; then echo "$out"; fi >> build.log
        """,
        [],
        id="if-redirect-to-log",
    ),
    pytest.param(
        'out=$(tool 2>&1); cat "$out"\n', ["SEM003"], id="cat-opens-argument"
    ),
    pytest.param(
        'out=$(tool 2>&1); cat "$out" | jq .\n',
        ["SEM003"],
        id="cat-argument-is-not-fed-on",
    ),
    pytest.param("tool 2>&1 | { jq .; }\n", ["SEM001"], id="group-stage-reads"),
    pytest.param("tool 2>&1 | (jq .)\n", ["SEM001"], id="subshell-stage-reads"),
    pytest.param(
        "tool 2>&1 | { read -r first; jq .; }\n",
        ["SEM001"],
        id="group-stage-surest-reader",
    ),
    pytest.param(
        "tool 2>&1 | { cat | jq .; }\n",
        ["SEM001"],
        id="group-stage-inner-pipeline",
    ),
    pytest.param("tool 2>&1 | { jq . < f; }\n", [], id="group-stage-own-stdin"),
    pytest.param(
        "tool 2>&1 | { cat >/dev/null; } | jq .\n",
        [],
        id="group-stage-discards",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        true | jq . <<EOF
        $out
        EOF
        """,
        ["SEM002"],
        id="heredoc-on-pipeline-feeds-last-stage",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        { printf '%s' "$out"; } | jq .
        """,
        ["SEM002"],
        id="feeder-in-group-stage",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        (printf '%s' "$out") | jq .
        """,
        ["SEM002"],
        id="feeder-in-subshell-stage",
    ),
    pytest.param(
        """\
        out=$(gh api x 2>&1)
        { printf '%s' "$out"; } >/dev/null | jq .
        """,
        [],
        id="feeder-in-group-redirected-away",
    ),
    pytest.param(
        """\
        s=1
        if [ "$s" -ne 0 ]; then
          out=$(tool 2>&1); s=$?
          jq . <<< "$out"
        fi
        """,
        ["SEM002"],
        id="status-test-before-capture",
    ),
    pytest.param(
        'out=$(java -jar app.jar -version 2>&1); jq . <<< "$out"\n',
        ["SEM002"],
        id="java-application-version",
    ),
    pytest.param(
        'out=$(java -cp lib -version 2>&1); jq . <<< "$out"\n',
        ["SEM004"],
        id="java-own-version-after-classpath",
    ),
    pytest.param(
        'out=$(ssh host remote-tool -V 2>&1); jq . <<< "$out"\n',
        ["SEM002"],
        id="ssh-remote-command-version",
    ),
    pytest.param(
        'out=$(ssh -p 22 -V 2>&1); jq . <<< "$out"\n',
        ["SEM004"],
        id="ssh-own-version-after-port",
    ),
    pytest.param(
        'out=$(tool &>/dev/stdout); jq . <<< "$out"\n',
        ["SEM002"],
        id="both-to-dev-stdout-captured",
    ),
    pytest.param(
        "tool &>/dev/stdout | jq .\n", ["SEM001"], id="both-to-dev-stdout-piped"
    ),
    pytest.param(
        "tool 2>/dev/fd/1 | jq .\n", ["SEM001"], id="stderr-to-dev-fd-1"
    ),
    pytest.param(
        "tool 2>/dev/stdout >/dev/null | jq .\n",
        [],
        id="stderr-alone-to-dev-stdout",
    ),
    pytest.param(
        "tool 2>&1 | while IFS= read -r l; do printf '%s\\n' \"$l\"; done"
        " | jq .\n",
        ["SEM001"],
        id="printing-loop-feeds-parser",
    ),
    pytest.param(
        "tool 2>&1 | while IFS= read -r l; do printf '%s\\n' \"$l\"; done\n",
        [],
        id="printing-loop-to-log",
    ),
    pytest.param(
        'tool 2>&1 | while read -r l; do echo "$l" >&2; done | jq .\n',
        [],
        id="printing-loop-to-stderr",
    ),
    pytest.param(
        'v=$(tool 2>&1 | while read -r l; do echo "$l"; done)\njq . <<< "$v"\n',
        ["SEM002"],
        id="printing-loop-captured",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        while read -r l; do echo "$l"; done <<< "$out" | jq .
        """,
        ["SEM002"],
        id="printing-loop-fed-value",
    ),
    pytest.param(
        "tool 2>&1 | { cat | cat; } | jq .\n",
        ["SEM001"],
        id="group-inner-pipeline-forwards",
    ),
    pytest.param(
        "tool 2>&1 | { cat | cat >/dev/null; } | jq .\n",
        [],
        id="group-inner-pipeline-discards",
    ),
    pytest.param("tool 2>&1 | cat clean.json | jq .\n", [], id="cat-file"),
    pytest.param("tool 2>&1 | cat - | jq .\n", ["SEM001"], id="cat-dash"),
    pytest.param("tool 2>&1 | cat -n | jq .\n", ["SEM001"], id="cat-option"),
    pytest.param(
        'out=$(tool 2>&1)\ncat f <<< "$out" | jq .\n',
        [],
        id="cat-file-ignores-herestring",
    ),
    pytest.param(
        """\
        output='{}'
        out=$(tool 2>&1)
        out="$output"
        jq . <<< "$out"
        """,
        [],
        id="overwrite-with-longer-name",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        out='$out'
        jq . <<< "$out"
        """,
        [],
        id="overwrite-with-quoted-literal",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        out="${out%x}"
        jq . <<< "$out"
        """,
        ["SEM002"],
        id="overwrite-from-itself",
    ),
    pytest.param(
        'out=$(tool 2>&1)\n{ jq .; } <<< "$out"\n',
        ["SEM002"],
        id="group-reads-herestring",
    ),
    pytest.param(
        'out=$(tool 2>&1)\n(jq .) <<< "$out"\n',
        ["SEM002"],
        id="subshell-reads-herestring",
    ),
    pytest.param(
        'out=$(tool 2>&1)\n{ jq . < f; } <<< "$out"\n',
        [],
        id="group-reader-own-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1)\n{ cat | jq .; } <<< "$out"\n',
        ["SEM002"],
        id="group-pipeline-reads-herestring",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        { jq .; } <<EOF
        $out
        EOF
        """,
        ["SEM002"],
        id="group-reads-heredoc",
    ),
    pytest.param(
        "tool &>'/dev/stdout' | jq .\n",
        ["SEM001"],
        id="quoted-dev-stdout",
    ),
    pytest.param(
        "tool 2>'/dev/fd/1' | jq .\n", ["SEM001"], id="quoted-dev-fd-1"
    ),
    pytest.param("tool 2>&1 | jq . <0\n", [], id="stdin-from-file-0"),
    pytest.param("tool 2>&1 | jq . <&0\n", ["SEM001"], id="stdin-dup-0"),
    pytest.param(
        "{ tool 2>&1 | cat; } | jq .\n", ["SEM001"], id="group-forwards-out"
    ),
    pytest.param(
        "( tool 2>&1 | cat ) | jq .\n", ["SEM001"], id="subshell-forwards-out"
    ),
    pytest.param(
        "{ { tool 2>&1 | cat; } | cat; } | jq .\n",
        ["SEM001"],
        id="nested-groups-forward-out",
    ),
    pytest.param(
        "{ tool 2>&1 | cat; } >/dev/null | jq .\n",
        [],
        id="group-forward-discarded",
    ),
    pytest.param(
        'v=$({ tool 2>&1 | cat; })\njq . <<< "$v"\n',
        ["SEM002"],
        id="group-forwards-into-capture",
    ),
    pytest.param(
        "tool 2>&1 | if true; then jq .; fi\n", ["SEM001"], id="if-stage"
    ),
    pytest.param(
        "tool 2>&1 | case x in x) jq . ;; esac\n", ["SEM001"], id="case-stage"
    ),
    pytest.param(
        "tool 2>&1 | for i in 1; do jq .; done\n", ["SEM001"], id="for-stage"
    ),
    pytest.param(
        "tool 2>&1 | if true; then jq . <f; fi\n",
        [],
        id="if-stage-own-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1)\nif true; then jq .; fi <<< "$out"\n',
        ["SEM002"],
        id="if-reads-herestring",
    ),
    pytest.param(
        'out=$(tool 2>&1)\njq . 3<<< "$out" <clean.json\n',
        [],
        id="herestring-on-fd-3",
    ),
    pytest.param(
        'out=$(tool 2>&1)\njq . <<< "$out" <clean.json\n',
        [],
        id="herestring-replaced-later",
    ),
    pytest.param(
        'out=$(tool 2>&1)\njq . <clean.json <<< "$out"\n',
        ["SEM002"],
        id="herestring-replaces-file",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        jq . <<EOF <clean.json
        $out
        EOF
        """,
        [],
        id="heredoc-replaced-later",
    ),
    pytest.param(
        'out=$(tool 2>&1)\n{ jq .; } <<< "$out" <clean.json\n',
        [],
        id="group-herestring-replaced-later",
    ),
    pytest.param(
        'out=$(tool 2>&1)\nread -r -u 3 line 3<<< "$out"\n',
        ["SEM002"],
        id="read-u-3-reads-fd-3",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        while read -r -u 3 l; do
          echo "$l" >> "$GITHUB_OUTPUT"
        done 3<<< "$out"
        """,
        ["SEM002"],
        id="loop-reads-fd-3",
    ),
    pytest.param("tool 2>&1 | jq . clean.json\n", [], id="jq-reads-a-file"),
    pytest.param("tool 2>&1 | jq . -\n", ["SEM001"], id="jq-reads-dash"),
    pytest.param("tool 2>&1 | jq -n '{\"ok\":true}'\n", [], id="jq-null-input"),
    pytest.param(
        "tool 2>&1 | jq --arg n x '.[$n]'\n", ["SEM001"], id="jq-arg-operands"
    ),
    pytest.param(
        "tool 2>&1 | jq -f prog.jq in.json\n", [], id="jq-from-file-input"
    ),
    pytest.param("tool 2>&1 | jq -f prog.jq\n", ["SEM001"], id="jq-from-file"),
    pytest.param(
        'out=$(tool 2>&1)\njq . clean.json <<< "$out"\n',
        [],
        id="jq-file-ignores-herestring",
    ),
    pytest.param(
        "tool 2>&1 | read -r -u 3 line 3<clean.txt\n", [], id="read-u-3-pipe"
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r -u 3 l; do
          echo "$l" >> "$GITHUB_OUTPUT"
        done 3<f
        """,
        [],
        id="loop-read-u-3-pipe",
    ),
    pytest.param("tool 2>&1 | yq -n '.a = 1'\n", [], id="yq-null-input"),
    pytest.param(
        "tool 2>&1 | yq e '.a' -o json\n", ["SEM001"], id="yq-reads-pipe"
    ),
    pytest.param("tool 2>&1 | grep -o x f\n", [], id="grep-reads-a-file"),
    pytest.param(
        "tool 2>&1 | grep -o -e x\n", ["SEM003"], id="grep-pattern-option"
    ),
    pytest.param(
        "tool 2>&1 | sed -n -e 's/a/b/p' f\n", [], id="sed-reads-a-file"
    ),
    pytest.param(
        "tool 2>&1 | awk -v a=1 '{print $2}' x=1\n",
        ["SEM003"],
        id="awk-assignment-operand",
    ),
    pytest.param("tool 2>&1 | awk '{print $2}' f\n", [], id="awk-reads-a-file"),
    pytest.param(
        "v=$(tool 2>&1 | cut -d' ' -f2)\n", ["SEM003"], id="cut-reads-pipe"
    ),
    pytest.param(
        "tool 2>&1 | xargs -a list.txt jq .\n", [], id="xargs-arg-file"
    ),
    pytest.param(
        "tool 2>&1 | python3 -m json.tool in.json\n",
        [],
        id="json-tool-reads-a-file",
    ),
    pytest.param(
        "tool 2>&1 | python3 -m json.tool\n",
        ["SEM001"],
        id="json-tool-reads-pipe",
    ),
    pytest.param(
        "tool 2>&1 | sed -e's/^/warning: /'\n", [], id="sed-attached-script"
    ),
    pytest.param(
        "tool 2>&1 | sed -i.bak -n p\n", ["SEM003"], id="sed-attached-suffix"
    ),
    pytest.param(
        "tool 2>&1 | sed -e's/a/b/p'\n", ["SEM003"], id="sed-attached-print"
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -o -equery)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-attached-pattern-not-quiet",
    ),
    pytest.param("tool 2>&1 | grep -efoo\n", [], id="grep-attached-not-o"),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -e^Pushed:)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM004"],
        id="grep-attached-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -e '^a' -e b)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-one-pattern-unanchored",
    ),
    pytest.param(
        "tool 2>&1 | xargs grep -a pattern\n",
        ["SEM003"],
        id="xargs-child-options",
    ),
    pytest.param(
        "tool 2>&1 | xargs -n1 -a f grep p\n", [], id="xargs-own-arg-file"
    ),
    pytest.param(
        "tool 2>&1 | xargs -I{} echo {}\n", ["SEM003"], id="xargs-replace"
    ),
    pytest.param(
        "tool 2>&1 | python3 -m json.tool --indent 2\n",
        ["SEM001"],
        id="json-tool-indent-value",
    ),
    pytest.param(
        "tool 2>&1 | python3 -m json.tool --indent=2 -\n",
        ["SEM001"],
        id="json-tool-indent-equals",
    ),
    pytest.param(
        "gh api x 2>&1 | jq -n '[inputs]'\n", ["SEM001"], id="jq-null-inputs"
    ),
    pytest.param(
        "gh api x 2>&1 | jq -n 'input.a'\n", ["SEM001"], id="jq-null-input"
    ),
    pytest.param(
        "gh api x 2>&1 | jq -n -f prog.jq\n",
        ["SEM001"],
        id="jq-null-filter-file",
    ),
    pytest.param(
        "gh api x 2>&1 | jq -n '[inputs]' f.json\n",
        [],
        id="jq-null-inputs-from-file",
    ),
    pytest.param("gh api x 2>&1 | jq -n '$input'\n", [], id="jq-null-variable"),
    pytest.param(
        """\
        out=$(tool 2>&1) && check
        s=$?
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="status-after-and-list",
    ),
    pytest.param(
        """\
        ! out=$(tool 2>&1)
        s=$?
        if [ "$s" -eq 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="status-after-negation",
    ),
    pytest.param(
        """\
        local out=$(tool 2>&1)
        s=$?
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="status-after-declaration",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -v '^DEBUG')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-inverted-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -F '^x')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-fixed-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | fgrep '^x')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="fgrep-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -e '^a' -f patterns)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-pattern-file-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -E '^a|b')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-alternation-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed '/^result:/p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-not-quiet-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n -e '/^result:/p' -e p)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-extra-script-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n '/^a/!p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-negated-address-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n -e '/^a/p' -e 's|^b: ||p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM004"],
        id="sed-every-script-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | awk '/^result:/ {print}; {print}')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="awk-extra-rule-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | awk -F: 'BEGIN { n = 0 } /^key:/ { print $2 }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM004"],
        id="awk-begin-and-anchored-rule",
    ),
    pytest.param(
        "tool 2>&1 | python3 -mjson.tool\n", ["SEM001"], id="python-m-attached"
    ),
    pytest.param(
        "tool 2>&1 | python3 -mjson.tool clean.json\n",
        [],
        id="python-m-attached-file",
    ),
    pytest.param(
        "tool 2>&1 | python3 -c'import json,sys; json.load(sys.stdin)'\n",
        ["SEM001"],
        id="python-c-attached",
    ),
    pytest.param(
        "tool 2>&1 | python3 -Bc 'import sys; sys.stdin.read()'\n",
        ["SEM001"],
        id="python-c-in-cluster",
    ),
    pytest.param(
        "tool 2>&1 | python3 script.py -c x\n", [], id="python-script-own-c"
    ),
    pytest.param("tool 2>&1 | base64 -di\n", ["SEM001"], id="base64-cluster"),
    pytest.param(
        "tool 2>&1 | node --eval='JSON.parse(1)'\n",
        ["SEM001"],
        id="node-eval-equals",
    ),
    pytest.param(
        "tool 2>&1 | node -pe 'JSON.parse(1)'\n", ["SEM001"], id="node-pe"
    ),
    pytest.param("tool 2>&1 | node app.js -e x\n", [], id="node-script-own-e"),
    pytest.param(
        "tool 2>&1 | yq -n --from-file filter.yq\n",
        ["SEM001"],
        id="yq-null-filter-file",
    ),
    pytest.param(
        "tool 2>&1 | sudo -nu root jq .\n",
        ["SEM001"],
        id="sudo-cluster-operand",
    ),
    pytest.param(
        "tool 2>&1 | sudo -uroot jq .\n", ["SEM001"], id="sudo-attached-operand"
    ),
    pytest.param(
        "tool 2>&1 | command grep -v '^debug:' | jq .\n",
        ["SEM001"],
        id="command-child-option",
    ),
    pytest.param(
        "tool 2>&1 | command -V jq\n", [], id="command-describe-upper"
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -r s <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-read-over",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf -v s '%d' 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-printf-v-over",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; mapfile -t s < list
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-mapfile-over",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; ((s++))
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-arithmetic-over",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; let s=1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-let-over",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; unset s
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-unset",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; for s in 1; do :; done
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-loop-variable",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -r line <<< "$s"
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-read-elsewhere",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf '%s\\n' s; ((s == 0)) || :
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-read-only-uses",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n '/^key:/,/^end:/p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-range-not-anchored",
    ),
    pytest.param('code=$(tool 2>&1); exit "$code"\n', ["SEM003"], id="exit"),
    pytest.param(
        'f() { code=$(tool 2>&1); return "$code"; }\n', ["SEM003"], id="return"
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do echo "$l"; exit 1; done | jq .
        """,
        ["SEM001"],
        id="while-read-exit-still-prints",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n '/^key:/ { n; p; }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-next-line-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n '/^key:/N;/^key:/p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-append-line-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n '/^key:/ { s/^key: *//; p; }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM004"],
        id="sed-block-substitute-print",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n 's/^key: *//ep')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-execute-flag-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -nz '/^key:/p')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-null-data-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | sed -n -e '/^key:/p' -f extra.sed)
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="sed-script-file-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -A1 '^key:')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-after-context-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep --context=2 '^key:')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-context-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -2 '^key:')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-numeric-context-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -z '^key:')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-null-data-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep -o '^key:.*')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM004"],
        id="grep-only-matching-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | awk '/^key:/ { getline; print }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="awk-getline-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | awk 'BEGIN { RS = "" } /^key:/ { print }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="awk-record-separator-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | awk -v RS= '/^key:/ { print }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="awk-record-separator-option-not-anchored",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | gawk -e '/^key:/' -e '{ print }')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="gawk-source-option-not-anchored",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          if [[ $l == ready ]]; then echo ok; fi
        done
        """,
        ["SEM003"],
        id="while-read-test-compares",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          case $l in ready) echo ok ;; esac
        done
        """,
        ["SEM003"],
        id="while-read-case-selects",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          (( l > 3 )) && echo big
        done
        """,
        ["SEM003"],
        id="while-read-arithmetic-compares",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          if [[ $x == ready ]]; then echo "$l"; fi
        done
        """,
        [],
        id="while-read-test-of-other-variable",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head --lines 1)\n",
        ["SEM003"],
        id="head-lines-separated-captured",
    ),
    pytest.param(
        "v=$(tool 2>&1 | tail --lines 1)\n",
        ["SEM003"],
        id="tail-lines-separated-captured",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -n1)\n", ["SEM003"], id="head-n-attached-captured"
    ),
    pytest.param(
        "tool 2>&1 | head --lines 1\n", [], id="head-lines-separated-to-log"
    ),
    pytest.param(
        "v=$(tool 2>&1 | head --lines 10)\n", [], id="head-lines-ten-captured"
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -10)\n", [], id="head-ten-short-captured"
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -as <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-read-attached-array",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -r -a s <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-read-separate-array",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -p s x <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-read-prompt-operand",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); MAPFILE=$?; mapfile -t -n 1 <<< 1
        if [ "$MAPFILE" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-mapfile-default-array",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); MAPFILE=$?; readarray -n1 <<< 1
        if [ "$MAPFILE" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-readarray-default-array",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; mapfile -t -n 1 lines <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-mapfile-option-operand",
    ),
    pytest.param(
        """\
        v=$(tool 2>&1 | grep ' ^key:')
        echo "x=$v" >> "$GITHUB_OUTPUT"
        """,
        ["SEM003"],
        id="grep-leading-space-not-anchored",
    ),
    pytest.param(
        "count=$(tool 2>&1); if (( count > 3 )); then echo big; fi\n",
        ["SEM002"],
        id="arithmetic-bare-name-compared",
    ),
    pytest.param(
        "count=$(tool 2>&1); (( count++ ))\n",
        ["SEM002"],
        id="arithmetic-bare-name-incremented",
    ),
    pytest.param(
        'count=$(tool 2>&1); echo "$(( count + 1 ))"\n',
        ["SEM002"],
        id="arithmetic-expansion-bare-name",
    ),
    pytest.param(
        "count=$(tool 2>&1); (( count = 3 ))\n",
        [],
        id="arithmetic-plain-assignment-target",
    ),
    pytest.param(
        """\
        if ! count=$(tool 2>&1); then
          if (( count > 3 )); then echo big; fi
          exit 1
        fi
        """,
        [],
        id="arithmetic-failure-path-only",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); copy="$out"
        jq . <<< "$copy"
        """,
        ["SEM002"],
        id="copy-then-parsed",
    ),
    pytest.param(
        """\
        f() {
          local out copy
          out=$(tool 2>&1)
          local copy=$out
          echo "v=$copy" >> "$GITHUB_OUTPUT"
        }
        """,
        ["SEM002"],
        id="local-copy-exported",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); copy="$out"
        echo "$copy"
        """,
        [],
        id="copy-only-logged",
    ),
    pytest.param(
        """\
        if ! out=$(tool 2>&1); then
          msg="failed: $out"; echo "::error::$msg"; exit 1
        fi
        """,
        [],
        id="copy-on-failure-path",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); a="$out"; b="$a"; c="$b"
        jq . <<< "$c"
        """,
        ["SEM002"],
        id="copy-chain-parsed",
    ),
    pytest.param(
        "tool 2>&1 | read -u 3 -u 0 line 3<clean.txt\n",
        ["SEM003"],
        id="read-last-u-is-stdin",
    ),
    pytest.param(
        "tool 2>&1 | read -u 0 -u 3 line 3<clean.txt\n",
        [],
        id="read-last-u-is-other-fd",
    ),
    pytest.param(
        "tool 2>&1 | mapfile -u 3 -u0 lines 3<clean.txt\n",
        ["SEM003"],
        id="mapfile-last-u-is-stdin",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -a arr s <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-read-array-ignores-operands",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -a s -a arr <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-read-last-array-wins",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; read -a arr -a s <<< 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-read-last-array-is-status",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf '%s\\n' -v s
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-printf-v-after-format",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf -- -v s
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        [],
        id="saved-status-printf-v-after-double-dash",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf -vs '%d' 1
        if [ "$s" -ne 0 ]; then jq . <<< "$out"; fi
        """,
        ["SEM002"],
        id="saved-status-printf-attached-v",
    ),
    pytest.param(
        "out='{}'; out=$(tool 2>&1) true; jq . <<< \"$out\"\n",
        [],
        id="temporary-prefix-capture",
    ),
    pytest.param(
        'out=$(tool 2>&1); copy="$out" true; jq . <<< "$copy"\n',
        [],
        id="temporary-prefix-copy",
    ),
    pytest.param(
        'out=$(tool 2>&1) :; jq . <<< "$out"\n',
        ["SEM002"],
        id="prefix-before-special-builtin",
    ),
    pytest.param(
        "count=$(tool 2>&1); (( count = 3 )); (( count > 0 ))\n",
        [],
        id="arithmetic-overwrite-ends-tracking",
    ),
    pytest.param(
        "count=$(tool 2>&1); (( count = count + 1 )); (( count > 0 ))\n",
        ["SEM002"],
        id="arithmetic-overwrite-reading-value",
    ),
    pytest.param(
        "count=$(tool 2>&1); c || (( count = 3 )); (( count > 0 ))\n",
        ["SEM002"],
        id="arithmetic-overwrite-after-or",
    ),
    pytest.param(
        "out=$(tool 2>&1); printf -v out '%s' '{}'; jq . <<< \"$out\"\n",
        [],
        id="printf-v-overwrite-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf -v out \'%s\' "${out%x}"; jq . <<< "$out"\n',
        ["SEM002"],
        id="printf-v-overwrite-reading-value",
    ),
    pytest.param(
        "out=$(tool 2>&1); if c; then printf -v out '%s' '{}'; fi; jq . <<< \"$out\"\n",
        ["SEM002"],
        id="printf-v-overwrite-in-branch",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -r out; jq . <<< "$out"\n',
        [],
        id="read-overwrite-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); unset out; jq . <<< "$out"\n',
        [],
        id="unset-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); unset -f out; jq . <<< "$out"\n',
        ["SEM002"],
        id="unset-function-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -t 0 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-zero-timeout-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -rt0.0 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-attached-zero-timeout-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -t "$t" out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-unknown-timeout-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -t 0 -t 5 out; jq . <<< "$out"\n',
        [],
        id="read-last-timeout-positive-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); mapfile -t out; jq . <<< "$out"\n',
        [],
        id="mapfile-overwrite-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); mapfile -O 1 -t out; jq . <<< "$out"\n',
        ["SEM002"],
        id="mapfile-origin-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); readarray -O1 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="readarray-origin-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); mapfile -O 0 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="mapfile-zero-origin-keeps-tracking",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; copy=$out
        if [ "$s" -ne 0 ]; then jq . <<< "$copy"; fi
        """,
        [],
        id="copy-used-on-status-failure-path",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; copy=$out
        if [ "$s" -eq 0 ]; then jq . <<< "$copy"; fi
        """,
        ["SEM002"],
        id="copy-used-on-status-success-path",
    ),
    pytest.param(
        'if ! out=$(tool 2>&1); then copy=$out; c; jq . <<< "$copy"; fi\n',
        [],
        id="copy-in-failure-branch-used-there",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; a=$out; b=$a
        if [ "$s" -ne 0 ]; then jq . <<< "$b"; fi
        """,
        [],
        id="copy-chain-on-status-failure-path",
    ),
    pytest.param(
        "out=$(tool 2>&1); printf -v copy '%s' \"$out\" | jq .\n",
        [],
        id="printf-v-prints-nothing",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf -v copy \'%s\' "$out"; jq . <<< "$copy"\n',
        ["SEM002"],
        id="printf-v-copy-parsed",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf -v msg \'error: %s\' "$out"; echo "$msg"\n',
        [],
        id="printf-v-copy-logged",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); s=$?; printf -v copy '%s' "$out"
        if [ "$s" -ne 0 ]; then jq . <<< "$copy"; fi
        """,
        [],
        id="printf-v-copy-on-status-failure-path",
    ),
    pytest.param(
        "out=$(tool 2>&1); printf '%s' \"$out\" | jq .\n",
        ["SEM002"],
        id="printf-without-v-feeds-pipe",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        printf -v msg '%s' "$out" >> "$GITHUB_OUTPUT"; echo "$msg"
        """,
        [],
        id="printf-v-runner-file-redirect-logged",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        printf -v msg '%s' "$out" >> "$GITHUB_OUTPUT"
        echo "msg=$msg" >> "$GITHUB_OUTPUT"
        """,
        ["SEM002"],
        id="printf-v-runner-file-redirect-copy-written",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf \'%s\' "$out" >> "$GITHUB_OUTPUT"\n',
        ["SEM002"],
        id="printf-without-v-to-runner-file",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -n 1 -n 10)\n",
        [],
        id="head-last-count-wins",
    ),
    pytest.param(
        "v=$(tool 2>&1 | tail -n 1 -n 10)\n",
        [],
        id="tail-last-count-wins",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -n 10 -n 1)\n",
        ["SEM003"],
        id="head-last-count-is-one",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -1 -n 10)\n",
        [],
        id="head-obsolete-count-overridden",
    ),
    pytest.param(
        "v=$(tool 2>&1 | head -n 1 -c 5)\n",
        [],
        id="head-byte-count-overrides-lines",
    ),
    pytest.param(
        'tool 2>&1 | jq -n \'{"input":"constant"}\'\n',
        [],
        id="jq-null-input-string-key",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '\"input\"'\n",
        [],
        id="jq-null-input-string-literal",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '{input: 1}'\n",
        [],
        id="jq-null-input-object-key",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '{input}'\n",
        [],
        id="jq-null-input-shorthand-key",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '{a: input}'\n",
        ["SEM001"],
        id="jq-null-input-object-value",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '{(input): 1}'\n",
        ["SEM001"],
        id="jq-null-input-computed-key",
    ),
    pytest.param(
        "tool 2>&1 | jq -n '\"\\(input)\"'\n",
        ["SEM001"],
        id="jq-null-input-interpolation",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do printf -v msg '%s' "$l"; done \\
          | jq .
        """,
        [],
        id="loop-printf-v-feeds-nothing",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          printf -v msg '%s' "$l" >> "$GITHUB_OUTPUT"
        done
        """,
        [],
        id="loop-printf-v-runner-file-redirect",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          printf 'v=%s' "$l" >> "$GITHUB_OUTPUT"
        done
        """,
        ["SEM001"],
        id="loop-printf-to-runner-file",
    ),
    pytest.param(
        "if tool 2>&1 | read -t 0; then echo ready; fi\n",
        ["SEM004"],
        id="pipe-read-zero-timeout-is-readiness",
    ),
    pytest.param(
        "tool 2>&1 | read -rt0.0 line && echo ready\n",
        ["SEM004"],
        id="pipe-read-attached-zero-timeout",
    ),
    pytest.param(
        "tool 2>&1 | read -t 0 -t 5 line\n",
        ["SEM003"],
        id="pipe-read-last-timeout-positive-extracts",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -t 0 <<< "$out"\n',
        ["SEM004"],
        id="herestring-read-zero-timeout",
    ),
    pytest.param(
        'tool 2>&1 | while read -t 0 l; do jq . <<< "$l"; done\n',
        [],
        id="loop-read-zero-timeout-reads-nothing",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 9<&-; read -u 9 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-closed-descriptor-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 9<&-; mapfile -u 9 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="mapfile-closed-descriptor-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); readarray -u9 out; jq . <<< "$out"\n',
        ["SEM002"],
        id="readarray-other-descriptor-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); read -u 9 -u 0 out; jq . <<< "$out"\n',
        [],
        id="read-last-descriptor-stdin-ends-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); < f.txt read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-from-missing-file-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); <&- read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-closed-stdin-keeps-tracking",
    ),
    pytest.param(
        'out=$(tool 2>&1); <<< x read out; jq . <<< "$out"\n',
        [],
        id="read-herestring-prefix-ends-tracking",
    ),
    pytest.param(
        "gh api x 2>&1 | env -S 'jq .'\n",
        ["SEM001"],
        id="env-split-string-runs-parser",
    ),
    pytest.param(
        "gh api x 2>&1 | env --split-string='jq -r' .z\n",
        ["SEM001"],
        id="env-long-split-string-runs-parser",
    ),
    pytest.param(
        "gh api x 2>&1 | env -iS'FOO=1 jq .'\n",
        ["SEM001"],
        id="env-split-string-cluster-and-assignment",
    ),
    pytest.param(
        "gh api x 2>&1 | env -S 'cat'\n",
        [],
        id="env-split-string-runs-cat",
    ),
    pytest.param(
        "gh api x 2>&1 | env -u X -S 'jq .'\n",
        ["SEM001"],
        id="env-split-string-after-option-operand",
    ),
    pytest.param(
        'gh api x 2>&1 | env -S "\'jq ."\n',
        [],
        id="env-split-string-unbalanced-not-followed",
    ),
    pytest.param(
        "tool 2>&'1' | jq .\n",
        ["SEM001"],
        id="single-quoted-descriptor-merges",
    ),
    pytest.param(
        "out=$(tool 2>&'1'); jq . <<< \"$out\"\n",
        ["SEM002"],
        id="single-quoted-descriptor-capture",
    ),
    pytest.param(
        "tool 2>'1' | jq .\n",
        [],
        id="single-quoted-file-named-1",
    ),
    pytest.param(
        "tool 2>&'-' | jq .\n",
        [],
        id="single-quoted-close-descriptor",
    ),
    pytest.param(
        "out=$(tool 2>&1); echo \"$out\" >> '$GITHUB_OUTPUT'\n",
        [],
        id="single-quoted-runner-file-name-is-literal",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); > "$dest" printf -v out '%s' '{}'
        jq . <<< "$out"
        """,
        ["SEM002"],
        id="store-behind-failing-output-redirect-keeps-value",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); 2>&1 printf -v out '%s' '{}'
        jq . <<< "$out"
        """,
        [],
        id="store-behind-descriptor-redirect-replaces-value",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); 2>/dev/null printf -v out '%s' '{}'
        jq . <<< "$out"
        """,
        [],
        id="store-behind-dev-null-redirect-replaces-value",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1); >&3 printf -v out '%s' '{}'
        jq . <<< "$out"
        """,
        ["SEM002"],
        id="store-behind-other-descriptor-keeps-value",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          printf -v msg '%s' "$l"; echo "$msg"
        done | jq .
        """,
        ["SEM001"],
        id="loop-prints-printf-v-copy",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          printf -v a '%s' "$l"; printf -v b '%s' "$a"; echo "$b"
        done | jq .
        """,
        ["SEM001"],
        id="loop-prints-copy-of-copy",
    ),
    pytest.param(
        """\
        tool 2>&1 | while read -r l; do
          printf -v msg '%s' "$l"; echo done
        done | jq .
        """,
        [],
        id="loop-copy-not-printed",
    ),
    pytest.param(
        "tool 2>&1 | python3 2>/dev/null -c 'import json,sys; json.load(sys.stdin)'\n",
        ["SEM001"],
        id="parser-option-after-redirect",
    ),
    pytest.param(
        "tool 2>&1 | grep 2>/dev/null -o x\n",
        ["SEM003"],
        id="extractor-option-after-redirect",
    ),
    pytest.param(
        "tool 2>&1 | jq . 2>/dev/null input.json\n",
        [],
        id="file-operand-after-redirect-reads-no-pipe",
    ),
    pytest.param(
        'out=$(tool 2>&1); mycmd 2>/dev/null "$out"\n',
        ["SEM003"],
        id="argument-after-redirect",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf -v c \'%s\' 2>/dev/null "$out"; jq . <<< "$c"\n',
        ["SEM002"],
        id="printf-v-operand-after-redirect",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf \'%s\' "$out" >> "$GITHUB_OUTPUT" extra\n',
        ["SEM002"],
        id="runner-file-redirect-before-trailing-word",
    ),
    pytest.param(
        'out=$(tool 2>&1); printf \'%s\' "$out" >> /tmp/log "$GITHUB_OUTPUT"\n',
        [],
        id="runner-file-word-after-redirect-is-an-argument",
    ),
    pytest.param(
        "a 2>&1 | jq .  # stderr-merge-ok -- inline reason\n",
        ["SEM001!"],
        id="suppressed-inline",
    ),
    pytest.param(
        "a 2>&1 | jq .  # gha-workflow-linter: allow-list-pin-ok\n",
        ["SEM001"],
        id="other-directive-does-not-suppress",
    ),
    pytest.param(
        "out=$(tool 2>&1); env printf -v out '%s' clean; jq . <<< \"$out\"\n",
        ["SEM002"],
        id="env-printf-v-sets-nothing-here",
    ),
    pytest.param(
        'out=$(tool 2>&1); sudo read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="sudo-read-sets-nothing-here",
    ),
    pytest.param(
        'out=$(tool 2>&1); timeout 5 read -r out; jq . <<< "$out"\n',
        ["SEM002"],
        id="timeout-read-sets-nothing-here",
    ),
    pytest.param(
        "out=$(tool 2>&1); command printf -v out '%s' x; jq . <<< \"$out\"\n",
        [],
        id="command-printf-v-overwrites",
    ),
    pytest.param(
        "tool 2>&1 | sed 's/a\\/b/x/p'\n",
        ["SEM003"],
        id="sed-escaped-delimiter-print-flag",
    ),
    pytest.param(
        "tool 2>&1 | sed 's|a\\|b|x|p'\n",
        ["SEM003"],
        id="sed-escaped-custom-delimiter-print-flag",
    ),
    pytest.param(
        "tool 2>&1 | sed 's/a\\/b/x/'\n",
        [],
        id="sed-escaped-delimiter-no-print",
    ),
    pytest.param(
        "tool 2>&1 | sed -n '/a\\/b/p'\n",
        ["SEM003"],
        id="sed-escaped-address-print",
    ),
    pytest.param(
        "tool 2>&1 | cat /dev/stdin | jq .\n",
        ["SEM001"],
        id="cat-dev-stdin-passes-on",
    ),
    pytest.param(
        "tool 2>&1 | jq . /dev/stdin\n",
        ["SEM001"],
        id="jq-dev-stdin",
    ),
    pytest.param(
        "tool 2>&1 | jq . /dev/fd/0\n",
        ["SEM001"],
        id="jq-dev-fd-0",
    ),
    pytest.param(
        "tool 2>&1 | jq . /proc/self/fd/0\n",
        ["SEM001"],
        id="jq-proc-self-fd-0",
    ),
    pytest.param(
        "tool 2>&1 | jq . /dev/fd/3\n",
        [],
        id="jq-dev-fd-3-is-not-stdin",
    ),
    pytest.param(
        "tool 2>&1 | python3 -m json.tool /dev/stdin\n",
        ["SEM001"],
        id="json-tool-dev-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); 0>&- read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-closed-stdin-prefix",
    ),
    pytest.param(
        'out=$(tool 2>&1); read out 0>&-; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-closed-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); read out 0>/dev/null; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-write-only-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 0>&-; read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-after-exec-closes-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 0>/dev/null; read out; jq . <<< "$out"\n',
        ["SEM002"],
        id="read-after-exec-write-only-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 0</dev/null; read out; jq . <<< "$out"\n',
        [],
        id="read-after-exec-readable-stdin",
    ),
    pytest.param(
        'out=$(tool 2>&1); exec 0>&-; printf -v out x; jq . <<< "$out"\n',
        [],
        id="printf-v-after-exec-closes-stdin",
    ),
    pytest.param(
        "tool 0>/dev/null 2>&1 | jq .\n",
        ["SEM001"],
        id="stdin-redirect-is-not-a-stdout-discard",
    ),
    pytest.param(
        "tool >&2>/dev/null | jq .\n",
        [],
        id="dup-target-is-not-next-descriptor",
    ),
    pytest.param(
        'out=$(tool 2>&1); true "$out" >> "$GITHUB_OUTPUT"\n',
        [],
        id="true-writes-nothing-to-runner-file",
    ),
    pytest.param(
        'out=$(tool 2>&1); : "$out" >> "$GITHUB_OUTPUT"\n',
        [],
        id="colon-writes-nothing-to-runner-file",
    ),
    pytest.param(
        'out=$(tool 2>&1); logger "$out" >> "$GITHUB_OUTPUT"\n',
        [],
        id="logger-writes-to-syslog",
    ),
    pytest.param(
        'out=$(tool 2>&1); logger <<< "$out" >> "$GITHUB_OUTPUT"\n',
        [],
        id="logger-fed-writes-to-syslog",
    ),
    pytest.param(
        'tool 2>&1 | while read -r l; do true "$l" >> "$GITHUB_OUTPUT"; done\n',
        [],
        id="loop-true-writes-nothing",
    ),
]


@pytest.mark.parametrize(("body", "expected"), MORE)
def test_merge_and_use_cases(body: str, expected: list[str]) -> None:
    """Merges, discards and uses beyond the issue's table."""
    assert rules_in(body) == expected


# Fixtures modelled on the corpus cases the issue names.
GERRIT_QUERY_FIXED = """\
#!/usr/bin/env bash
set -euo pipefail
err_file=$(mktemp)
trap 'rm -f "$err_file"' EXIT
if ! json_output=$(timeout "$TIMEOUT" ssh -p "$PORT" "$USER@$HOST" \\
    gerrit query --format JSON --current-patch-set "change:$CHANGE" \\
    2>"$err_file"); then
  echo "::error::Gerrit query failed: $(cat "$err_file")"
  exit 1
fi
if ! jq empty <<< "$json_output" 2>/dev/null; then
  echo "::error::Gerrit returned invalid JSON"
  exit 1
fi
echo "json=$(jq -c . <<< "$json_output" | head -1)" >> "$GITHUB_OUTPUT"
"""

CHECK_FORK_EXISTS = """\
FORK="${FORK_OWNER}/${REPO_NAME}"
output="$(gh api "repos/$FORK" --jq .full_name 2>&1)"
status=$?
if [ "$status" -eq 0 ]; then
  echo 'exists=true' >> "$GITHUB_OUTPUT"
elif grep -q 'HTTP 404' <<< "$output"; then
  echo 'exists=false' >> "$GITHUB_OUTPUT"
else
  echo "::error::Could not check $FORK: $output"
  exit 1
fi
"""

FAILURE_IDIOMS = """\
if ! out=$(packer init "$template" 2>&1); then printf '%s\\n' "$out"; fi
if ! msg=$(git push origin HEAD 2>&1); then
  echo "::error::push failed: $msg"
  exit 1
fi
result=$(helm lint . 2>&1) || { echo "$result"; exit 1; }
"""

DISCARD_IDIOMS = """\
if command -v jq >/dev/null 2>&1; then echo has-jq; fi
docker rm -f c &>/dev/null || true
git rev-parse --verify main > /dev/null 2>&1 && echo ok
version=$(tool --version 2>/dev/null | head -1)
errors=$(make check 2>&1 >/dev/null)
make build 2>&1 | tee build.log
"""


def test_gerrit_query_fixed_is_clean() -> None:
    """The fixed gerrit_query.sh keeps stderr out of the JSON."""
    assert script_rules(GERRIT_QUERY_FIXED) == []


def test_gerrit_query_before_fix_is_high() -> None:
    """The defect that broke gerrit-change-info is reported at high."""
    broken = GERRIT_QUERY_FIXED.replace('2>"$err_file"', "2>&1")
    found = scan_text(broken, "script", "gerrit_query.sh")
    assert [(f.rule, f.confidence, f.variable) for f in found] == [
        ("SEM002", "high", "json_output")
    ]


def test_check_fork_exists_step_is_clean() -> None:
    """A capture used only on the failure path is not reported."""
    assert rules_in(CHECK_FORK_EXISTS) == []


@pytest.mark.parametrize(
    "text", [FAILURE_IDIOMS, DISCARD_IDIOMS], ids=["failure", "discard"]
)
def test_idioms_are_clean(text: str) -> None:
    """Failure-path uses and discards are never reported."""
    assert rules_in(text) == []
    assert script_rules(text) == []


def test_script_functions_keep_their_own_paths() -> None:
    """Path analysis stays within a function."""
    text = """\
    #!/bin/bash
    fetch() {
      local out
      out=$(curl -sf "$1" 2>&1) || { log_error "$out"; return 1; }
      jq -r .tag <<< "$out"
    }
    check() {
      local out
      if ! out=$(curl -sf "$1" 2>&1); then
        error "$out"
        return 1
      fi
    }
    out=unrelated
    jq . <<< "$out"
    """
    found = scan_text(textwrap.dedent(text), "script", "lib.sh")
    assert [(f.rule, f.line, f.variable) for f in found] == [
        ("SEM002", 4, "out")
    ]


def test_yaml_scalar_styles_and_lines() -> None:
    """Block, folded and quoted scalars map findings to their lines."""
    text = textwrap.dedent(
        """\
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  json=$(ssh h q \\
                    --format JSON 2>&1)
                  jq empty <<< "$json"
              - run: >
                  gh api x 2>&1 | jq -r .z
              - run: "v=$(a 2>&1); echo \\"x=$v\\" >> $GITHUB_OUTPUT"
              - run: 'b 2>&1 | yq .'
              - shell: pwsh
                run: c 2>&1 | jq .
        """
    )
    found = scan_text(text, "workflow", "w.yml")
    assert [(f.line, f.rule) for f in found] == [
        (7, "SEM002"),
        (11, "SEM001"),
        (12, "SEM002"),
        (13, "SEM001"),
    ]
    assert found[0].detail == "$json is parsed by jq (line 9)"
    assert found[0].snippet == "json=$(ssh h q \\"


def test_yaml_comment_on_one_line_run_suppresses() -> None:
    """A YAML comment after a one-line ``run:`` value carries the directive.

    YAML takes the comment out of the value, so the shell never sees it.
    """
    text = textwrap.dedent(
        """\
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: 'a 2>&1 | jq .' # stderr-merge-ok -- deliberate
              - run: b 2>&1 | jq .  # gha-workflow-linter: stderr-merge-ok
              - run: "c 2>&1 | jq ."
              - run: d 2>&1 | jq . # allow-list-pin-ok
              - run: 'e 2>&1 | jq . # stderr-merge-ok -- in the shell'
              - run: |
                  f 2>&1 | jq .
              # stderr-merge-ok -- a YAML comment after a block
        """
    )
    found = scan_text(text, "workflow", "w.yml")
    assert [(f.line, f.suppressed, f.reason) for f in found] == [
        (6, True, "deliberate"),
        (7, True, None),
        (8, False, None),
        (9, False, None),
        (10, True, "in the shell"),
        (12, False, None),
    ]


def test_heredoc_body_is_not_shell() -> None:
    """Text in a quoted here-document is not read as commands."""
    body = """\
    cat <<'EOF'
    gh api x 2>&1 | jq .
    EOF
    """
    assert rules_in(body) == []


def test_nested_substitution_in_double_quotes() -> None:
    """A ``$( )`` nested in a double-quoted ``$( )`` is still read."""
    body = (
        'echo "r=$(echo "$(gh api ${{ inputs.x }} 2>&1)" | jq -r .a)" '
        '>> "$GITHUB_OUTPUT"\n'
    )
    found = scan_text(as_workflow(body), "workflow", "w.yml")
    assert [(f.rule, f.detail) for f in found] == [
        ("SEM002", "the captured output is parsed by jq")
    ]


def test_composite_action_step_is_tagged() -> None:
    """A finding in a composite action carries the ``action`` tag."""
    text = textwrap.dedent(
        """\
        runs:
          using: composite
          steps:
            - shell: bash
              run: out=$(gh api x 2>&1); jq . <<< "$out"
        """
    )
    found = scan_text(text, "action", "action.yml")
    assert [(f.rule, f.tags, f.variable) for f in found] == [
        ("SEM002", ("action",), "out")
    ]


def test_workflow_tags() -> None:
    """Workflow tags name the triggers, secrets, writes and checkout."""
    text = textwrap.dedent(
        """\
        on:
          workflow_call:
          pull_request_target:
          workflow_run:
            workflows: [ci]
        permissions:
          contents: write
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ secrets.TOKEN }}"
        """
    )
    assert file_tags(text, "workflow") == (
        "workflow_call",
        "pull_request_target",
        "workflow_run",
        "secrets",
        "write-permissions",
        "no-checkout",
    )
    assert file_tags(WORKFLOW_HEAD, "workflow") == ()
    assert file_tags("on: [push]\njobs: {}\n", "script") == ()
    assert file_tags(": [\n", "workflow") == ()


def test_job_write_all_is_a_write() -> None:
    """``write-all`` on a job counts as a write permission."""
    text = "on: push\njobs:\n  a:\n    permissions: write-all\n"
    assert "write-permissions" in file_tags(text, "workflow")


def test_invalid_yaml_raises() -> None:
    """A workflow that is not YAML cannot be scanned."""
    with pytest.raises(ValueError, match="not valid YAML"):
        scan_text("jobs: [\n", "workflow", "w.yml")


def test_finding_fields() -> None:
    """A finding carries its rule's confidence, fix and JSON form."""
    found = scan_text("gh api x 2>&1 | jq .\n", "script", "s.sh")[0]
    assert found.confidence == "high"
    assert found.fix == RULES["SEM001"].fix
    assert found.to_dict() == {
        "path": "s.sh",
        "line": 1,
        "rule": "SEM001",
        "confidence": "high",
        "detail": "the merged stream is parsed by jq",
        "snippet": "gh api x 2>&1 | jq .",
        "variable": None,
        "tags": [],
        "suppressed": False,
    }


def test_suppression_reason_is_kept() -> None:
    """The directive's reason is kept on the finding."""
    found = scan_text(
        "a 2>&1 | jq .  # stderr-merge-ok -- by design\n", "script", "s.sh"
    )
    assert found[0].suppressed
    assert found[0].reason == "by design"


def _finding(rule: str, *, suppressed: bool = False) -> StderrMergeFinding:
    return StderrMergeFinding("p", 1, rule, "d", "s", suppressed=suppressed)


def test_result_summary_and_enforcement() -> None:
    """Counts leave suppressed findings apart; enforcement has a floor."""
    result = StderrMergeResult(
        [
            _finding("SEM001"),
            _finding("SEM003"),
            _finding("SEM004"),
            _finding("SEM002", suppressed=True),
        ],
        files_scanned=3,
    )
    assert result.summary() == {
        "total": 3,
        "suppressed": 1,
        "files_scanned": 3,
        "by_rule": {"SEM001": 1, "SEM002": 0, "SEM003": 1, "SEM004": 1},
        "by_confidence": {"high": 1, "medium": 1, "low": 1},
    }
    assert [f.rule for f in result.enforced()] == ["SEM001", "SEM003"]
    assert [f.rule for f in result.enforced("low")] == [
        "SEM001",
        "SEM003",
        "SEM004",
    ]
    assert [f.rule for f in result.enforced("high")] == ["SEM001"]


def _write(root: Path, relpath: str, text: str) -> Path:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_scan_repository_discovers_every_kind(tmp_path: Path) -> None:
    """Workflows, actions, scripts and shebang files are all read."""
    merge = "gh api x 2>&1 | jq .\n"
    _write(tmp_path, ".github/workflows/ci.yml", as_workflow(merge))
    _write(
        tmp_path,
        "sub/action.yaml",
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: gh api x 2>&1 | jq .\n",
    )
    _write(tmp_path, "scripts/a.sh", merge)
    _write(tmp_path, "scripts/tool", "#!/bin/sh\n" + merge)
    _write(tmp_path, "node_modules/x/b.sh", merge)
    _write(tmp_path, "skip/c.sh", merge)
    _write(tmp_path, "notes.txt", merge)
    result = scan_repository(tmp_path, exclude=["skip/"])
    assert sorted(f.path for f in result.findings) == [
        ".github/workflows/ci.yml",
        "scripts/a.sh",
        "scripts/tool",
        "sub/action.yaml",
    ]
    assert result.files_scanned == 4
    assert result.problems == ()


def test_scan_repository_skip_actions(tmp_path: Path) -> None:
    """``skip_actions`` leaves action metadata out, unless it is named."""
    _write(
        tmp_path,
        "sub/action.yml",
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: gh api x 2>&1 | jq .\n",
    )
    _write(tmp_path, "scripts/a.sh", "gh api x 2>&1 | jq .\n")
    skipped = scan_repository(tmp_path, skip_actions=True)
    named = scan_repository(
        tmp_path, files=["sub/action.yml"], skip_actions=True
    )
    assert [f.path for f in skipped.findings] == ["scripts/a.sh"]
    assert [f.path for f in named.findings] == ["sub/action.yml"]


def test_scan_repository_named_files(tmp_path: Path) -> None:
    """Files named with --files are scanned whatever their name."""
    _write(tmp_path, "notes.txt", "gh api x 2>&1 | jq .\n")
    _write(tmp_path, "skip/c.sh", "gh api x 2>&1 | jq .\n")
    result = scan_repository(
        tmp_path, files=["notes.txt", "skip/*.sh"], exclude=["skip/"]
    )
    assert [f.path for f in result.findings] == ["notes.txt", "skip/c.sh"]


def test_scan_repository_named_absolute_glob(tmp_path: Path) -> None:
    """An absolute --files glob expands from the filesystem root."""
    _write(tmp_path, "s/a.sh", "gh api x 2>&1 | jq .\n")
    result = scan_repository(tmp_path, files=[f"{tmp_path}/s/*.sh"])
    assert [f.path for f in result.findings] == ["s/a.sh"]
    assert result.problems == ()


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="needs a directory the user cannot list",
)
def test_scan_repository_prunes_excluded_directories(tmp_path: Path) -> None:
    """An excluded directory is not entered, so unreadable is no problem."""
    locked = tmp_path / "build" / "locked"
    locked.mkdir(parents=True)
    locked.chmod(0)
    try:
        result = scan_repository(tmp_path, exclude=["build/"])
        unexcluded = scan_repository(tmp_path)
    finally:
        locked.chmod(0o700)
    assert result.problems == ()
    assert len(unexcluded.problems) == 1


def test_scan_repository_reports_unreadable_yaml(tmp_path: Path) -> None:
    """A workflow that is not YAML is a problem, not a crash."""
    _write(tmp_path, ".github/workflows/bad.yml", "jobs: [\n")
    result = scan_repository(tmp_path)
    assert result.findings == []
    assert len(result.problems) == 1
    assert result.problems[0].startswith(".github/workflows/bad.yml: ")


def test_scan_repository_reports_a_missing_named_file(tmp_path: Path) -> None:
    """A literal --files path that does not exist is a problem."""
    result = scan_repository(tmp_path, files=["scripts/typo.sh"])
    assert result.files_scanned == 1
    assert len(result.problems) == 1
    assert result.problems[0].startswith("scripts/typo.sh: ")


def test_scan_repository_glob_matching_nothing(tmp_path: Path) -> None:
    """A --files glob that matches nothing is no problem."""
    result = scan_repository(tmp_path, files=["scripts/*.sh"])
    assert result.files_scanned == 0
    assert result.problems == ()
