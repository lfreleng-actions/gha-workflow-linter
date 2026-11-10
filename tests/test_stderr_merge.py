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
        OUTPUT=$(./version-extract "${ARGS[@]}" 2>&1)
        JSON_LINE=$(echo "${OUTPUT}" | sed -n '/^{/,/^}/p')
        """,
        ["SEM002"],
        id="sed-range-is-not-a-prefix",
    ),
    pytest.param(
        """\
        out=$(tool 2>&1)
        body=$(awk '/^BEGIN-JSON/,/^END-JSON/' <<< "$out")
        """,
        ["SEM002"],
        id="awk-range-is-not-a-prefix",
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
        "v=$(docker exec -i box openssl s_client -connect h:443 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM004"],
        id="openssl-through-docker-exec",
    ),
    pytest.param(
        'v=$(docker exec box curl -s x 2>&1)\njq . <<< "$v"\n',
        ["SEM002"],
        id="ordinary-command-through-docker-exec",
    ),
    pytest.param(
        "v=$(docker run --rm -e A=1 -v /a:/b img openssl s_client 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM004"],
        id="openssl-through-docker-run",
    ),
    pytest.param(
        'v=$(podman exec box openssl s_client 2>&1)\njq . <<< "$v"\n',
        ["SEM004"],
        id="openssl-through-podman-exec",
    ),
    pytest.param(
        "v=$(kubectl -n ns exec pod -c c -- openssl s_client 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM004"],
        id="openssl-through-kubectl-exec",
    ),
    pytest.param(
        "v=$(ssh -i key -p 22 host 'openssl s_client' 2>&1)\njq . <<< \"$v\"\n",
        ["SEM004"],
        id="openssl-through-ssh",
    ),
    pytest.param(
        "v=$(ssh host 'curl x' 2>&1)\njq . <<< \"$v\"\n",
        ["SEM002"],
        id="ordinary-command-through-ssh",
    ),
    pytest.param(
        "v=$(ssh host 'openssl s_client -connect h:443; curl -s x' 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM002"],
        id="compound-program-through-ssh",
    ),
    pytest.param(
        "v=$(ssh host 'openssl s_client | curl -s x' 2>&1)\njq . <<< \"$v\"\n",
        ["SEM002"],
        id="pipeline-through-ssh",
    ),
    pytest.param(
        "v=$(ssh host 'openssl s_client -connect \"a;b\"' 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM004"],
        id="quoted-operator-through-ssh",
    ),
    pytest.param(
        "v=$(docker run --entrypoint curl img openssl s_client 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM002"],
        id="entrypoint-through-docker-run",
    ),
    pytest.param(
        "v=$(podman run --entrypoint=curl img openssl s_client 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM002"],
        id="entrypoint-equals-through-podman-run",
    ),
    pytest.param(
        "id=$(docker run -d img openssl s_client 2>&1)\n"
        'echo "id=$id" >> "$GITHUB_OUTPUT"\n',
        ["SEM002"],
        id="detached-docker-run",
    ),
    pytest.param(
        "id=$(docker run --detach img openssl s_client 2>&1)\n"
        'echo "id=$id" >> "$GITHUB_OUTPUT"\n',
        ["SEM002"],
        id="detached-long-docker-run",
    ),
    pytest.param(
        "id=$(docker run -dit --rm img openssl s_client 2>&1)\n"
        'echo "id=$id" >> "$GITHUB_OUTPUT"\n',
        ["SEM002"],
        id="detached-cluster-docker-run",
    ),
    pytest.param(
        "id=$(docker exec -d box openssl s_client 2>&1)\n"
        'echo "id=$id" >> "$GITHUB_OUTPUT"\n',
        ["SEM002"],
        id="detached-docker-exec",
    ),
    pytest.param(
        "v=$(docker exec -it --detach-keys ctrl-x box openssl s_client 2>&1)\n"
        'jq . <<< "$v"\n',
        ["SEM004"],
        id="detach-keys-is-not-detach",
    ),
    pytest.param(
        "v=$(sudo docker container exec -u root box timeout 5 "
        'openssl s_client 2>&1)\njq . <<< "$v"\n',
        ["SEM004"],
        id="wrappers-around-and-inside-a-launcher",
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
        "a 2>&1 | jq .  # stderr-merge-ok -- inline reason\n",
        ["SEM001!"],
        id="suppressed-inline",
    ),
    pytest.param(
        "a 2>&1 | jq .  # gha-workflow-linter: allow-list-pin-ok\n",
        ["SEM001"],
        id="other-directive-does-not-suppress",
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


def test_scan_repository_stops_at_nested_repositories(tmp_path: Path) -> None:
    """A worktree or clone below the root is another checkout."""
    (tmp_path / ".git").mkdir()
    _write(tmp_path, "a.sh", "gh api x 2>&1 | jq .\n")
    _write(tmp_path, ".worktrees/topic/.git", "gitdir: ../../.git/wt\n")
    _write(tmp_path, ".worktrees/topic/a.sh", "gh api x 2>&1 | jq .\n")
    (tmp_path / "vendor" / "lib" / ".git").mkdir(parents=True)
    _write(tmp_path, "vendor/lib/b.sh", "gh api x 2>&1 | jq .\n")

    result = scan_repository(tmp_path)

    assert [f.path for f in result.findings] == ["a.sh"]
    assert result.problems == ()


def test_named_files_in_a_nested_repository_are_scanned(
    tmp_path: Path,
) -> None:
    """``--files`` bypasses discovery, so the boundary does not apply."""
    (tmp_path / "vendor" / "lib" / ".git").mkdir(parents=True)
    _write(tmp_path, "vendor/lib/b.sh", "gh api x 2>&1 | jq .\n")

    result = scan_repository(tmp_path, files=["vendor/lib/b.sh"])

    assert [f.path for f in result.findings] == ["vendor/lib/b.sh"]


def test_scan_repository_reads_an_invalid_timestamp(tmp_path: Path) -> None:
    """A value safe_load cannot build leaves the tags, not the shell."""
    _write(
        tmp_path,
        ".github/workflows/w.yml",
        "on: push\n"
        "env: {VERSION: 2026-13-01}\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: gh api x 2>&1 | jq .\n",
    )

    result = scan_repository(tmp_path)

    assert [f.rule for f in result.findings] == ["SEM001"]
    assert result.findings[0].tags == ()
    assert result.problems == ()


def test_scan_repository_reports_unreadable_yaml(tmp_path: Path) -> None:
    """A workflow that is not YAML is a problem, not a crash."""
    _write(tmp_path, ".github/workflows/bad.yml", "jobs: [\n")
    result = scan_repository(tmp_path)
    assert result.findings == []
    assert len(result.problems) == 1
    assert result.problems[0].startswith(".github/workflows/bad.yml: ")
