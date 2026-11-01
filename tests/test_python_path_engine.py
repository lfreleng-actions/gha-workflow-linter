# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the Python import-path scan engine."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

from gha_workflow_linter.python_path import _engine as audit

PLANTED_MARKER = "PLANTED-CODE-RAN"


def rules(text: str, kind: str = "script") -> list[str]:
    """The rule of each finding in ``text``."""
    return [f.rule for f in audit.scan_text(text, kind, "repo", "file")]


def action_step(line: str) -> str:
    """An action whose one step runs ``line``."""
    return f"runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        {line}\n"


class OracleTest(unittest.TestCase):
    """The scanner agrees with what Python really does.

    Each case runs under bash in a directory holding a planted
    ``csv.py`` and a planted ``trusted_pkg``. A case counts when
    planted code ran. The scanner must report exactly the cases where
    it ran, with two deliberate exceptions: -P is reported as partial
    although it protects on the Python running the tests, and a ``cd``
    into a directory other than the action's own is reported, since
    the scanner cannot judge an arbitrary directory's trust.
    """

    tmp: tempfile.TemporaryDirectory[str]
    bin: str
    trusted: str
    work: str

    CASES = [
        # (shell, expected rule or None, planted code ran on this Python)
        ('PYTHONPATH="$T" python3 -m trusted_pkg.main', "PPA001", True),
        ('python3 -c "import csv"', "PPA002", True),
        ('python3 -E -c "import csv"', "PPA002", True),
        ('python3 -X utf8 -c "import csv"', "PPA002", True),
        ('echo "import csv" | python3', "PPA003", True),
        ('python3 - < "$T/snippet.py"', "PPA003", True),
        ('python3 < "$T/snippet.py"', "PPA003", True),
        ('python3 -I -c "import csv"', None, False),
        ('python3 -Ic "import csv"', None, False),
        ('python3 -W ignore -I -c "import csv"', None, False),
        ('python3 -s -I -E -c "import csv"', None, False),
        ('python3 "$T/script.py"', None, False),
        ('python3 -I "$T/script.py"', None, False),
        ('PYTHONPATH="$T:" python3 "$T/script.py"', "PPA004", True),
        ('PYTHONPATH=":$T" python3 "$T/script.py"', "PPA004", True),
        ('PYTHONPATH="$T:$PYTHONPATH" python3 "$T/script.py"', "PPA004", True),
        (
            'PYTHONPATH="$T${PYTHONPATH:+:$PYTHONPATH}" python3 "$T/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="$T${PYTHONPATH:+:${PYTHONPATH}}" python3 "$T/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}$T" python3 "$T/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:-}:$T" python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:-$T}:$T" python3 "$T/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH}:$T" python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        ('PYTHONPATH="$T::$T" python3 "$T/script.py"', "PPA004", True),
        ('PYTHONPATH="$T" python3 "$T/script.py"', None, False),
        ('PYTHONPATH="$T:" python3 -I "$T/script.py"', "PPA004", False),
        ("python3 --version", None, False),
        # Start-up modules cannot be shadowed, but sitecustomize runs
        # from an empty PYTHONPATH entry whatever the program imports.
        ('python3 -c "import sys"', "PPA002", False),
        (
            'PYTHONPATH="$T:" python3 -c "import sys"',
            ("PPA002", "PPA004"),
            True,
        ),
        (
            '(cd -- "$GITHUB_ACTION_PATH" && python3 -E -s -m trusted_pkg.main)',
            None,
            False,
        ),
        (
            'cd "$GITHUB_ACTION_PATH" && cd "$OLDPWD" && python3 -m trusted_pkg.main',
            "PPA001",
            True,
        ),
        (
            'cd "$T" && PYTHONPATH="$T" python3 -m trusted_pkg.main',
            "PPA001",
            False,
        ),
        # A path that climbs out of the action's directory leaves it.
        (
            'cd "$GITHUB_ACTION_PATH/../work" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A variable reassigned to the workspace is no longer trusted.
        (
            'dir="$GITHUB_ACTION_PATH"; dir="$PWD"; cd "$dir"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A cd in a subshell or substitution ends with it.
        (
            '(cd "$GITHUB_ACTION_PATH" && :); python3 -c "import csv"',
            "PPA002",
            True,
        ),
        (
            'echo "$(cd "$GITHUB_ACTION_PATH" && pwd)"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A heredoc body with an unquoted delimiter runs its substitutions.
        ('cat <<EOF\n$(python3 -c "import csv")\nEOF', "PPA002", True),
        ("cat <<'EOF'\n$(python3 -c \"import csv\")\nEOF", None, False),
        # "<<" inside quotes is text, not a heredoc.
        ("echo '<<EOF'\npython3 -c 'import csv'", "PPA002", True),
        # A heredoc opened in a quoted substitution is read first.
        (
            'got="$(python3 -I - <<\'PY\'\nprint("$(")\nPY\n)"\npython3 -c "import csv"',
            "PPA002",
            True,
        ),
        # Input redirections are not arguments.
        ('python3 < "$T/snippet.py" -I', None, False),
        ('python3 0< "$T/snippet.py"', "PPA003", True),
        # Set but empty is not unset: "+" tests only for set.
        (
            'export PYTHONPATH=; PYTHONPATH="$T${PYTHONPATH+:$PYTHONPATH}" '
            'python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # Single quotes keep "$" literal: no empty entry here.
        (
            "PYTHONPATH='/nonexistent:$PYTHONPATH' python3 \"$T/script.py\"",
            None,
            False,
        ),
        # Text joined onto the action path names a sibling directory.
        (
            'cd "${GITHUB_ACTION_PATH}-cache" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A skipped cd does not count: true succeeds, so cd never runs.
        (
            'true || cd "$GITHUB_ACTION_PATH" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A failed cd leaves the directory where it was.
        (
            'if cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; then :; '
            'else python3 -c "import csv"; fi',
            "PPA002",
            True,
        ),
        # Code after return does not run.
        (
            'f() { return; cd "$GITHUB_ACTION_PATH"; }; f; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A function defined in a subshell stays there.
        (
            'f() { cd "$PWD"; }; ( f() { cd "$GITHUB_ACTION_PATH"; } ); f; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A local variable is gone once its function returns.
        (
            'dir="$PWD"; f() { local dir="$GITHUB_ACTION_PATH"; }; f; cd "$dir"; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # ;& runs the next arm's body too.
        (
            'cd "$GITHUB_ACTION_PATH"; case x in x) cd "$OLDPWD" ;& *) '
            'python3 -c "import csv" ;; esac',
            "PPA002",
            True,
        ),
        # A loop that keeps climbing leaves the action directory.
        (
            'cd "$GITHUB_ACTION_PATH/a/b"; '
            'for n in 1 2 3 4; do python3 -c "import csv"; cd ..; done',
            "PPA002",
            True,
        ),
        # Options held in a variable are still options.
        ('opts=-E; python3 "$opts" -c "import csv"', "PPA002", True),
        # A value is taken when it is assigned.
        (
            'PY=python3; CMD=$PY; PY=echo; $CMD -c "import csv"',
            "PPA002",
            True,
        ),
        # A variable's empty entry is still empty in PYTHONPATH.
        ('P="$T:"; PYTHONPATH="$P" python3 "$T/script.py"', "PPA004", True),
        # Setting one element changes only that element.
        (
            "PY=(python3 -I); PY[1]=-E; \"${PY[@]}\" -c 'import csv'",
            "PPA002",
            True,
        ),
        # A subscript selects one element; no subscript, the first.
        (
            "PY_RUN=(python3 -I); \"${PY_RUN[0]}\" -c 'import csv'",
            "PPA002",
            True,
        ),
        ("PY_RUN=(python3 -I); ${PY_RUN} -c 'import csv'", "PPA002", True),
        # A function defined on one branch only may not exist.
        (
            "if false; then python3() { :; }; fi; python3 -c 'import csv'",
            "PPA002",
            True,
        ),
        # A function shadows the builtin of its name.
        (
            'cd() { :; }; cd "$GITHUB_ACTION_PATH"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A function fails where its body fails.
        (
            'f() { cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; }; '
            'f || python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # env's option operands are not the program.
        (
            'env -u PYTHONHOME PYTHONPATH="$T:" python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # Substitutions in an arithmetic for loop run; what the planted
        # module prints is echoed back so the oracle sees it.
        (
            "for ((i=$(python3 -c 'import csv' | tee /dev/stderr | wc -l); i<0; i++)); "
            "do :; done 2>&1",
            "PPA002",
            True,
        ),
        # An unquoted array element splits into words.
        ("PY=('python3 -E'); $PY -c 'import csv'", "PPA002", True),
        # -e is off in a condition list, so a failed cd is followed.
        (
            'if cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; true; then '
            "python3 -c 'import csv'; fi",
            "PPA002",
            True,
        ),
        # ...and in a function whose status is tested.
        (
            'f() { cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; '
            "python3 -c 'import csv'; }; f || :",
            "PPA002",
            True,
        ),
        # A variable holding a builtin's name runs the builtin.
        (
            'go=cd; cd "$GITHUB_ACTION_PATH"; "$go" "$OLDPWD"; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A function's prefix assignment holds only while it runs.
        (
            'dir="$GITHUB_ACTION_PATH"; f() { cd "$dir"; }; dir="$PWD" f; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A function's arguments become $@.
        ('f() { python3 "$@"; }; f -c "import csv"', "PPA002", True),
        # A relative directory follows the wrappers before it.
        (
            'cd "$GITHUB_ACTION_PATH"; env -C "$OLDPWD" env -C . '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # Quoting does not change what - means to cd.
        (
            'cd "$GITHUB_ACTION_PATH"; cd "-" >/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # += appends: here, to a value with no empty entry.
        (
            'export PYTHONPATH="$T"; PYTHONPATH+=":$T"; python3 "$T/script.py"',
            None,
            False,
        ),
        # A link from the action directory can lead anywhere.
        (
            'ln -sfn "$PWD" "$T/link"; '
            'cd "$(readlink "$GITHUB_ACTION_PATH/link")" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A quoted export operand still assigns.
        (
            'export "PYTHONPATH=$T:"; python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # Arrays keep their indices.
        ("PY=(); PY[1]=python3; \"${PY[1]}\" -c 'import csv'", "PPA002", True),
        # uv by path is still uv.
        (
            '"$(command -v uv)" run --no-config --no-project --python "$(command -v python3)" '
            "python -c 'import csv'",
            "PPA002",
            True,
        ),
        # A declaration builtin by quoted name or through builtin.
        ('"export" PYTHONPATH="$T:"; python3 "$T/script.py"', "PPA004", True),
        (
            'builtin export PYTHONPATH="$T:"; python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # An empty expansion is removed from the command line.
        ("opts=; python3 ${opts:-} -c 'import csv'", "PPA002", True),
        # Under set -e, ! keeps going after a failure.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; ! cd "$OLDPWD"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # read sets its names from input.
        (
            "opts=-I; read -r opts <<<'-E'; python3 \"$opts\" -c 'import csv'",
            "PPA002",
            True,
        ),
        # A local made on one path only leaves the global on the other.
        (
            'set -e; dir="$GITHUB_ACTION_PATH"; f() { if [ -n "$1" ]; then local dir="$1"; '
            'else dir="$PWD"; fi; }; f; cd "$dir"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # set -- ends set's options.
        (
            'set -- -e; cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A command held in an array is checked like any other.
        (
            'cmd=(env PYTHONPATH="$T:" python3); "${cmd[@]}" "$T/script.py"',
            "PPA004",
            True,
        ),
        # set +e: a failed cd leaves the directory where it was.
        (
            'set +e; cd "$GITHUB_ACTION_PATH/missing" 2>/dev/null; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # CDPATH can send a relative cd anywhere.
        (
            'mkdir -p lib && cp csv.py lib/; export CDPATH="$PWD"; '
            'cd "$GITHUB_ACTION_PATH"; cd lib >/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # env assignments count behind other wrappers.
        (
            'command env PYTHONPATH="$T:" python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # -- ends Python's options: the next word is a script.
        ('python3 -- "$T/script.py" -m', None, False),
        # A function named pwd prints what it likes.
        (
            'set -e; pwd() { printf "%s\\n" "$OLDPWD"; }; cd "$GITHUB_ACTION_PATH"; '
            'cd "$(pwd)"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A builtin sees its prefix assignments.
        (
            'set -e; mkdir -p lib && cp csv.py lib/; cd "$GITHUB_ACTION_PATH"; '
            'CDPATH="$OLDPWD" cd lib >/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # CDPATH searches dot-prefixed names too.
        (
            'set -e; mkdir -p .hidden && cp csv.py .hidden/; export CDPATH="$PWD"; '
            'cd "$GITHUB_ACTION_PATH"; cd .hidden >/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # An option's operand is not the script.
        (
            'python3 --check-hash-based-pycs always -c "import csv"',
            "PPA002",
            True,
        ),
        # A program run through env expands from what the walk knows.
        (
            'PY="$(command -v python3)"; env "$PY" -c "import csv"',
            "PPA002",
            True,
        ),
        # A value built from PYTHONPATH keeps its colons.
        (
            'unset PYTHONPATH; composed="$T:$PYTHONPATH"; '
            'export PYTHONPATH="$composed"; python3 "$T/script.py"',
            "PPA004",
            True,
        ),
        # HOME can point anywhere.
        ('set -e; HOME="$PWD"; cd; python3 -c "import csv"', "PPA002", True),
    ]

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        cls.bin = os.path.join(base, "bin")
        cls.trusted = os.path.join(base, "trusted")
        cls.work = os.path.join(base, "work")
        for directory in (cls.bin, cls.trusted, cls.work):
            os.makedirs(directory)
        os.symlink(sys.executable, os.path.join(cls.bin, "python3"))
        package = os.path.join(cls.trusted, "trusted_pkg")
        os.makedirs(package)
        cls._write(os.path.join(package, "__init__.py"), "")
        cls._write(os.path.join(package, "main.py"), "import csv\n")
        cls._write(os.path.join(cls.trusted, "script.py"), "import csv\n")
        cls._write(os.path.join(cls.trusted, "snippet.py"), "import csv\n")
        cls._write(
            os.path.join(cls.work, "csv.py"), f"print({PLANTED_MARKER!r})\n"
        )
        # An empty PYTHONPATH entry runs this at start-up, before any
        # import the program makes.
        cls._write(
            os.path.join(cls.work, "sitecustomize.py"),
            f"print({PLANTED_MARKER!r})\n",
        )
        planted = os.path.join(cls.work, "trusted_pkg")
        os.makedirs(planted)
        cls._write(os.path.join(planted, "__init__.py"), "")
        cls._write(
            os.path.join(planted, "main.py"), f"print({PLANTED_MARKER!r})\n"
        )
        # Outside the trusted tree but not in the workspace: its parent,
        # and a sibling named like it. Python run there must be reported.
        os.makedirs(os.path.join(cls.trusted, "a", "b"))
        os.makedirs(cls.trusted + "-cache")
        for outside in (base, cls.trusted + "-cache"):
            cls._write(
                os.path.join(outside, "csv.py"), f"print({PLANTED_MARKER!r})\n"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    @staticmethod
    def _write(path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def planted_code_ran(self, shell: str) -> bool:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("PYTHON")
        }
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["T"] = self.trusted
        env["GITHUB_ACTION_PATH"] = self.trusted
        result = subprocess.run(
            ["bash", "-c", shell],
            cwd=self.work,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return PLANTED_MARKER in result.stdout

    def test_cases(self) -> None:
        for shell, rule, planted_ran in self.CASES:
            with self.subTest(shell=shell):
                self.assertEqual(
                    self.planted_code_ran(shell), planted_ran, "oracle drifted"
                )
                expected = (
                    list(rule)
                    if isinstance(rule, tuple)
                    else [rule]
                    if rule
                    else []
                )
                self.assertEqual(rules(shell), expected)

    @unittest.skipIf(sys.version_info < (3, 11), "-P needs Python 3.11")
    def test_dash_p_is_partial(self) -> None:
        shell = 'python3 -P -c "import csv"'
        self.assertFalse(self.planted_code_ran(shell))
        findings = audit.scan_text(shell, "script", "repo", "file")
        self.assertEqual([f.rule for f in findings], ["PPA002"])
        self.assertIn("partial", findings[0].detail)
        # -P does not drop an empty PYTHONPATH entry: sitecustomize runs.
        shell = 'PYTHONPATH="$T:" python3 -P "$T/script.py"'
        self.assertTrue(self.planted_code_ran(shell))
        self.assertEqual(rules(shell), ["PPA004"])


class ParsingTest(unittest.TestCase):
    """How invocations and files are read."""

    def test_interpreter_forms(self) -> None:
        self.assertEqual(rules("/usr/bin/python3 -m pip install x"), ["PPA001"])
        self.assertEqual(rules("python3.12 -m build"), ["PPA001"])
        self.assertEqual(rules("python -m pytest"), ["PPA001"])
        self.assertEqual(
            rules(
                'uv run --no-config --no-project --python "$py" python -m pytest'
            ),
            ["PPA001"],
        )
        self.assertEqual(rules('out=$(python3 -c "print(1)")'), ["PPA002"])
        self.assertEqual(rules("cd x && python3 -m y"), ["PPA001"])
        self.assertEqual(rules("python3 -Im y"), [])

    def test_lookalikes_are_ignored(self) -> None:
        for text in (
            "uses: actions/setup-python@abc",
            "python-version: '3.12'",
            "cat .python-version",
            "pip install python-dateutil",
            "# python3 -m commented out",
            "echo done # python3 -m in a trailing comment",
            'case "$lang" in\n  java|python|go) ;;\n  python) echo ok ;;\nesac',
            "add_language python",
            "if command -v python3 > /dev/null 2>&1; then",
            'py="$(command -v python)"',
            "for candidate in python3 python; do",
            'echo "python on PATH: $(command -v python || true)"',
            "which python3",
            "true  # note; python3 -m x",
            "echo 'not $(python3 -m x) in single quotes'",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_command_positions(self) -> None:
        for text, rule in (
            ("if ! python3 -m x; then", "PPA001"),
            ("then python3 -m x", "PPA001"),
            ("while python3 -c 'import x'; do", "PPA002"),
            (
                'uv run --no-config --no-project --python "$py" --with pyyaml python -m x',
                "PPA001",
            ),
            (
                "uv run --no-config --no-project --python \"$py\" python - <<'PY'",
                "PPA003",
            ),
            ('"$VENV/bin/python" -m x', "PPA001"),
            ("x=$(python3 - <<EOF", "PPA003"),
            ("FOO=1 BAR='a b' python3 -m x", "PPA001"),
            ("exec python3 -m x", "PPA001"),
            ("env python3 -m x", "PPA001"),
            ("a && python3 -c 'import y'", "PPA002"),
            ("a || python3 -c 'import y'", "PPA002"),
            ("{ python3 -m x; }", "PPA001"),
            ('echo "result: $(python3 -m x)"', "PPA001"),
            ('echo "result: `python3 -m x`"', "PPA001"),
            ("python3 > \"$out\" <<'PY'", "PPA003"),
            ("python3 2> /dev/null < input.py", "PPA003"),
            ("command python3 -m x", "PPA001"),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [rule])

    def test_two_invocations_on_one_line(self) -> None:
        self.assertEqual(rules("python3 -I -m a; python3 -m b"), ["PPA001"])

    def test_continuation_lines(self) -> None:
        text = "python3 \\\n  -I \\\n  -m module\npython3 \\\n  -m other\n"
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 4)])

    def test_heredoc_inside_a_quoted_substitution(self) -> None:
        """A heredoc opened inside "$(...)" is read before the quote closes.

        Taken from generic-workflows' test-lint-plan.sh, where reading the
        body as part of the quoted text lost the lines after it.
        """
        text = textwrap.dedent(
            """\
            got="$("${PY_RUN[@]}" - "${resolver}" "${url}" <<'PYEOF'
            import ast
            import sys
            source = open(sys.argv[1], encoding="utf-8").read()
            namespace = {"urllib": urllib}
            if missing:
                sys.exit(f"resolver is missing: {missing}")
            print(
                namespace["display_config"](
                    {"kind": "url", "config": sys.argv[2]}
                )
            )
            PYEOF
            )"

              if [ "${got}" = "${expect}" ]; then
                passed=$((passed + 1))
              fi
            python3 -m after
            """
        )
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertIn(("PPA001", 19), [(f.rule, f.line) for f in findings])

    def test_heredoc_body_is_not_shell(self) -> None:
        text = textwrap.dedent(
            """\
            python3 -I - <<'PY'
            cmd = "python3 -m inside"
            os.system("python3 -c 'import x'")
            PY
            cat <<EOF | python3 -I -
            python3 -m also-inside
            EOF
            python3 -m after
            """
        )
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 8)])

    def test_here_string_is_not_a_heredoc(self) -> None:
        self.assertEqual(
            rules("python3 -m a <<< x\npython3 -m b"), ["PPA001", "PPA001"]
        )

    def test_quoted_strings_span_lines(self) -> None:
        for text, expected in (
            (
                'docker exec c bash -c "\n  cd /tmp &&\n  uv run main.py\n"\npython3 -m after',
                ["PPA001"],
            ),
            ('python3 -c "\nimport json\nprint(1)\n"', ["PPA002"]),
            ("python3 -I -c '\nimport json\n'\npython3 -m after", ["PPA001"]),
            ("cat <<'EOF'\ndon't stop here\nEOF\npython3 -m after", ["PPA001"]),
            ("echo $'it\\'s'\npython3 -m after", ["PPA001"]),
            (
                'got="$(python3 -I - "$f" <<\'PYEOF\'\nprint("it\'s", ")")\nPYEOF\n)"\n'
                "python3 -m after",
                ["PPA001"],
            ),
            (
                "got=\"$(python3 - <<'PYEOF'\nimport json\nPYEOF\n)\"\npython3 -I -m after",
                ["PPA003"],
            ),
            (
                'v="$(awk \'/^x:/ { f = 1 }\n  f && /d:/ { gsub(/[" ]/, "", $2) }\' \\\n'
                '  action.yaml)"\npython3 -E -s -m unittest',
                ["PPA001"],
            ),
            ('x="$(echo "(nested)")"\npython3 -m after', ["PPA001"]),
            ("# it's a comment\npython3 -m after", ["PPA001"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_yaml_reads_run_blocks_only(self) -> None:
        text = textwrap.dedent(
            """\
            name: python3 -m not-a-command
            description: runs python3 -c in prose
            runs:
              using: composite
              steps:
                - run: python3 -m single
                  shell: bash
                - name: block
                  shell: bash
                  run: |
                    set -e
                    python3 -c "import x"
                - run: >-
                    python3
                    -I -m folded
                - name: after
                  with:
                    script: python3 -m outside-run
            """
        )
        findings = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertEqual(
            [(f.rule, f.line) for f in findings],
            [("PPA001", 6), ("PPA002", 12)],
        )

    def test_quoted_single_line_run(self) -> None:
        self.assertEqual(rules("- run: 'python3 -m x'", "workflow"), ["PPA001"])

    def test_ignore_mark(self) -> None:
        self.assertEqual(rules("python3 -m x  # python-path-audit: ignore"), [])
        self.assertEqual(rules("# python-path-audit: ignore\npython3 -m x"), [])

    def test_safepath_variable_is_partial(self) -> None:
        text = "export PYTHONSAFEPATH=1\npython3 -m x\n"
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertIn("partial", findings[0].detail)


class UvOracleTest(unittest.TestCase):
    """The uv rules agree with what uv really runs.

    Each case runs under bash in a workspace holding a .python-version
    that names one planted interpreter and a .venv holding another;
    each writes its own marker as it starts and then fails. uv passes
    over an interpreter that fails, so a command that still works
    proves nothing: only the markers count. The scanner must report
    PPA006 exactly when the .python-version interpreter ran and PPA007
    exactly when the .venv one did.
    """

    CASES = [
        "uv run --no-project python s.py",
        "uv run --no-config --no-project python s.py",
        "uv run --no-config --no-project --with six python -I s.py",
        "uv run --isolated --no-project python s.py",
        "uv run --no-project -p 3.12 python s.py",
        "UV_PYTHON=3.12 uv run --no-config --no-project python s.py",
        'uv run --no-config --no-project --python "$GOOD" python s.py',
        'UV_PYTHON="$GOOD" uv run --no-project python s.py',
        'py="$(cd "$T" && UV_NO_CONFIG=1 uv python find --system)"\n'
        'uv run --no-config --no-project --python "$py" python s.py',
        'uv run --no-config --no-project --directory "$GITHUB_ACTION_PATH" python "$S"',
        'VIRTUAL_ENV="$GOODVENV" uv run --no-config --no-project python s.py',
        "UV_SYSTEM_PYTHON=1 uv run --no-config --no-project python s.py",
        "uv run --script s.py",
        "uv run --no-config --locked --script s.py",
        'uv venv "$OUT/v1"',
        'uv venv --no-config "$OUT/v2"',
        "uv python find",
        "UV_NO_CONFIG=1 uv python find",
        "uv python find --system",
        "UV_NO_CONFIG=1 uv python find --system",
        "UV_NO_CONFIG=1 UV_SYSTEM_PYTHON=1 uv python find",
        "uv pip install --dry-run six",
        "uv pip install --dry-run --no-config six",
        "uv pip install --dry-run -p 3.12 six",
        'uv pip install --dry-run --python "$GOOD" six',
        "uv pip install --dry-run --system six",
        'VIRTUAL_ENV="$GOODVENV" uv pip install --dry-run six',
        "uv pip list",
        "uv pip freeze",
        "uv pip compile req.txt",
        "uvx --from six python -c pass",
        "uv tool run --from six python -c pass",
        # A command's own assignment reaches only that command.
        "UV_NO_CONFIG=1 true\nuv python find --system",
        'UV_NO_CONFIG=1 uv venv "$OUT/v3"\nuv venv "$OUT/v4"',
        # Without export, an assignment stays in the shell.
        "UV_NO_CONFIG=1\nuv python find --system",
        "export UV_NO_CONFIG=1\nuv python find --system",
        # The launched program's arguments are not uv's.
        "uv run -- python s.py --no-config",
        'uv run python s.py --python "$GOOD"',
        # A relative environment names the workspace's own .venv.
        "VIRTUAL_ENV=.venv uv pip install --dry-run six",
        "uv pip install --dry-run --python .venv/bin/python six",
        # uv works where --directory says, whatever the shell's directory.
        'cd "$GITHUB_ACTION_PATH"; uv run --directory "$OLDPWD" --no-project python s.py',
        'uv run --directory "$GITHUB_ACTION_PATH" --no-config --no-project python "$S"',
        # uv's global options can come before the subcommand.
        "uv --no-config run --no-project python s.py",
        # An explicit --python overrides UV_PYTHON.
        'UV_PYTHON="$GOOD" uv pip install --dry-run --python .venv/bin/python six',
        # export -n and unset remove a setting, however it is quoted.
        "export UV_NO_CONFIG=1; export -n UV_NO_CONFIG=1; uv python find --system",
        'export UV_NO_CONFIG=1; unset "UV_NO_CONFIG"; uv python find --system',
        # A setting made on one branch only does not protect.
        'if test -n "$PIN"; then UV_PYTHON="$GOOD"; fi; export UV_PYTHON; uv venv "$OUT/v5"',
        # A relative interpreter is resolved where uv runs.
        'cd "$GITHUB_ACTION_PATH"; uv --directory "$OLDPWD" pip list --python .venv/bin/python',
        # declare +x stops exporting.
        "export UV_NO_CONFIG=1; declare +x UV_NO_CONFIG; uv python find --system",
    ]

    uv: str
    tmp: tempfile.TemporaryDirectory[str]
    base: str
    trusted: str
    good: str
    goodvenv: str

    @classmethod
    def setUpClass(cls) -> None:
        uv = shutil.which("uv")
        if not uv:
            raise unittest.SkipTest("uv is not installed")
        cls.uv = uv
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        cls.base = base
        cls.trusted = os.path.join(base, "action")
        os.makedirs(cls.trusted)
        found = subprocess.run(
            [cls.uv, "python", "find", "--system"],
            cwd=cls.trusted,
            env={**os.environ, "UV_NO_CONFIG": "1"},
            capture_output=True,
            text=True,
            check=False,
        )
        if found.returncode != 0:
            raise unittest.SkipTest("uv found no Python interpreter")
        cls.good = found.stdout.strip()
        cls.goodvenv = os.path.join(base, "goodvenv")
        subprocess.run(
            [
                cls.uv,
                "venv",
                "-q",
                "--no-config",
                "--python",
                cls.good,
                cls.goodvenv,
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def run_case(self, shell: str, plant: str, project: bool = False) -> bool:
        """Run one case with one planted file; True when its interpreter ran.

        ``plant`` is "pin" (a .python-version naming an interpreter) or
        "venv" (a .venv). They are planted apart: with both, a failing
        pinned interpreter stops uv before it would reach the .venv.
        With ``project``, the workspace is also a uv project (a
        pyproject.toml and uv.lock), where 'uv run' and 'uv export' use
        the project's own environment.
        """
        work = tempfile.mkdtemp(dir=self.base)
        marker = os.path.join(work, "ran")
        workspace = os.path.join(work, "ws")
        os.makedirs(workspace)
        if project:
            with open(
                os.path.join(workspace, "pyproject.toml"), "w", encoding="utf-8"
            ) as h:
                h.write(
                    '[project]\nname = "caller"\nversion = "0"\n'
                    'requires-python = ">=3.9"\ndependencies = []\n'
                )
            subprocess.run(
                [self.uv, "lock", "-q", "--no-config", "--python", self.good],
                cwd=workspace,
                capture_output=True,
                check=False,
            )
        stub = f'#!/bin/sh\necho "$0" >> "{marker}"\nexit 1\n'
        if plant == "venv":
            os.makedirs(os.path.join(workspace, ".venv", "bin"))
            target = os.path.join(workspace, ".venv", "bin", "python3")
            os.symlink(
                "python3", os.path.join(workspace, ".venv", "bin", "python")
            )
            with open(
                os.path.join(workspace, ".venv", "pyvenv.cfg"),
                "w",
                encoding="utf-8",
            ) as h:
                h.write("home = /usr/bin\nversion = 3.12.0\n")
        else:
            target = os.path.join(workspace, "pinned")
            with open(
                os.path.join(workspace, ".python-version"),
                "w",
                encoding="utf-8",
            ) as h:
                h.write(target + "\n")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(stub)
        os.chmod(target, 0o755)
        with open(os.path.join(workspace, "s.py"), "w", encoding="utf-8") as h:
            h.write("pass\n")
        with open(
            os.path.join(workspace, "req.txt"), "w", encoding="utf-8"
        ) as h:
            h.write("six\n")
        script = os.path.join(self.trusted, "s.py")
        with open(script, "w", encoding="utf-8") as h:
            h.write("pass\n")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("UV_", "VIRTUAL_ENV", "PYTHON"))
        }
        env.update(
            {
                "GOOD": self.good,
                "GOODVENV": self.goodvenv,
                "T": self.trusted,
                "S": script,
                "OUT": work,
                "GITHUB_ACTION_PATH": self.trusted,
            }
        )
        subprocess.run(
            ["bash", "-c", shell],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        return os.path.exists(marker)

    def test_cases(self) -> None:
        for shell in self.CASES:
            for plant, rule in (("pin", "PPA006"), ("venv", "PPA007")):
                with self.subTest(shell=shell, plant=plant):
                    ran = self.run_case(shell, plant)
                    reported = rule in rules(shell)
                    self.assertEqual(
                        reported, ran, f"uv ran the planted {plant}: {ran}"
                    )

    PROJECT_CASES = [
        'uv run --no-config --python "$GOOD" python s.py',
        'uv run --no-config --no-project --python "$GOOD" python s.py',
        'uv run --no-config --python "$GOOD" --script "$S"',
        'UV_PROJECT_ENVIRONMENT="$OUT/pe" uv run --no-config --python "$GOOD" python s.py',
        "uv run --no-config --locked python s.py",
        "uv export --no-config --locked --format requirements-txt",
        'UV_PROJECT_ENVIRONMENT="$OUT/pe" uv export --no-config --locked',
        'uv pip install --dry-run --python "$GOOD" six',
        # A relative project environment is the workspace's .venv.
        "UV_PROJECT_ENVIRONMENT=.venv uv export --no-config --locked",
        'UV_PROJECT_ENVIRONMENT=.venv uv run --no-config --python "$GOOD" python s.py',
        # In a project, uv run ignores another active environment.
        'VIRTUAL_ENV="$GOODVENV" uv run --no-config --python "$GOOD" python s.py',
        'VIRTUAL_ENV="$GOODVENV" uv run --no-config --active python s.py',
        'VIRTUAL_ENV="$GOODVENV" uv run --no-config --no-project python s.py',
    ]

    # uv 0.13 stopped using the project's .venv for a --script run given
    # an explicit --python; uv 0.11 still uses it. The engine reports the
    # case for every uv version, so on newer uv it over-reports here.
    REPORTED_FOR_OLDER_UV = frozenset(
        {'uv run --no-config --python "$GOOD" --script "$S"'}
    )

    def test_project_layout(self) -> None:
        """In a uv project, the project's .venv decides more than --python."""
        for shell in self.PROJECT_CASES:
            with self.subTest(shell=shell):
                ran = self.run_case(shell, "venv", project=True)
                reported = "PPA007" in rules(shell)
                if shell in self.REPORTED_FOR_OLDER_UV:
                    self.assertTrue(reported, "reported whatever uv does")
                    continue
                self.assertEqual(
                    reported, ran, f"uv ran the planted venv: {ran}"
                )


class UvTest(unittest.TestCase):
    """uv rules that need no uv to check."""

    def test_global_options_before_run(self) -> None:
        """uv's global options do not hide the program 'uv run' starts."""
        for text, expected in (
            (
                "uv --no-config run --no-project --python /usr/bin/python3 python -c 'import csv'",
                ["PPA002"],
            ),
            (
                "uv --directory src run python -m x",
                ["PPA006", "PPA007", "PPA001"],
            ),
            ("uvx --from six python -c 'import csv'", ["PPA002"]),
            ("uv tool run --from six python -m x", ["PPA001"]),
            ("uv pip install -r requirements.txt", ["PPA007"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_directory_moves_the_program(self) -> None:
        """uv --directory and env -C set the launched program's directory."""
        for text, expected in (
            (
                'cd "$GITHUB_ACTION_PATH"; uv run --directory "$GITHUB_WORKSPACE" '
                "--no-config --no-project --python /usr/bin/python3 python -m x",
                ["PPA001"],
            ),
            ('uv run --directory "$GITHUB_ACTION_PATH" python -m x', []),
            ('env -C "$GITHUB_ACTION_PATH" python3 -m x', []),
            (
                'cd "$GITHUB_ACTION_PATH"; env --chdir "$GITHUB_WORKSPACE" python3 -m x',
                ["PPA001"],
            ),
            (
                'cd "$GITHUB_ACTION_PATH"; env --chdir="$GITHUB_WORKSPACE" python3 -m x',
                ["PPA001"],
            ),
            ('env --chdir="$GITHUB_ACTION_PATH" python3 -m x', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_wrappers(self) -> None:
        for text, expected in (
            ("sudo -u runner python3 -m x", ["PPA001"]),
            ("nice -n 10 python3 -c 'import csv'", ["PPA002"]),
            ("timeout -s KILL 30 python3 -m x", ["PPA001"]),
            ("command -v python3", []),
            ('set -e; builtin cd "$GITHUB_ACTION_PATH"; python3 -m x', []),
            ("coproc python3 -m x", ["PPA001"]),
            # sudo starts its program with a fresh environment, unless -E.
            (
                "export UV_NO_CONFIG=1; sudo uv python find --system",
                ["PPA006"],
            ),
            (
                "export UV_NO_CONFIG=1; sudo -E uv python find --system",
                [],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_step_level_uv_settings(self) -> None:
        text = (
            "runs:\n  steps:\n    - env:\n        UV_NO_CONFIG: '1'\n"
            "        UV_NO_PROJECT: '1'\n        UV_PYTHON: /opt/py/bin/python3\n"
            "      run: uv run python x.py\n"
        )
        self.assertEqual(rules(text, "action"), [])

    def test_top_level_env_in_an_action_does_not_apply(self) -> None:
        """Composite action metadata has no top-level env: the runner ignores it."""
        text = (
            "env:\n  UV_NO_CONFIG: '1'\n  UV_NO_PROJECT: '1'\n  UV_PYTHON: /opt/py/bin/python3\n"
            "runs:\n  steps:\n    - run: uv run python x.py\n"
        )
        self.assertEqual(rules(text, "action"), ["PPA006", "PPA007"])

    def test_trusted_directory(self) -> None:
        text = 'set -e\ncd "$GITHUB_ACTION_PATH"\nuv run python x.py\nuv pip install six\n'
        self.assertEqual(rules(text), [])

    def test_path_values(self) -> None:
        """Only a path outside the workspace stops uv using the workspace's .venv."""
        for value, reported in (
            ("3.12", True),
            ("'>=3.10'", True),
            ("/usr/bin/python3", False),
            ('"$py"', False),
            ('"${py}"', False),
            ('"$VENV/bin/python"', False),
            ('"$version"', True),
            (".venv/bin/python", True),
            ('"$GITHUB_WORKSPACE/.venv/bin/python"', True),
        ):
            text = (
                'py="$(command -v python3)"\n'
                f"uv pip install --python {value} six\n"
            )
            with self.subTest(value=value):
                self.assertEqual("PPA007" in rules(text), reported)

    def test_setup_uv_steps(self) -> None:
        def step(*lines: str) -> str:
            body = "".join(f"\n      {line}" for line in lines)
            return (
                "runs:\n  steps:\n    - uses: astral-sh/setup-uv@"
                + "0" * 40
                + body
                + "\n"
            )

        for text, expected in (
            (step("with:", "  enable-cache: false"), ["PPA008"]),
            (step("env:", "  UV_NO_CONFIG: '1'"), ["PPA008"]),
            # Env alone leaves setup-uv reading uv.toml from the workspace.
            (
                step("env:", "  UV_NO_CONFIG: '1'", "  UV_SYSTEM_PYTHON: '1'"),
                ["PPA008"],
            ),
            (step("with:", "  python-version: '3.12'"), ["PPA008"]),
            (
                step("with:", "  working-directory: ${{ github.action_path }}"),
                [],
            ),
            (step("with:", "  working-directory: ${{ runner.temp }}"), []),
            (step("with:", "  working-directory: src"), ["PPA008"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text, "action"), expected)


class ContextTest(unittest.TestCase):
    """What a file establishes: variables, aliases and trusted cwds."""

    def test_interpreter_variables(self) -> None:
        for text, expected in (
            (
                'python="$RUNNER_TEMP/venv/bin/python"\n"$python" -m tool',
                ["PPA001"],
            ),
            ('PY=python3\n$PY -c "import x"', ["PPA002"]),
            (
                'PYTHON_BIN="$(command -v python3)"\n"$PYTHON_BIN" -c "import x"',
                ["PPA002"],
            ),
            (
                'for candidate in python3 python; do\n  "$candidate" -m x\ndone',
                ["PPA001"],
            ),
            ('CLI="python -m tool.cli"\n${CLI} --version', ["PPA001"]),
            ('CLI="uvx --from tool tool"\n${CLI} --version', []),
            ('python="$RUNNER_TEMP/venv/bin/python"\n"$python" -I -m tool', []),
            ('x="$(something)"\n"$x" -m tool', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_arrays(self) -> None:
        for text, expected in (
            ('PY_RUN=(python3 -I)\n"${PY_RUN[@]}" - <<EOF\nimport x\nEOF', []),
            (
                'PY_RUN=(python3)\n"${PY_RUN[@]}" - <<EOF\nimport x\nEOF',
                ["PPA003"],
            ),
            (
                'pip=("$venv/bin/python" -m pip download\n  --dest d)\n"${pip[@]}" six',
                ["PPA001"],
            ),
            ('tox_cmd=(uvx --from tox tox)\n"${tox_cmd[@]}" -c tox.ini', []),
            (
                'PY_RUN=(uv run --no-project --no-config --python "$py" --with pyyaml python)\n'
                '"${PY_RUN[@]}" - <<EOF\nimport yaml\nEOF',
                ["PPA003"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_setup_python_output(self) -> None:
        text = "- run: ${{ steps.setup.outputs.python-path }} -m pip install x"
        self.assertEqual(rules(text, "workflow"), ["PPA001"])

    def test_cd_carries_across_lines(self) -> None:
        text = (
            "runs:\n  steps:\n    - env:\n        ACTION_PATH: ${{ github.action_path }}\n"
            '      run: |\n        cd "${ACTION_PATH}"\n        python -m src.main\n'
            "    - run: |\n        python -m other\n"
        )
        findings = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 9)])

    def test_subshell_scopes_cd(self) -> None:
        text = 'set -e\n(\n  cd "$GITHUB_ACTION_PATH"\n  python3 -m inside\n)\npython3 -m outside\n'
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 6)])

    def test_cd_elsewhere_ends_trust(self) -> None:
        text = 'set -e\ncd "$GITHUB_ACTION_PATH"\npython3 -m a\ncd "$GITHUB_WORKSPACE"\npython3 -m b\n'
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 5)])

    def test_errexit(self) -> None:
        """Without -e a failed cd is followed; set -e and set +e switch it."""
        for text, expected in (
            ('cd "$GITHUB_ACTION_PATH"\npython3 -m x', ["PPA001"]),
            ('set -e\ncd "$GITHUB_ACTION_PATH"\npython3 -m x', []),
            ('set -euo pipefail\ncd "$GITHUB_ACTION_PATH"\npython3 -m x', []),
            ('set -o errexit\ncd "$GITHUB_ACTION_PATH"\npython3 -m x', []),
            (
                'set -e\nset +e\ncd "$GITHUB_ACTION_PATH"\npython3 -m x',
                ["PPA001"],
            ),
            ('#!/bin/bash -eu\ncd "$GITHUB_ACTION_PATH"\npython3 -m x', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_step_shell_sets_errexit(self) -> None:
        """The runner's bash and sh run with -e; a custom shell line may not."""
        for shell, expected in (
            ("bash", []),
            ("sh", []),
            ("bash -e {0}", []),
            ("bash --noprofile --norc -eo pipefail {0}", []),
            ("bash {0}", ["PPA001"]),
        ):
            text = (
                "runs:\n  using: composite\n  steps:\n"
                f"    - shell: {shell}\n      run: |\n"
                '        cd "$GITHUB_ACTION_PATH"\n        python3 -m x\n'
            )
            with self.subTest(shell=shell):
                self.assertEqual(rules(text, "action"), expected)

    def test_shell_aliases_of_the_action_directory(self) -> None:
        for text, kind, expected in (
            (
                'dir="$GITHUB_ACTION_PATH"\ncd "$dir"\npython3 -m a',
                "script",
                [],
            ),
            (
                'a="$GITHUB_ACTION_PATH"\nb="$a/lib"\ncd "$b"\npython3 -m a',
                "script",
                [],
            ),
            (
                'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
                'cd "$SCRIPT_DIR"\npython3 -m a',
                "script",
                [],
            ),
            (
                'dir="$GITHUB_WORKSPACE"\ncd "$dir"\npython3 -m a',
                "script",
                ["PPA001"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules("set -e\n" + text, kind), expected)

    def test_links_lead_anywhere(self) -> None:
        """realpath and readlink are trusted only for the running script itself."""
        for text, expected in (
            ('set -e\ncd "$(dirname "$(realpath "$0")")"\npython3 -m x', []),
            (
                'set -e\ncd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"\npython3 -m x',
                [],
            ),
            (
                'set -e\ncd "$(dirname "$0")"\ncd "$(readlink link)"\npython3 -m x',
                ["PPA001"],
            ),
            (
                'set -e\ncd "$(realpath "$GITHUB_ACTION_PATH/lib")"\npython3 -m x',
                ["PPA001"],
            ),
        ):
            with self.subTest(text=text):
                found = audit.scan_text(
                    text, "script", "repo", "scripts/run.sh"
                )
                self.assertEqual([f.rule for f in found], expected)

    def test_deep_calls_make_the_scan_incomplete(self) -> None:
        """A call chain deeper than the walk follows is not read as a no-op."""
        chain = "\n".join(f"f{n}() {{ f{n + 1}; }}" for n in range(40))
        text = f'set -e\n{chain}\nf40() {{ cd "$GITHUB_WORKSPACE"; }}\nf0\npython3 -m x\n'
        with self.assertRaises(ValueError):
            audit.scan_text(text, "script", "repo", "run.sh")
        recursive = (
            'set -e\ncd "$GITHUB_ACTION_PATH"\nf() { f; }\nf\npython3 -m x\n'
        )
        self.assertEqual(rules(recursive), ["PPA001"])

    def test_script_directory_stays_in_its_repository(self) -> None:
        """``dirname "$0"`` and ``..`` are trusted up to the script's repository root."""
        text = (
            'root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"\n'
            'f() { (cd -- "${root}" && python3 -m tests.x); }'
        )
        for relpath, expected in (
            ("scripts/run.sh", []),
            ("run.sh", ["PPA001"]),
        ):
            with self.subTest(relpath=relpath):
                findings = audit.scan_text(text, "script", "repo", relpath)
                self.assertEqual([f.rule for f in findings], expected)

    def test_working_directory(self) -> None:
        text = (
            "runs:\n  steps:\n    - run: python3 -m a\n"
            "      working-directory: ${{ github.action_path }}\n"
            "    - run: python3 -m b\n      working-directory: src\n"
        )
        findings = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 5)])

    def test_github_env_pythonpath(self) -> None:
        text = (
            'SAFE="${PYTHONPATH:-}"\nSAFE="${SAFE//x/}"\n'
            'echo "PYTHONPATH=${GITHUB_ACTION_PATH}/src:${SAFE}" >> "$GITHUB_ENV"\n'
            'echo "PYTHONPATH=${GITHUB_ACTION_PATH}/src" >> "$GITHUB_ENV"\n'
            'cat >> "$GITHUB_ENV" <<EOF\nPYTHONPATH=/opt/x:\nEOF\n'
        )
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual(
            [(f.rule, f.line) for f in findings], [("PPA004", 3), ("PPA004", 6)]
        )
        self.assertIn("GITHUB_ENV", findings[0].detail)

    def test_workspace_entry_in_action(self) -> None:
        text = "env:\n  PYTHONPATH: ${{ github.workspace }}/lib\n"
        self.assertEqual(rules(text, "action"), ["PPA005"])
        self.assertEqual(rules(text, "workflow"), [])


class PythonpathTest(unittest.TestCase):
    """PYTHONPATH values in shell and YAML."""

    def test_yaml_env_self_reference(self) -> None:
        text = "env:\n  PYTHONPATH: ${{ github.action_path }}:${{ env.PYTHONPATH }}\n"
        self.assertEqual(rules(text, "action"), ["PPA004"])

    def test_only_reference_is_fine(self) -> None:
        self.assertEqual(rules('export PYTHONPATH="$PYTHONPATH"'), [])
        self.assertEqual(rules('export PYTHONPATH="${PYTHONPATH:-/opt/x}"'), [])

    def test_yaml_env_plain_value_is_fine(self) -> None:
        self.assertEqual(
            rules("env:\n  PYTHONPATH: ${{ github.action_path }}\n", "action"),
            [],
        )

    def test_empty_assignment_is_fine(self) -> None:
        self.assertEqual(rules("PYTHONPATH= python3 x.py"), [])

    def test_relative_entry_only_in_actions(self) -> None:
        self.assertEqual(
            rules("env:\n  PYTHONPATH: src\n", "action"), ["PPA005"]
        )
        self.assertEqual(rules("env:\n  PYTHONPATH: src\n", "workflow"), [])
        self.assertEqual(rules("export PYTHONPATH=src", "script"), [])

    def test_working_directory_entries_in_actions(self) -> None:
        # An action's working directory is the caller's workspace
        for value in (
            '"$PWD/src"',
            '"${PWD}"',
            '"$(pwd)/lib"',
            '"/opt/x:`pwd`"',
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    rules(action_step(f"export PYTHONPATH={value}"), "action"),
                    ["PPA005"],
                )

    def test_command_output_alone_is_not_judged(self) -> None:
        for line in (
            'export PYTHONPATH="$(python3 -I f.py)"',
            'PYTHONPATH="$("$python" -I "$FILTER")"',
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), [])
        text = action_step('export PYTHONPATH="$(python3 -I f.py):lib"')
        self.assertEqual(rules(text, "action"), ["PPA005"])
        found = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertIn("'lib'", found[0].detail)

    def test_yaml_values_are_not_shell_expanded(self) -> None:
        """The runner substitutes ${{ }} in YAML values, never $name or ~."""
        for value, expected in (
            ('"/opt/x:" # explanation', ["PPA004"]),
            ("'${{ github.action_path }}' # action modules", []),
            ('"$PYTHONPATH"', ["PPA005"]),
            ('"/opt/x:$PYTHONPATH"', ["PPA005"]),
            ("~/lib", ["PPA005"]),
            ("/opt/x:${{ env.PYTHONPATH }}", ["PPA004"]),
            ('":"', ["PPA004"]),
        ):
            text = f"runs:\n  steps:\n    - env:\n        PYTHONPATH: {value}\n      run: x\n"
            with self.subTest(value=value):
                self.assertEqual(rules(text, "action"), expected)

    def test_shell_tilde_and_quotes(self) -> None:
        """An unquoted ~ in an assignment is a home directory; a quoted one is not."""
        for line, expected in (
            ("export PYTHONPATH=~/lib", []),
            ("export PYTHONPATH=/opt:~/lib", []),
            ('export PYTHONPATH="~/lib"', ["PPA005"]),
            ("export PYTHONPATH='/opt/x:$PYTHONPATH'", ["PPA005"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)


class YamlTest(unittest.TestCase):
    """Workflow and action files as the runner reads them."""

    def test_folded_block_keeps_more_indented_lines(self) -> None:
        text = (
            "runs:\n  steps:\n    - shell: bash\n      run: >\n"
            "        echo before\n          python3 -m tool\n        echo after\n"
        )
        findings = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 6)])

    def test_env_reaches_only_its_own_step(self) -> None:
        text = textwrap.dedent(
            """\
            on: push
            env:
              UV_SYSTEM_PYTHON: '1'
            jobs:
              a:
                env:
                  UV_NO_CONFIG: '1'
                steps:
                  - run: uv python find
                  - env:
                      UV_NO_CONFIG: '0'
                    run: uv python find
              b:
                steps:
                  - run: uv python find
                  - env:
                      UV_NO_CONFIG: '1'
                    run: echo later
            """
        )
        findings = audit.scan_text(text, "workflow", "repo", "ci.yaml")
        self.assertEqual(
            [(f.rule, f.line) for f in findings],
            [("PPA006", 12), ("PPA006", 15)],
        )

    def test_non_shell_steps_are_skipped(self) -> None:
        text = (
            "on: push\njobs:\n  a:\n    steps:\n"
            "      - shell: python\n        run: |\n          import os\n"
            "      - shell: bash\n        run: python3 -m x\n"
        )
        findings = audit.scan_text(text, "workflow", "repo", "ci.yaml")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA001", 9)])

    def test_run_keys_outside_steps_are_not_shell(self) -> None:
        text = (
            "on: push\njobs:\n  a:\n    strategy:\n      matrix:\n"
            "        include:\n          - run: python3 -m not-a-step\n"
            "    steps:\n      - uses: some/action@" + "0" * 40 + "\n"
            "        with:\n          run: python3 -m an-input\n"
        )
        self.assertEqual(rules(text, "workflow"), [])

    def test_literal_working_directory(self) -> None:
        """working-directory is not shell-expanded: $GITHUB_ACTION_PATH is a folder name."""
        for directory, expected in (
            ("${{ github.action_path }}", []),
            ("${{ github.action_path }}/src", []),
            ("${{ github.action_path }}/..", ["PPA001"]),
            ("$GITHUB_ACTION_PATH", ["PPA001"]),
            ("src", ["PPA001"]),
        ):
            text = (
                "runs:\n  steps:\n    - run: python3 -m a\n"
                f"      working-directory: {directory}\n"
            )
            with self.subTest(directory=directory):
                self.assertEqual(rules(text, "action"), expected)

    def test_invalid_yaml_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            audit.scan_text("steps: [\n", "workflow", "repo", "ci.yaml")

    def test_alias_expansion_is_bounded(self) -> None:
        """A small file whose aliases double at each level stops the scan of it."""
        lines = ["a0: &a0 [x, y]"]
        lines += [f"a{n}: &a{n} [*a{n - 1}, *a{n - 1}]" for n in range(1, 30)]
        with self.assertRaises(ValueError):
            audit.scan_text(
                "\n".join(lines) + "\n", "workflow", "repo", "ci.yaml"
            )

    def test_deep_nesting_is_an_error(self) -> None:
        """Expansions nested past the parser's limit stop the scan of that file."""
        for depth, fails in ((20, False), (2000, True)):
            text = "echo " + "${x:-" * depth + "y" + "}" * depth + "\n"
            with self.subTest(depth=depth):
                if fails:
                    with self.assertRaises(ValueError):
                        audit.scan_text(text, "script", "repo", "run.sh")
                else:
                    self.assertEqual(
                        audit.scan_text(text, "script", "repo", "run.sh"), []
                    )


class EnvWriteTest(unittest.TestCase):
    """PYTHONPATH values written to $GITHUB_ENV, however they are written."""

    def test_writers(self) -> None:
        for line, expected in (
            (
                "echo -e 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            ("echo 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"", []),
            (
                "printf '%b\\n' 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            (
                'writer=(echo \'PYTHONPATH=/opt/x:\'); "${writer[@]}" >> "$GITHUB_ENV"',
                ["PPA004"],
            ),
            (
                'line=\'PYTHONPATH=/opt/x:\'; echo "$line" >> "$GITHUB_ENV"',
                ["PPA004"],
            ),
            (
                "line='PYTHONPATH=/opt/x:'\ncat >> \"$GITHUB_ENV\" <<EOF\n$line\nEOF",
                ["PPA004"],
            ),
            ('echo "PYTHONPATH=/opt/x:" >> "$GITHUB_ENV"', ["PPA004"]),
            ('echo -n PYTHONPATH=/opt/x: >> "$GITHUB_ENV"', ["PPA004"]),
            (
                'printf \'PYTHONPATH=%s:\\n\' "$GITHUB_ACTION_PATH" >> "$GITHUB_ENV"',
                ["PPA004"],
            ),
            ('printf \'%s\\n\' "PYTHONPATH=/opt/x" >> "$GITHUB_ENV"', []),
            (
                "printf '%s=%s\\n' PYTHONPATH /opt/x: >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            ('{ echo "PYTHONPATH=/opt/x:"; } >> "$GITHUB_ENV"', ["PPA004"]),
            (
                'cat <<-EOF >> "$GITHUB_ENV"\n\tPYTHONPATH=/nonexistent:\n\tEOF',
                ["PPA004"],
            ),
            ('cat <<EOF >> "$GITHUB_ENV"\nPYTHONPATH=/opt/x\nEOF', []),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)


class WalkTest(unittest.TestCase):
    """Directory trust and variables, followed in the order the shell runs."""

    @staticmethod
    def step(shell: str) -> list[str]:
        """The rules found in an action step running ``shell``."""
        body = "".join(f"\n        {line}" for line in shell.split("\n"))
        text = (
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |"
            + body
            + "\n"
        )
        return rules(text, "action")

    def test_branches_merge(self) -> None:
        for text, expected in (
            (
                'if a; then cd "$GITHUB_ACTION_PATH"; fi\npython3 -m x',
                ["PPA001"],
            ),
            (
                'if a; then cd "$GITHUB_ACTION_PATH"; else cd "$GITHUB_ACTION_PATH"; fi\n'
                "python3 -m x",
                [],
            ),
            ('[ -d x ] && cd "$GITHUB_ACTION_PATH"\npython3 -m x', ["PPA001"]),
            ('cd "$GITHUB_ACTION_PATH" || exit 1\npython3 -m x', []),
            ('cd "$GITHUB_ACTION_PATH" || python3 -m x', ["PPA001"]),
            (
                'case "$a" in\n  x) cd "$GITHUB_ACTION_PATH" ;;\nesac\npython3 -m x',
                ["PPA001"],
            ),
            ('cd "$GITHUB_ACTION_PATH" | true\npython3 -m x', ["PPA001"]),
            ('cd "$GITHUB_ACTION_PATH" &\npython3 -m x', ["PPA001"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.step(text), expected)

    def test_functions_run_where_called(self) -> None:
        for text, expected in (
            ('f() { python3 -m x; }\ncd "$GITHUB_ACTION_PATH"\nf', []),
            (
                'f() { python3 -m x; }\nf\ncd "$GITHUB_ACTION_PATH"\nf',
                ["PPA001"],
            ),
            ('go() { cd "$GITHUB_ACTION_PATH"; }\ngo\npython3 -m x', []),
            ("f() { python3 -m x; }", ["PPA001"]),
            (
                'setup() { PY=(python3); }\nrun_it() { "${PY[@]}" -m x; }',
                ["PPA001"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.step(text), expected)

    def test_loops(self) -> None:
        text = 'cd "$GITHUB_ACTION_PATH"\nfor d in a b; do\n  python3 -m x\n  cd ..\ndone'
        self.assertEqual(self.step(text), ["PPA001"])

    def test_suffix_must_stay_inside(self) -> None:
        for target, expected in (
            ('"$GITHUB_ACTION_PATH/src"', []),
            ('"$GITHUB_ACTION_PATH/src/../lib"', []),
            ('"$GITHUB_ACTION_PATH/.."', ["PPA001"]),
            ('"$GITHUB_ACTION_PATH/$sub"', ["PPA001"]),
            ('"${GITHUB_ACTION_PATH%/*}"', ["PPA001"]),
            ("'$GITHUB_ACTION_PATH'", ["PPA001"]),
        ):
            with self.subTest(target=target):
                self.assertEqual(
                    self.step(f"cd {target}\npython3 -m x"), expected
                )

    def test_action_path_means_nothing_in_a_workflow(self) -> None:
        text = 'on: push\njobs:\n  a:\n    steps:\n      - run: cd "$GITHUB_ACTION_PATH" && python3 -m x\n'
        self.assertEqual(rules(text, "workflow"), ["PPA001"])

    def test_environment_variables_from_yaml(self) -> None:
        text = (
            "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
            "          PYTHON: ${{ steps.py.outputs.python-path }}\n"
            '        run: "\\"$PYTHON\\" -m unittest"\n'
        )
        self.assertEqual(rules(text, "workflow"), ["PPA001"])

    def test_set_allexport(self) -> None:
        self.assertEqual(
            rules("set -a\nUV_NO_CONFIG=1\nuv python find --system"), []
        )
        self.assertEqual(
            rules("set -a\nset +a\nUV_NO_CONFIG=1\nuv python find --system"),
            ["PPA006"],
        )


class DiscoveryTest(unittest.TestCase):
    """Walking folders of repositories."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.root = root
        files = {
            "repo-a/.git/HEAD": "",
            "repo-a/action.yaml": "runs:\n  steps:\n    - run: python3 -m a\n",
            "repo-a/.github/workflows/ci.yaml": (
                "on: pull_request_target\njobs:\n  x:\n    steps:\n"
                "      - run: python3 -c 'import y'\n"
            ),
            "repo-a/scripts/go.sh": "#!/bin/sh\necho x | python3\n",
            "repo-a/bin/tool": "#!/usr/bin/env bash\npython3 -m tool\n",
            "repo-a/node_modules/dep/x.sh": "python3 -m ignored\n",
            "repo-a/docs/README.md": "python3 -m ignored\n",
            "repo-b/.git/HEAD": "",
            "repo-b/action.yml": "runs:\n  steps:\n    - run: python3 -I -m safe\n",
        }
        for relpath, text in files.items():
            path = os.path.join(root, relpath)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)

    def test_scan_folder_of_repositories(self) -> None:
        findings = audit.scan([self.root])
        got = [(f.kind, f.repo, f.path, f.rule) for f in findings]
        self.assertEqual(
            got,
            [
                ("action", "repo-a", "action.yaml", "PPA001"),
                ("workflow", "repo-a", ".github/workflows/ci.yaml", "PPA002"),
                ("script", "repo-a", "bin/tool", "PPA001"),
                ("script", "repo-a", "scripts/go.sh", "PPA003"),
            ],
        )
        self.assertIn("pull_request_target", findings[1].tags)

    def test_reusable_workflow_tag(self) -> None:
        for text, expected in (
            ("on:\n  workflow_call:\n    inputs: {}\njobs: {}\n", True),
            ("on:\n  push:\n  workflow_call:\njobs: {}\n", True),
            ("on: [push, workflow_call]\njobs: {}\n", True),
            ("on: workflow_call\njobs: {}\n", True),
            (
                "on:\n  pull_request:\njobs:\n  x:\n    steps:\n"
                "      - run: python3 -I -c \"d['workflow_call']\"\n",
                False,
            ),
            ("# called like a workflow_call\non:\n  push:\njobs: {}\n", False),
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    "workflow_call" in audit.file_tags(text, "workflow"),
                    expected,
                )

    def test_trigger_tags_read_the_on_block(self) -> None:
        text = (
            "on:\n  workflow_dispatch:\n  # pull_request_target:\njobs:\n  x:\n    steps:\n"
            "      - run: echo '{\"workflow_run_id\": 1}'\n"
        )
        tags = audit.file_tags(text, "workflow")
        self.assertNotIn("workflow_run", tags)
        self.assertNotIn("pull_request_target", tags)
        text = "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\njobs: {}\n"
        self.assertIn("workflow_run", audit.file_tags(text, "workflow"))
        self.assertEqual(audit.triggers(text), {"workflow_run"})
        text = "on:\n  push:\n    workflow_call:\njobs: {}\n"
        self.assertEqual(audit.triggers(text), {"push"})
        self.assertEqual(
            audit.triggers("on: push  # not workflow_call\njobs: {}\n"),
            {"push"},
        )

    def test_secrets_tag_needs_the_secrets_context(self) -> None:
        head = "on: pull_request\njobs:\n  x:\n    steps:\n"
        for step, expected in (
            ('      - run: echo "${{ secrets.TOKEN }}"\n', True),
            ("      - env:\n          T: ${{secrets.TOKEN}}\n", True),
            ("      - run: echo \"${{ secrets['TOKEN'] }}\"\n", True),
            ('      - run: echo "${{ toJSON(secrets) }}"\n', True),
            ("    secrets: inherit\n", True),
            ('      - run: echo "${{ secrets.GITHUB_TOKEN }}"\n', False),
            (
                "      - run: for m in secrets.py sitecustomize.py; do :; done\n",
                False,
            ),
            ('      - run: touch "${dir}/secrets.py"\n', False),
        ):
            with self.subTest(step=step):
                tags = audit.file_tags(head + step, "workflow")
                self.assertEqual("secrets" in tags, expected)

    def test_tags_ignore_comments(self) -> None:
        text = (
            "# Deliberately pull_request, not pull_request_target\n"
            "on: pull_request\njobs:\n  x:\n    steps:\n      - run: python3 -m y\n"
        )
        findings = audit.scan_text(text, "workflow", "repo", "ci.yaml")
        self.assertNotIn("pull_request_target", findings[0].tags)

    def test_explicit_files_are_always_scanned(self) -> None:
        files = {
            "saved-action.yaml": "runs:\n  steps:\n    - run: python3 -m a\n",
            "saved-workflow.yml": "on: push\njobs:\n  x:\n    steps:\n      - run: python3 -m b\n",
            "helper": "echo x | python3\n",
        }
        expected = {
            "saved-action.yaml": ("action", "PPA001"),
            "saved-workflow.yml": ("workflow", "PPA001"),
            "helper": ("script", "PPA003"),
        }
        for name, text in files.items():
            path = os.path.join(self.root, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            with self.subTest(name=name):
                findings = audit.scan([path])
                self.assertEqual(
                    [(f.kind, f.rule) for f in findings], [expected[name]]
                )

    def test_main_exit_codes_and_json(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = audit.main([self.root, "--json", "--kinds", "action"])
        self.assertEqual(code, 1)
        self.assertEqual(
            [f["repo"] for f in json.loads(out.getvalue())], ["repo-a"]
        )
        with redirect_stdout(io.StringIO()):
            clean = audit.main([os.path.join(self.root, "repo-b")])
        self.assertEqual(clean, 0)

    def test_unscannable_file_makes_the_scan_incomplete(self) -> None:
        broken = os.path.join(self.root, "repo-b", ".github", "workflows")
        os.makedirs(broken)
        with open(
            os.path.join(broken, "ci.yaml"), "w", encoding="utf-8"
        ) as handle:
            handle.write("jobs: [\n")
        problems: list[str] = []
        self.assertEqual(
            audit.scan([os.path.join(self.root, "repo-b")], problems), []
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("ci.yaml", problems[0])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = audit.main([os.path.join(self.root, "repo-b")])
        self.assertEqual(code, 2)

    def test_missing_root_makes_the_scan_incomplete(self) -> None:
        missing = os.path.join(self.root, "no-such-repo")
        problems: list[str] = []
        self.assertEqual(audit.scan([missing], problems), [])
        self.assertEqual(len(problems), 1)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(audit.main([missing]), 2)

    def test_named_file_finds_its_repository(self) -> None:
        """A file named on its own still gets its path within its repository."""
        script = os.path.join(self.root, "repo-a", "scripts", "run.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write('set -e\ncd "$(dirname "$0")/.."\npython3 -m tool\n')
        self.assertEqual(audit.scan([script]), [])
        findings = audit.scan(
            [os.path.join(self.root, "repo-a", "scripts", "go.sh")]
        )
        self.assertEqual(
            [(f.repo, f.path) for f in findings], [("repo-a", "scripts/go.sh")]
        )


if __name__ == "__main__":
    unittest.main()
