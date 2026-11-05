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
    planted code ran. A case where it ran never comes out clean: the
    scanner reports the rule, or PPA009 where the deciding word is not
    a literal it reads. Where it did not run, the scanner stays quiet
    except for the false positives the design accepts, each marked
    below, and -P, reported as partial although it protects on the
    Python running the tests.
    """

    tmp: tempfile.TemporaryDirectory[str]
    bin: str
    trusted: str
    work: str

    CASES = [
        # (shell, expected rule or None, planted code ran on this Python)
        (
            'PYTHONPATH="$RUNNER_TEMP" python3 -m trusted_pkg.main',
            "PPA001",
            True,
        ),
        ('python3 -c "import csv"', "PPA002", True),
        ('python3 -E -c "import csv"', "PPA002", True),
        ('python3 -X utf8 -c "import csv"', "PPA002", True),
        ('echo "import csv" | python3', "PPA003", True),
        ('python3 - < "$RUNNER_TEMP/snippet.py"', "PPA003", True),
        ('python3 < "$RUNNER_TEMP/snippet.py"', "PPA003", True),
        ('python3 -I -c "import csv"', None, False),
        ('python3 -Ic "import csv"', None, False),
        ('python3 -W ignore -I -c "import csv"', None, False),
        ('python3 -s -I -E -c "import csv"', None, False),
        ('python3 "$RUNNER_TEMP/script.py"', None, False),
        ('python3 -I "$RUNNER_TEMP/script.py"', None, False),
        (
            'PYTHONPATH="$RUNNER_TEMP:" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH=":$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP:$PYTHONPATH" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP${PYTHONPATH:+:$PYTHONPATH}" python3 "$RUNNER_TEMP/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP${PYTHONPATH:+:${PYTHONPATH}}" python3 "$RUNNER_TEMP/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:-}:$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="${PYTHONPATH:-$RUNNER_TEMP}:$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="${PYTHONPATH}:$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP::$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP" python3 "$RUNNER_TEMP/script.py"',
            None,
            False,
        ),
        (
            'PYTHONPATH="$RUNNER_TEMP:" python3 -I "$RUNNER_TEMP/script.py"',
            "PPA004",
            False,
        ),
        ("python3 --version", None, False),
        # Start-up modules cannot be shadowed, but sitecustomize runs
        # from an empty PYTHONPATH entry whatever the program imports.
        ('python3 -c "import sys"', "PPA002", False),
        (
            'PYTHONPATH="$RUNNER_TEMP:" python3 -c "import sys"',
            ("PPA002", "PPA004"),
            True,
        ),
        # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
        (
            '(cd -- "$GITHUB_ACTION_PATH" && python3 -E -s -m trusted_pkg.main)',
            "PPA001",
            False,
        ),
        (
            'cd "$GITHUB_ACTION_PATH" && cd "$OLDPWD" && python3 -m trusted_pkg.main',
            "PPA001",
            True,
        ),
        (
            'cd "$RUNNER_TEMP" && PYTHONPATH="$RUNNER_TEMP" python3 -m trusted_pkg.main',
            "PPA001",
            False,
        ),
        # A path that climbs out of the action's directory leaves it.
        (
            'cd "$GITHUB_ACTION_PATH/../work" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A variable reassigned to the workspace.
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
        ('python3 < "$RUNNER_TEMP/snippet.py" -I', None, False),
        ('python3 0< "$RUNNER_TEMP/snippet.py"', "PPA003", True),
        # Set but empty is not unset: "+" tests only for set.
        (
            'export PYTHONPATH=; PYTHONPATH="$RUNNER_TEMP${PYTHONPATH+:$PYTHONPATH}" '
            'python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        # Single quotes keep "$" literal: no empty entry here.
        (
            "PYTHONPATH='/nonexistent:$PYTHONPATH' python3 \"$RUNNER_TEMP/script.py\"",
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
        # Unresolved: the deciding word is not a literal the scan reads.
        ('opts=-E; python3 "$opts" -c "import csv"', "PPA009", True),
        # A value is taken when it is assigned.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            'PY=python3; CMD=$PY; PY=echo; $CMD -c "import csv"',
            "PPA009",
            True,
        ),
        # A variable's empty entry is still empty in PYTHONPATH.
        # Unresolved: $P is not a name the scan knows.
        (
            'P="$RUNNER_TEMP:"; PYTHONPATH="$P" python3 "$RUNNER_TEMP/script.py"',
            "PPA009",
            True,
        ),
        # Setting one element changes only that element.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "PY=(python3 -I); PY[1]=-E; \"${PY[@]}\" -c 'import csv'",
            "PPA009",
            True,
        ),
        # A subscript selects one element; no subscript, the first.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "PY_RUN=(python3 -I); \"${PY_RUN[0]}\" -c 'import csv'",
            "PPA009",
            True,
        ),
        # Unresolved: the deciding word is not a literal the scan reads.
        ("PY_RUN=(python3 -I); ${PY_RUN} -c 'import csv'", "PPA009", True),
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
            'env -u PYTHONHOME PYTHONPATH="$RUNNER_TEMP:" python3 "$RUNNER_TEMP/script.py"',
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
        # Unresolved: the deciding word is not a literal the scan reads.
        ("PY=('python3 -E'); $PY -c 'import csv'", "PPA009", True),
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
        # Unresolved: the deciding word is not a literal the scan reads.
        ('f() { python3 "$@"; }; f -c "import csv"', "PPA009", True),
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
        # FALSE POSITIVE: the scan does not follow the export two
        # commands earlier, so += may start from an unset PYTHONPATH.
        (
            'export PYTHONPATH="$RUNNER_TEMP"; PYTHONPATH+=":$RUNNER_TEMP"; python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            False,
        ),
        # A link from the action directory can lead anywhere.
        (
            'ln -sfn "$PWD" "$RUNNER_TEMP/link"; '
            'cd "$(readlink "$GITHUB_ACTION_PATH/link")" && python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A quoted export operand still assigns.
        (
            'export "PYTHONPATH=$RUNNER_TEMP:"; python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        # Arrays keep their indices.
        # Unresolved: the deciding word is not a literal the scan reads.
        ("PY=(); PY[1]=python3; \"${PY[1]}\" -c 'import csv'", "PPA009", True),
        # uv by path is still uv; --python found on PATH is not an
        # absolute path written in the command.
        (
            '"$(command -v uv)" run --no-config --no-project --python "$(command -v python3)" '
            "python -c 'import csv'",
            ("PPA002", "PPA007"),
            True,
        ),
        # A declaration builtin by quoted name or through builtin.
        (
            '"export" PYTHONPATH="$RUNNER_TEMP:"; python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        (
            'builtin export PYTHONPATH="$RUNNER_TEMP:"; python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        # An empty expansion is removed from the command line.
        # Unresolved: the deciding word is not a literal the scan reads.
        ("opts=; python3 ${opts:-} -c 'import csv'", "PPA009", True),
        # Under set -e, ! keeps going after a failure.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; ! cd "$OLDPWD"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # read sets its names from input.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "opts=-I; read -r opts <<<'-E'; python3 \"$opts\" -c 'import csv'",
            "PPA009",
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
        # A command held in an array is out of sight.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            'cmd=(env PYTHONPATH="$RUNNER_TEMP:" python3); "${cmd[@]}" "$RUNNER_TEMP/script.py"',
            "PPA009",
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
            'command env PYTHONPATH="$RUNNER_TEMP:" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        # -- ends Python's options: the next word is a script.
        ('python3 -- "$RUNNER_TEMP/script.py" -m', None, False),
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
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            'PY="$(command -v python3)"; env "$PY" -c "import csv"',
            "PPA009",
            True,
        ),
        # A value built from PYTHONPATH keeps its colons.
        # Unresolved: $composed is not a name the scan knows.
        (
            'unset PYTHONPATH; composed="$RUNNER_TEMP:$PYTHONPATH"; '
            'export PYTHONPATH="$composed"; python3 "$RUNNER_TEMP/script.py"',
            "PPA009",
            True,
        ),
        # HOME can point anywhere.
        ('set -e; HOME="$PWD"; cd; python3 -c "import csv"', "PPA002", True),
        # env -S runs the words its operand splits into.
        # Unresolved: the deciding word is not a literal the scan reads.
        ("env -S \"python3 -c 'import csv'\"", "PPA009", True),
        # Assignments may follow env's --.
        (
            'env -- PYTHONPATH="$RUNNER_TEMP:" python3 "$RUNNER_TEMP/script.py"',
            "PPA004",
            True,
        ),
        # Past sixteen values, a loop variable is unknown, not its first
        # sixteen.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "for flag in -I -IB -Is -IS -Iu -Iq -Ib -IO -IOO -IBs -IBS -IBu "
            "-IBq -IBb -IBO -Isu -E; do python3 \"$flag\" -c 'import csv'; done",
            "PPA009",
            True,
        ),
        # shift and set -- change a function's arguments.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            'set -e; f() { shift; python3 "$@"; }; f -I -c "import csv"',
            "PPA009",
            True,
        ),
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            'set -e; f() { set -- -E; python3 "$@" -c "import csv"; }; f -I',
            "PPA009",
            True,
        ),
        # pushd -n and popd -n change only the stack, not the directory.
        (
            'set -e; pushd -n "$GITHUB_ACTION_PATH" >/dev/null; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; pushd "$OLDPWD" >/dev/null; '
            'popd -n >/dev/null; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # popd leaves OLDPWD where it was.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; pushd "$OLDPWD" >/dev/null; '
            'popd >/dev/null; cd "$OLDPWD"; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A substitution in an array subscript runs.
        (
            "items=(ok); { : \"${items[$(python3 -c 'import csv' >&2; echo 0)]}\"; } 2>&1",
            "PPA002",
            True,
        ),
        # An array element keeps the value it was given.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "read -r flag <<<'-E'; opts=(\"$flag\"); flag=-I; "
            "python3 \"${opts[@]}\" -c 'import csv'",
            "PPA009",
            True,
        ),
        # A loop list splits into words.
        # Unresolved: the deciding word is not a literal the scan reads.
        (
            "pythons='python3 python3'; for py in $pythons; do "
            "\"$py\" -c 'import csv'; done",
            "PPA009",
            True,
        ),
        # command's own options come before the builtin it runs.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; command -- cd "$OLDPWD"; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; command -p cd "$OLDPWD"; '
            'python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; command -v cd >/dev/null; '
            'python3 -c "import csv"',
            "PPA002",
            False,
        ),
        # A quoted empty value is still an argument: here, the script.
        # FALSE POSITIVE: the scan does not read the empty value.
        ("opts=''; python3 \"$opts\" -c 'import csv'", "PPA009", False),
        # Unresolved: the deciding word is not a literal the scan reads.
        ("opts=''; python3 $opts -c 'import csv'", "PPA009", True),
        # A call that only returns one status has no way out with the
        # other.
        # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
        (
            'set -e; f() { return 1; }; cd "$GITHUB_ACTION_PATH"; '
            'f && cd "$OLDPWD"; python3 -c "import csv"',
            "PPA002",
            False,
        ),
        # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
        (
            'set -e; f() { return 0; }; cd "$GITHUB_ACTION_PATH"; '
            'f || cd "$OLDPWD"; python3 -c "import csv"',
            "PPA002",
            False,
        ),
        # A prefix assignment lasts for its command only.
        # Unresolved: the deciding word is not a literal the scan reads.
        ('flags=-I true; python3 $flags -c "import csv"', "PPA009", True),
        # An assignment after the use is not seen by it.
        ('python3 $flags -c "import csv"; flags=-I', "PPA009", True),
        # return outside a function fails and the script goes on in the
        # directory it was in.
        (
            'cd "$GITHUB_ACTION_PATH/missing" || return 1; python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
        (
            'cd "$GITHUB_ACTION_PATH" || exit 1; python3 -c "import csv"',
            "PPA002",
            False,
        ),
        # env -C runs its program elsewhere.
        (
            'set -e; cd "$GITHUB_ACTION_PATH"; env -C "$OLDPWD" python3 -c "import csv"',
            "PPA002",
            True,
        ),
        # A redirect does not hide the command's own substitutions.
        ("echo \"$(python3 -c 'import csv')\" >&1", "PPA002", True),
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
        env["RUNNER_TEMP"] = self.trusted
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
                found = rules(shell)
                self.assertEqual(sorted(found), sorted(expected))
                if planted_ran:
                    self.assertTrue(found, "planted code ran unreported")

    @unittest.skipIf(sys.version_info < (3, 11), "-P needs Python 3.11")
    def test_dash_p_is_partial(self) -> None:
        shell = 'python3 -P -c "import csv"'
        self.assertFalse(self.planted_code_ran(shell))
        findings = audit.scan_text(shell, "script", "repo", "file")
        self.assertEqual([f.rule for f in findings], ["PPA002"])
        self.assertIn("partial", findings[0].detail)
        # -P does not drop an empty PYTHONPATH entry: sitecustomize runs.
        shell = 'PYTHONPATH="$RUNNER_TEMP:" python3 -P "$RUNNER_TEMP/script.py"'
        self.assertTrue(self.planted_code_ran(shell))
        self.assertEqual(rules(shell), ["PPA004"])


class ParsingTest(unittest.TestCase):
    """How invocations and files are read."""

    def test_interpreter_forms(self) -> None:
        self.assertEqual(rules("/usr/bin/python3 -m pip install x"), ["PPA001"])
        self.assertEqual(rules("python3.12 -m build"), ["PPA001"])
        self.assertEqual(rules("python -m pytest"), ["PPA001"])
        # The scan cannot read "$py", so it cannot tell what uv runs.
        self.assertEqual(
            rules(
                'uv run --no-config --no-project --python "$py" python -m pytest'
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(
                "uv run --no-config --no-project --python /usr/bin/python3 "
                "python -m pytest"
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
            "if command -v python3 > /dev/null 2>&1; then :; fi",
            'py="$(command -v python)"',
            "for candidate in python3 python; do :; done",
            'echo "python on PATH: $(command -v python || true)"',
            "which python3",
            "true  # note; python3 -m x",
            "echo 'not $(python3 -m x) in single quotes'",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_command_positions(self) -> None:
        for text, rule in (
            ("if ! python3 -m x; then :; fi", "PPA001"),
            ("if a; then python3 -m x; fi", "PPA001"),
            ("while python3 -c 'import x'; do :; done", "PPA002"),
            (
                "uv run --no-config --no-project --python /usr/bin/python3 "
                "--with pyyaml python -m x",
                "PPA001",
            ),
            (
                "uv run --no-config --no-project --python /usr/bin/python3 "
                "python - <<'PY'\nPY",
                "PPA003",
            ),
            ('"$VENV/bin/python" -m x', "PPA001"),
            ("x=$(python3 - <<EOF\nEOF\n)", "PPA003"),
            ("FOO=1 BAR='a b' python3 -m x", "PPA001"),
            ("exec python3 -m x", "PPA001"),
            ("env python3 -m x", "PPA001"),
            ("a && python3 -c 'import y'", "PPA002"),
            ("a || python3 -c 'import y'", "PPA002"),
            ("{ python3 -m x; }", "PPA001"),
            ('echo "result: $(python3 -m x)"', "PPA001"),
            ('echo "result: `python3 -m x`"', "PPA001"),
            ("python3 > \"$out\" <<'PY'\nPY", "PPA003"),
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
        text = "PYTHONSAFEPATH=1 python3 -m x\n"
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertIn("partial", findings[0].detail)


class UvOracleTest(unittest.TestCase):
    """The uv rules agree with what uv really runs.

    Each case runs under bash in a workspace holding a .python-version
    that names one planted interpreter and a .venv holding another;
    each writes its own marker as it starts and then fails. uv passes
    over an interpreter that fails, so a command that still works
    proves nothing: only the markers count. When the .python-version
    interpreter ran, the scanner reports PPA006, and PPA007 when the
    .venv one did, or PPA009 where a deciding word is not a literal it
    reads. Otherwise it reports neither, except for the false positives
    in ``FALSE_POSITIVES``.
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
        # Help and version output runs no Python.
        "uv run --help",
        "uv venv -h",
        "uv pip install --help",
        "uv python find --help",
        "uv --version",
        "uv run -- python s.py --help",
    ]

    # FALSE POSITIVE: (shell, plant) pairs the scanner reports although
    # uv did not run the planted interpreter. A setting whose value is
    # not a literal does not count as protection, and the scanner does
    # not follow export (a reader moves the setting to the step's env:).
    FALSE_POSITIVES = frozenset(
        {
            ('UV_PYTHON="$GOOD" uv run --no-project python s.py', "pin"),
            ('UV_PYTHON="$GOOD" uv run --no-project python s.py', "venv"),
            (
                'VIRTUAL_ENV="$GOODVENV" uv run --no-config --no-project '
                "python s.py",
                "venv",
            ),
            ('VIRTUAL_ENV="$GOODVENV" uv pip install --dry-run six', "venv"),
            ("export UV_NO_CONFIG=1\nuv python find --system", "pin"),
            (
                'UV_PROJECT_ENVIRONMENT="$OUT/pe" uv export --no-config --locked',
                "project",
            ),
            (
                'VIRTUAL_ENV="$GOODVENV" uv run --no-config --active python s.py',
                "project",
            ),
            (
                'VIRTUAL_ENV="$GOODVENV" uv run --no-config --no-project '
                "python s.py",
                "project",
            ),
        }
    )

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

    def check(self, shell: str, rule: str, plant: str, ran: bool) -> None:
        """Ran: the rule or PPA009 is reported. Did not: the rule is not."""
        found = rules(shell)
        if ran:
            self.assertTrue(
                rule in found or "PPA009" in found,
                f"uv ran the planted {plant}, reported {found}",
            )
        elif (shell, plant) in self.FALSE_POSITIVES:
            self.assertIn(rule, found, "a listed false positive went quiet")
        else:
            self.assertNotIn(rule, found, f"uv did not run the planted {plant}")

    def test_cases(self) -> None:
        for shell in self.CASES:
            for plant, rule in (("pin", "PPA006"), ("venv", "PPA007")):
                with self.subTest(shell=shell, plant=plant):
                    self.check(shell, rule, plant, self.run_case(shell, plant))

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
    # an explicit --python; uv 0.11 still uses it. The scanner reports
    # the case for every uv version (PPA009: it cannot read "$GOOD").
    REPORTED_FOR_OLDER_UV = frozenset(
        {'uv run --no-config --python "$GOOD" --script "$S"'}
    )

    def test_project_layout(self) -> None:
        """In a uv project, the project's .venv decides more than --python."""
        for shell in self.PROJECT_CASES:
            with self.subTest(shell=shell):
                ran = self.run_case(shell, "venv", project=True)
                if shell in self.REPORTED_FOR_OLDER_UV:
                    found = rules(shell)
                    self.assertTrue(
                        "PPA007" in found or "PPA009" in found,
                        "reported whatever uv does",
                    )
                    continue
                if (shell, "project") in self.FALSE_POSITIVES:
                    self.assertFalse(ran, "listed false positive ran")
                    self.assertIn("PPA007", rules(shell))
                    continue
                self.check(shell, "PPA007", "venv", ran)


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
        """uv --directory and env -C are not followed.

        A directory the scan cannot read is PPA009; otherwise the
        program is judged where the block runs.
        """
        for text, expected in (
            (
                'cd "$GITHUB_ACTION_PATH"; uv run --directory "$GITHUB_WORKSPACE" '
                "--no-config --no-project --python /usr/bin/python3 python -m x",
                ["PPA009"],
            ),
            (
                'uv run --directory "$GITHUB_ACTION_PATH" python -m x',
                ["PPA009"],
            ),
            # FALSE POSITIVE: --directory exempts nothing (R1).
            (
                "runs:\n  steps:\n    - run: uv run --directory "
                "${{ github.action_path }} python -m x\n",
                ["PPA006", "PPA007", "PPA001"],
            ),
            # FALSE POSITIVE: no directory exempts Python; only -I does.
            ('env -C "$GITHUB_ACTION_PATH" python3 -m x', ["PPA001"]),
            (
                'cd "$GITHUB_ACTION_PATH"; env --chdir "$GITHUB_WORKSPACE" python3 -m x',
                ["PPA001"],
            ),
            (
                'cd "$GITHUB_ACTION_PATH"; env --chdir="$GITHUB_WORKSPACE" python3 -m x',
                ["PPA009"],
            ),
            ('env --chdir="$GITHUB_ACTION_PATH" python3 -m x', ["PPA009"]),
            (
                'cd "$GITHUB_ACTION_PATH"; env -iC"$GITHUB_WORKSPACE" python3 -m x',
                ["PPA009"],
            ),
            (
                'cd "$GITHUB_ACTION_PATH"; env --chd="$GITHUB_WORKSPACE" python3 -m x',
                ["PPA009"],
            ),
            (
                'env -C "$GITHUB_ACTION_PATH" -C "$GITHUB_WORKSPACE" python3 -m x',
                ["PPA001"],
            ),
            # FALSE POSITIVE: no directory exempts Python; only -I does.
            (
                'set -e; cd "$GITHUB_ACTION_PATH"; env -C /opt -C sub python3 -m x',
                ["PPA001"],
            ),
            (
                'set -e; cd "$GITHUB_ACTION_PATH"; uv run --no-config --no-project '
                '--python /usr/bin/python3 env -C "$GITHUB_WORKSPACE" python3 -m x',
                ["PPA001"],
            ),
            (
                'set -e; cd "$GITHUB_ACTION_PATH"; env -C "$GITHUB_WORKSPACE" '
                "uv run python s.py",
                ["PPA006", "PPA007"],
            ),
            (
                "uv run --no-config --no-project --python /usr/bin/python3 "
                '--directory "$GITHUB_ACTION_PATH" env -C "$GITHUB_WORKSPACE" '
                "python3 -m tool",
                ["PPA009"],
            ),
            (
                'cd "$GITHUB_ACTION_PATH"; poetry run env -C "$GITHUB_WORKSPACE" '
                "python3 -m tool",
                ["PPA001"],
            ),
        ):
            kind = "action" if text.startswith("runs:") else "script"
            with self.subTest(text=text):
                self.assertEqual(rules(text, kind), expected)

    def test_env_wrapper_removes_step_settings(self) -> None:
        """env NAME=value replaces what the step's env: sets.

        -i, -u and - remove settings the scan would have to track, so
        before uv they are PPA009 (R3); the last NAME=value wins.
        """
        env = (
            "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
            "          UV_NO_CONFIG: '1'\n          UV_NO_PROJECT: '1'\n"
            "          UV_PYTHON: /opt/python\n        run: {}\n"
        )
        for line, expected in (
            ("uv run python s.py", []),
            (
                "env -u UV_NO_CONFIG -u UV_NO_PROJECT -u UV_PYTHON uv run python s.py",
                ["PPA009"],
            ),
            ("env -u UV_NO_PROJECT uv run python s.py", ["PPA009"]),
            ("env --unset=UV_NO_PROJECT uv run python s.py", ["PPA009"]),
            ("env -i PATH=/usr/bin uv run python s.py", ["PPA009"]),
            ("env - PATH=/usr/bin uv run python s.py", ["PPA009"]),
            ("env UV_PYTHON=.venv/bin/python uv run python s.py", ["PPA007"]),
            ('env -u "$v" uv run python s.py', ["PPA009"]),
            ("env UV_PYTHON=/usr/bin/python3 uv run python s.py", []),
            (
                "env UV_PYTHON=/usr/bin/python3 UV_PYTHON=.venv/bin/python "
                "uv run python s.py",
                ["PPA007"],
            ),
            (
                "UV_PYTHON=.venv/bin/python UV_PYTHON=/usr/bin/python3 "
                "uv run python s.py",
                [],
            ),
            (
                "UV_PYTHON=/usr/bin/python3 UV_PYTHON=.venv/bin/python "
                "uv run python s.py",
                ["PPA007"],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(env.format(line), "workflow"), expected)

    def test_launched_program_is_judged_like_any_other(self) -> None:
        """The program uv run starts goes through the usual wrappers and names."""
        safe = "uv run --no-config --no-project --python /usr/bin/python3 "
        for text, expected in (
            (safe + "env -S \"python3 -c 'import csv'\"", ["PPA009"]),
            (safe + "\"$prog\" -c 'import csv'", ["PPA009"]),
            (safe + "nice python3 -m x", ["PPA001"]),
            (safe + "python3 s.py", []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_missing_and_unknown_words(self) -> None:
        """A deciding uv word that is missing or unknown is PPA009."""
        for text in (
            "uv run --directory",
            "uv run --python",
            'uv "$verb" python s.py',
            'uv -q "$verb" python s.py',
            'uv --no-config "$verb" python s.py',
            'uv python "$verb"',
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["PPA009"])

    def test_expressions_in_uv_paths(self) -> None:
        """Only a literal absolute path is outside; no expression counts (R1)."""
        safe = "uv run --no-config --no-project --python {} python s.py"
        for path, kind, expected in (
            (
                "${{ github.workspace }}/.venv/bin/python",
                "workflow",
                ["PPA007"],
            ),
            ("${{ inputs.python }}", "workflow", ["PPA007"]),
            ("${{ inputs.venv }}/bin/python", "workflow", ["PPA007"]),
            ("${{ runner.temp }}/py/bin/python", "workflow", ["PPA007"]),
            (
                "${{ runner.temp }}/../w/.venv/bin/python",
                "workflow",
                ["PPA007"],
            ),
            ("${{ steps.py.outputs.python-path }}", "workflow", ["PPA007"]),
            (
                "${{ github.action_path }}/.venv/bin/python",
                "action",
                ["PPA007"],
            ),
            (
                "${{ github.action_path }}/.venv/bin/python",
                "workflow",
                ["PPA007"],
            ),
        ):
            line = safe.format(path)
            text = (
                f"on: push\njobs:\n  a:\n    steps:\n      - run: {line}\n"
                if kind == "workflow"
                else f"runs:\n  steps:\n    - run: {line}\n"
            )
            with self.subTest(path=path, kind=kind):
                self.assertEqual(rules(text, kind), expected)
        # --directory exempts nothing, wherever it points (R1).
        for directory, kind, expected in (
            (
                "${{ github.action_path }}",
                "action",
                ["PPA006", "PPA007", "PPA001"],
            ),
            (
                "${{ github.action_path }}/sub",
                "action",
                ["PPA006", "PPA007", "PPA001"],
            ),
            (
                "${{ github.action_path }}/..",
                "action",
                ["PPA006", "PPA007", "PPA001"],
            ),
            (
                "${{ github.action_path }}",
                "workflow",
                ["PPA006", "PPA007", "PPA001"],
            ),
            (
                "${{ github.workspace }}",
                "workflow",
                ["PPA006", "PPA007", "PPA001"],
            ),
            ("${{ inputs.dir }}", "workflow", ["PPA006", "PPA007", "PPA001"]),
        ):
            line = f"uv run --directory {directory} python -m x"
            text = (
                f"on: push\njobs:\n  a:\n    steps:\n      - run: {line}\n"
                if kind == "workflow"
                else f"runs:\n  steps:\n    - run: {line}\n"
            )
            with self.subTest(directory=directory, kind=kind):
                self.assertEqual(rules(text, kind), expected)

    def test_env_split_string(self) -> None:
        """env -S, however spelt, runs a command the scan does not read."""
        for text, expected in (
            ("env -S\"python3 -c 'import csv'\"", ["PPA009"]),
            ("env -iS 'python3 -c \"import csv\"'", ["PPA009"]),
            ("env --split-string='python3 -c \"import csv\"'", ["PPA009"]),
            ("env --spl='python3 -m x'", ["PPA009"]),
            ("env -S 'PYTHONPATH=/x: python3 /opt/tool.py'", ["PPA009"]),
            # FALSE POSITIVE: the split command is not read, even when safe.
            ("env -S 'python3 -I -c \"import csv\"'", ["PPA009"]),
            ('read -r cmd\nenv -S "$cmd"', ["PPA009"]),
            # Python's own -S is not env's.
            ('python3 -S "a b.py"', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_env_assignments_after_double_dash(self) -> None:
        for text, expected in (
            ("env -- PYTHONPATH=/opt/x: python3 /opt/tool.py", ["PPA004"]),
            (
                "env -- X=1 uv run --no-config python3 -I script.py",
                ["PPA007"],
            ),
            (
                "uv run --no-config --no-project --python /usr/bin/python3 "
                "env PYTHONPATH=/x: python3 /opt/tool.py",
                ["PPA004"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_wrappers(self) -> None:
        for text, expected in (
            ("sudo -u runner python3 -m x", ["PPA001"]),
            ("nice -n 10 python3 -c 'import csv'", ["PPA002"]),
            ("timeout -s KILL 30 python3 -m x", ["PPA001"]),
            ("command -v python3", []),
            ("coproc python3 -m x", ["PPA001"]),
            # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
            (
                'set -e; builtin cd "$GITHUB_ACTION_PATH"; python3 -m x',
                ["PPA001"],
            ),
            # The scan does not follow export, so it reports both.
            (
                "export UV_NO_CONFIG=1; sudo uv python find --system",
                ["PPA006"],
            ),
            (
                "export UV_NO_CONFIG=1; sudo -E uv python find --system",
                ["PPA006"],
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

    def test_no_directory_is_trusted(self) -> None:
        """A cd into the action path does not exempt uv (R1)."""
        text = 'set -e\ncd "$GITHUB_ACTION_PATH"\nuv run python x.py\nuv pip install six\n'
        self.assertEqual(rules(text), ["PPA006", "PPA007", "PPA007"])

    def test_path_values(self) -> None:
        """Only a path outside the workspace stops uv using the workspace's .venv.

        A value the scan cannot read is PPA009, as ESTATE.md counts it.
        """
        for value, expected in (
            ("3.12", ["PPA007"]),
            ("'>=3.10'", ["PPA007"]),
            ("/usr/bin/python3", []),
            ('"$py"', ["PPA009"]),
            ('"${py}"', ["PPA009"]),
            ('"$VENV/bin/python"', ["PPA009"]),
            ('"$version"', ["PPA009"]),
            (".venv/bin/python", ["PPA007"]),
            ('"$GITHUB_WORKSPACE/.venv/bin/python"', ["PPA009"]),
        ):
            text = (
                'py="$(command -v python3)"\n'
                f"uv pip install --python {value} six\n"
            )
            with self.subTest(value=value):
                self.assertEqual(rules(text), expected)

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
            # The expression must end the path or be followed by "/".
            (
                step(
                    "with:",
                    "  working-directory: ${{ github.action_path }}-cache",
                ),
                ["PPA008"],
            ),
            (step("with:", "  working-directory: /opt/uv"), []),
            (
                step("with:", "  working-directory: /home/runner/work/x"),
                ["PPA008"],
            ),
            (step("with:", "  working-directory: src"), ["PPA008"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text, "action"), expected)


class ContextTest(unittest.TestCase):
    """A block establishes nothing: no constants and no directory trust.

    A word is judged by what is written in the command (R1, R2).
    """

    def test_interpreter_variables(self) -> None:
        for text, expected in (
            # Unresolved: the deciding word is not a literal the scan reads.
            (
                'python="$RUNNER_TEMP/venv/bin/python"\n"$python" -m tool',
                ["PPA009"],
            ),
            ('PY=python3\n$PY -c "import x"', ["PPA009"]),
            # A program held in a variable the scan does not resolve.
            (
                'PYTHON_BIN="$(command -v python3)"\n"$PYTHON_BIN" -c "import x"',
                ["PPA009"],
            ),
            (
                'for candidate in python3 python; do\n  "$candidate" -m x\ndone',
                ["PPA009"],
            ),
            # Known limit (DESIGN.md): a variable holding a whole
            # command, with no Python-looking signal, is not seen.
            ('CLI="python -m tool.cli"\n${CLI} --version', []),
            ('CLI="uvx --from tool tool"\n${CLI} --version', []),
            ('"${PUBLISH[@]}" dist/*', []),
            ("$JSON_MODE", []),
            ('"$GIT" status', []),
            ("$SUDO apt-get install -y x", []),
            ("$SUDO python3 -m x", ["PPA009"]),
            ('"$UV" run python s.py', ["PPA009"]),
            # Python's options come first: -m later is not a signal.
            ('"$GIT" commit -m python3', []),
            ('$K exec "$BP" -c bridge', []),
            ('"$Python" s', ["PPA009"]),
            # FALSE POSITIVE: the value is not read, so -I is out of sight.
            (
                'python="$RUNNER_TEMP/venv/bin/python"\n"$python" -I -m tool',
                ["PPA009"],
            ),
            ('x="$(something)"\n"$x" -m tool', ["PPA009"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_arrays(self) -> None:
        for text, expected in (
            # An array's elements are not read (R2): it is PPA009 when
            # the command looks like Python, here by its "-" (which
            # tree-sitter drops before a heredoc) or its -c.
            # FALSE POSITIVE: the array's -I is not read.
            (
                'PY_RUN=(python3 -I)\n"${PY_RUN[@]}" - <<EOF\nimport x\nEOF',
                ["PPA009"],
            ),
            (
                'PY_RUN=(python3)\n"${PY_RUN[@]}" - <<EOF\nimport x\nEOF',
                ["PPA009"],
            ),
            # Known limit (DESIGN.md): no Python-looking signal.
            (
                'pip=("$venv/bin/python" -m pip download\n  --dest d)\n"${pip[@]}" six',
                [],
            ),
            # FALSE POSITIVE: uvx --from runs no project code, but the
            # scan does not read the array.
            (
                'tox_cmd=(uvx --from tox tox)\n"${tox_cmd[@]}" -c tox.ini',
                ["PPA009"],
            ),
            (
                'PY_RUN=(uv run --no-project --no-config --python "$py" --with pyyaml python)\n'
                '"${PY_RUN[@]}" - <<EOF\nimport yaml\nEOF',
                ["PPA009"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_setup_python_output(self) -> None:
        text = "- run: ${{ steps.setup.outputs.python-path }} -m pip install x"
        self.assertEqual(rules(text, "workflow"), ["PPA001"])

    def test_cd_in_a_subshell(self) -> None:
        text = 'set -e\n(\n  cd "$GITHUB_ACTION_PATH"\n  python3 -m inside\n)\npython3 -m outside\n'
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual(
            [(f.rule, f.line) for f in findings], [("PPA001", 4), ("PPA001", 6)]
        )

    def test_cd_elsewhere(self) -> None:
        text = 'set -e\ncd "$GITHUB_ACTION_PATH"\npython3 -m a\ncd "$GITHUB_WORKSPACE"\npython3 -m b\n'
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual(
            [(f.rule, f.line) for f in findings], [("PPA001", 3), ("PPA001", 5)]
        )

    def test_errexit(self) -> None:
        """A cd earns nothing, with or without -e (R1)."""
        for text, expected in (
            ('cd "$GITHUB_ACTION_PATH"\npython3 -m x', ["PPA001"]),
            ('set -e\ncd "$GITHUB_ACTION_PATH"\npython3 -m x', ["PPA001"]),
            (
                'set -euo pipefail\ncd "$GITHUB_ACTION_PATH"\npython3 -m x',
                ["PPA001"],
            ),
            (
                'set -o errexit\ncd "$GITHUB_ACTION_PATH"\npython3 -m x',
                ["PPA001"],
            ),
            (
                '#!/bin/bash -eu\ncd "$GITHUB_ACTION_PATH"\npython3 -m x',
                ["PPA001"],
            ),
            ('set -e\ncd "$GITHUB_ACTION_PATH"\npython3 -I -m x', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_step_shell_earns_nothing(self) -> None:
        """Whatever the step's shell, a cd exempts nothing (R1)."""
        for shell, expected in (
            ("bash", ["PPA001"]),
            ("sh", ["PPA001"]),
            ("bash -e {0}", ["PPA001"]),
            ("bash --noprofile --norc -eo pipefail {0}", ["PPA001"]),
            ("bash {0}", ["PPA001"]),
        ):
            text = (
                "runs:\n  using: composite\n  steps:\n"
                f"    - shell: {shell}\n      run: |\n"
                '        cd "$GITHUB_ACTION_PATH"\n        python3 -m x\n'
            )
            with self.subTest(shell=shell):
                self.assertEqual(rules(text, "action"), expected)

    def test_working_directory(self) -> None:
        text = (
            "runs:\n  steps:\n    - run: python3 -m a\n"
            "      working-directory: ${{ github.action_path }}\n"
            "    - run: python3 -m b\n      working-directory: src\n"
        )
        findings = audit.scan_text(text, "action", "repo", "action.yaml")
        # working-directory exempts nothing (R1).
        self.assertEqual(
            [(f.rule, f.line) for f in findings], [("PPA001", 3), ("PPA001", 5)]
        )

    def test_github_env_pythonpath(self) -> None:
        text = (
            'SAFE="${PYTHONPATH:-}"\nSAFE="${SAFE//x/}"\n'
            'echo "PYTHONPATH=${GITHUB_ACTION_PATH}/src:${SAFE}" >> "$GITHUB_ENV"\n'
            'echo "PYTHONPATH=${GITHUB_ACTION_PATH}/src" >> "$GITHUB_ENV"\n'
            'cat >> "$GITHUB_ENV" <<EOF\nPYTHONPATH=/opt/x:\nEOF\n'
        )
        findings = audit.scan_text(text, "script", "repo", "file")
        # $SAFE is not a name the scan knows; a heredoc's finding
        # names the line of the command that writes it.
        self.assertEqual(
            [(f.rule, f.line) for f in findings], [("PPA009", 3), ("PPA004", 5)]
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

    def test_command_output_is_unresolved(self) -> None:
        """Only $(pwd) is read; any other command's output is PPA009 (R2)."""
        for line, expected in (
            ('export PYTHONPATH="$(python3 -I f.py)"', ["PPA009"]),
            # The program inside is a variable the scan cannot resolve.
            ('PYTHONPATH="$("$python" -I "$FILTER")"', ["PPA009", "PPA009"]),
            ('export PYTHONPATH="$(python3 -I f.py):lib"', ["PPA009"]),
            ('export PYTHONPATH="$(pwd)/lib"', ["PPA005"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)

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

    def test_expressions_keep_their_meaning(self) -> None:
        """${{ env.PYTHONPATH }} is PYTHONPATH; github.workspace the workspace."""
        for line, kind, expected in (
            (
                'PYTHONPATH="/opt/x:${{ env.PYTHONPATH }}" python3 s.py',
                "workflow",
                ["PPA004"],
            ),
            (
                "PYTHONPATH=/opt/x:${{ env.PYTHONPATH }} python3 s.py",
                "workflow",
                ["PPA004"],
            ),
            (
                'echo "PYTHONPATH=/opt/x:${{ env.PYTHONPATH }}" >> "$GITHUB_ENV"',
                "workflow",
                ["PPA004"],
            ),
            # Unresolved: an input could name the workspace (R2).
            (
                'PYTHONPATH="/opt/x:${{ inputs.p }}" python3 s.py',
                "workflow",
                ["PPA009"],
            ),
            (
                'PYTHONPATH="${{ github.workspace }}/src" python3 s.py',
                "action",
                ["PPA005"],
            ),
            (
                'PYTHONPATH="${{ github.action_path }}/src" python3 s.py',
                "action",
                [],
            ),
            # Unresolved: $src is not a name the scan knows (R2).
            (
                "src=${{ github.action_path }}/src\nPYTHONPATH=$src python3 s.py",
                "action",
                ["PPA009"],
            ),
            (
                'PYTHONPATH="$GITHUB_ACTION_PATH/src:$OTHER" python3 s.py',
                "action",
                ["PPA009"],
            ),
            (
                'PYTHONPATH="$RUNNER_TEMP/a:$HOME/b:$pythonLocation/c" python3 s.py',
                "action",
                [],
            ),
        ):
            body = "".join(f"\n          {part}" for part in line.split("\n"))
            text = (
                f"on: push\njobs:\n  a:\n    steps:\n      - run: |{body}\n"
                if kind == "workflow"
                else f"runs:\n  steps:\n    - run: |{body}\n"
            )
            with self.subTest(line=line):
                self.assertEqual(rules(text, kind), expected)

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

    def test_joined_lines_map_to_their_own_line(self) -> None:
        """A finding names the line a command is on, however YAML joins it."""
        head = "on: push\njobs:\n  a:\n    steps:\n"
        mark = "# python-path-audit: ignore"
        for run, expected in (
            (
                f"      - run: >-\n          echo ready;\n          python3 -m x {mark}\n",
                [],
            ),
            (
                "      - run: >-\n          echo ready;\n          python3 -m x\n",
                [("PPA001", 7)],
            ),
            (
                "      - run: echo a &&\n          python3 -m y\n",
                [("PPA001", 6)],
            ),
            (
                "      - run: 'echo ''a'' &&\n          python3 -m y'\n",
                [("PPA001", 6)],
            ),
            (
                "      - run: >-\n          echo ${{ inputs.x }};\n"
                "          python3 -m z\n",
                [("PPA001", 7)],
            ),
        ):
            with self.subTest(run=run):
                findings = audit.scan_text(head + run, "workflow", "r", "f")
                self.assertEqual([(f.rule, f.line) for f in findings], expected)

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
        """working-directory exempts nothing, wherever it points (R1)."""
        for directory, expected in (
            ("${{ github.action_path }}", ["PPA001"]),
            ("${{ github.action_path }}/src", ["PPA001"]),
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

    def test_deep_nesting_is_reported(self) -> None:
        """A command nested past the walk's limit is PPA010, not skipped."""
        for depth, expected in ((20, set()), (2000, {"PPA010"})):
            text = "echo " + "${x:-" * depth + "y" + "}" * depth + "\n"
            with self.subTest(depth=depth):
                self.assertEqual(set(rules(text)), expected)
        text = "echo " + "${x:-" * 300 + "$(python3 -m x)" + "}" * 300 + "\n"
        found = rules(text)
        self.assertTrue(found)
        self.assertEqual(set(found), {"PPA010"})


class EnvWriteTest(unittest.TestCase):
    """PYTHONPATH values written to $GITHUB_ENV, however they are written."""

    def test_writers(self) -> None:
        for line, expected in (
            (
                "echo -e 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            ("echo 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"", []),
            # Unresolved: a conversion other than %s and %%, an escape
            # other than \\n, or a line that starts with an expansion
            # is not decoded (R4).
            (
                "printf '%b\\n' 'PYTHONPATH=/opt/x:\\nOTHER=1' >> \"$GITHUB_ENV\"",
                ["PPA009"],
            ),
            (
                "printf 'PYTHONPATH=%.7s\\n' /opt/x:abc >> \"$GITHUB_ENV\"",
                ["PPA009"],
            ),
            (
                "printf 'PYTHON\\x50ATH=/opt/x:\\n' >> \"$GITHUB_ENV\"",
                ["PPA009"],
            ),
            (
                "echo -e 'PYTHONPATH=/opt/x\\x3a' >> \"$GITHUB_ENV\"",
                ["PPA009"],
            ),
            ("printf 'OTHER=%d\\n' 1 >> \"$GITHUB_ENV\"", []),
            # Known limit (DESIGN.md): a command held in a variable
            # with no Python-looking signal is not seen.
            (
                'writer=(echo \'PYTHONPATH=/opt/x:\'); "${writer[@]}" >> "$GITHUB_ENV"',
                [],
            ),
            # Known limit (DESIGN.md): a whole line written from a
            # variable is not read, unless its text mentions PYTHONPATH.
            ('line=\'PYTHONPATH=/opt/x:\'; echo "$line" >> "$GITHUB_ENV"', []),
            (
                "line='PYTHONPATH=/opt/x:'\ncat >> \"$GITHUB_ENV\" <<EOF\n$line\nEOF",
                [],
            ),
            ('echo "OTHER=$x" >> "$GITHUB_ENV"', []),
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
            # A record: the lines between NAME<<DELIMITER and the delimiter.
            (
                'cat >> "$GITHUB_ENV" <<EOF\nPYTHONPATH<<END\n/opt/x:\nEND\nEOF',
                ["PPA004"],
            ),
            (
                'cat >> "$GITHUB_ENV" <<EOF\nPYTHONPATH<<END\n/opt/x\nEND\nEOF',
                [],
            ),
            (
                "printf 'PYTHONPATH<<END\\n/opt/x:\\nEND\\n' >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            (
                "echo -e 'PYTHONPATH<<END\\n/opt/x:\\nEND' >> \"$GITHUB_ENV\"",
                ["PPA004"],
            ),
            # A record that later writes go on with is not followed
            # across commands: PPA009, even when the value is safe.
            (
                '{\n  echo "PYTHONPATH<<EOF"\n  echo "/opt/x:"\n  echo "EOF"\n'
                '} >> "$GITHUB_ENV"',
                ["PPA009"],
            ),
            (
                '{\n  echo "PYTHONPATH<<EOF"\n  echo "/opt/x"\n  echo "EOF"\n'
                '} >> "$GITHUB_ENV"',
                ["PPA009"],
            ),
            (
                'echo "PYTHONPATH<<EOF" >> "$GITHUB_ENV"\n'
                'echo "/opt/x:" >> "$GITHUB_ENV"\necho EOF >> "$GITHUB_ENV"',
                ["PPA009"],
            ),
            # Another variable's record does not hide a later setting.
            (
                'cat >> "$GITHUB_ENV" <<EOF\nOTHER<<END\nx\nEND\n'
                "PYTHONPATH=/opt/x:\nEOF",
                ["PPA004"],
            ),
            # Output piped into tee, past wrappers, is written too.
            ('echo "PYTHONPATH=/opt/x:" | tee -a "$GITHUB_ENV"', ["PPA004"]),
            (
                'echo "PYTHONPATH=/opt/x:" | sudo tee -a "$GITHUB_ENV" >/dev/null',
                ["PPA004"],
            ),
            (
                'printf "PYTHONPATH=/opt/x:\\n" | cat >> "$GITHUB_ENV"',
                ["PPA004"],
            ),
            ('echo "PYTHONPATH=/opt/x:" | tee -a out.txt', []),
            # A newline inside quotes ends a line too.
            ('echo "OTHER=1\nPYTHONPATH=/opt/x:" >> "$GITHUB_ENV"', ["PPA004"]),
            # Known limit (DESIGN.md): a line written from a variable.
            (
                'line="PYTHONPATH=$GITHUB_ACTION_PATH/src:"\n'
                'cat <<EOF >> "$GITHUB_ENV"\n$line\nEOF',
                [],
            ),
            (
                'line="PYTHONPATH=$GITHUB_ACTION_PATH/src:"\n'
                'echo "$line"" " >> "$GITHUB_ENV"',
                [],
            ),
            (
                'line="OTHER=1\nPYTHONPATH=$GITHUB_ACTION_PATH:"\n'
                'echo "$line" >> "$GITHUB_ENV"',
                [],
            ),
            ('echo "$HOST_GATEWAY" >> "$GITHUB_ENV"', []),
            ('printf \'%s\\n\' "$env_lines" >> "$GITHUB_ENV"', []),
            ('printf "$fmt" >> "$GITHUB_ENV"', []),
            # Unresolved: an unread line that mentions PYTHONPATH.
            ('echo "$x PYTHONPATH" >> "$GITHUB_ENV"', ["PPA009"]),
            ('printf "$fmt" PYTHONPATH /x: >> "$GITHUB_ENV"', ["PPA009"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_record_findings_name_the_writing_command(self) -> None:
        text = (
            'echo start\ncat >> "$GITHUB_ENV" <<EOF\nOTHER=1\n'
            "PYTHONPATH<<END\n/opt/x:\nEND\nEOF\n"
        )
        findings = audit.scan_text(text, "script", "repo", "file")
        self.assertEqual([(f.rule, f.line) for f in findings], [("PPA004", 2)])


class WalkTest(unittest.TestCase):
    """How a block is walked: each command judged on its own words.

    The scan follows no directories, variables, branches, functions,
    exports or positional parameters: where the shell's state
    decides, it reports.
    """

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

    def test_no_cd_is_trusted(self) -> None:
        """No cd exempts Python, however it is guarded (R1)."""
        for text in (
            'cd "$GITHUB_ACTION_PATH"\npython3 -m x',
            'cd "$GITHUB_ACTION_PATH" || exit 1\npython3 -m x',
            'cd "$GITHUB_ACTION_PATH" || exit\npython3 -m x',
            'cd "$GITHUB_ACTION_PATH/src" && python3 -m x',
            'if a; then cd "$GITHUB_ACTION_PATH"; else cd "$GITHUB_ACTION_PATH"; fi\n'
            "python3 -m x",
            'pushd "$GITHUB_ACTION_PATH"\npython3 -m x',
        ):
            with self.subTest(text=text):
                self.assertEqual(self.step(text), ["PPA001"])

    def test_functions_are_judged_where_defined(self) -> None:
        for text, expected in (
            # FALSE POSITIVE: no cd is trusted; only -I exempts Python.
            ('f() { python3 -m x; }\ncd "$GITHUB_ACTION_PATH"\nf', ["PPA001"]),
            (
                'f() { python3 -m x; }\nf\ncd "$GITHUB_ACTION_PATH"\nf',
                ["PPA001"],
            ),
            # FALSE POSITIVE: a cd inside a function is not followed.
            (
                'go() { cd "$GITHUB_ACTION_PATH"; }\ngo\npython3 -m x',
                ["PPA001"],
            ),
            ("f() { python3 -m x; }", ["PPA001"]),
            # An array of all its elements is out of sight.
            (
                'setup() { PY=(python3); }\nrun_it() { "${PY[@]}" -m x; }',
                ["PPA009"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.step(text), expected)

    def test_yaml_working_directory_earns_nothing(self) -> None:
        """working-directory exempts nothing (R1)."""
        step = (
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n"
            "      working-directory: ${{{{ github.action_path }}}}\n"
            "      run: |\n        {}\n"
        )
        for line, expected in (
            ("python3 -c 'import csv'", ["PPA002"]),
            ("python3 -I -c 'import csv'", []),
            ("cd \"$GITHUB_WORKSPACE\"; python3 -c 'import csv'", ["PPA002"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(step.format(line), "action"), expected)

    def test_no_constants(self) -> None:
        """A variable's value is never read: a deciding $name is PPA009 (R2)."""
        for text, expected in (
            ("flags=-I\npython3 \"$flags\" -c 'import csv'", ["PPA009"]),
            ("flags=-I true; python3 \"$flags\" -c 'import csv'", ["PPA009"]),
            ("python3 \"$flags\" -c 'import csv'; flags=-I", ["PPA009"]),
            ("python3 $flags -c 'import csv'", ["PPA009"]),
            ("python3 ${flags:+-I} -c 'import csv'", ["PPA009"]),
            ('p=/opt/x:\nPYTHONPATH="$p" python3 s.py', ["PPA009"]),
            ('PYTHONPATH="$p" python3 s.py\np=/opt/x', ["PPA009"]),
            # Not a deciding word: a Python script's own argument.
            ('python3 -I s.py "$flags"', []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_redirected_command_substitutions(self) -> None:
        for text in (
            "echo \"$(python3 -c 'import csv')\" >out",
            "x=$(python3 -m tool) 2>/dev/null",
        ):
            with self.subTest(text=text):
                self.assertNotEqual(rules(text), [])

    def test_loops(self) -> None:
        text = 'cd "$GITHUB_ACTION_PATH"\nfor d in a b; do\n  python3 -m x\n  cd ..\ndone'
        self.assertEqual(self.step(text), ["PPA001"])

    def test_action_path_means_nothing_in_a_workflow(self) -> None:
        text = 'on: push\njobs:\n  a:\n    steps:\n      - run: cd "$GITHUB_ACTION_PATH" && python3 -m x\n'
        self.assertEqual(rules(text, "workflow"), ["PPA001"])

    def test_environment_variables_from_yaml(self) -> None:
        text = (
            "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
            "          PYTHON: ${{ steps.py.outputs.python-path }}\n"
            '        run: "\\"$PYTHON\\" -m unittest"\n'
        )
        # The interpreter is a step output the scan cannot read.
        self.assertEqual(rules(text, "workflow"), ["PPA009"])

    def test_set_allexport(self) -> None:
        # FALSE POSITIVE: set -a exporting the assignment is not followed.
        self.assertEqual(
            rules("set -a\nUV_NO_CONFIG=1\nuv python find --system"),
            ["PPA006"],
        )
        self.assertEqual(
            rules("set -a\nset +a\nUV_NO_CONFIG=1\nuv python find --system"),
            ["PPA006"],
        )

    def test_positional_parameters(self) -> None:
        """$1, $@ and the rest are never resolved: they are PPA009."""
        isolated = "python3 \"$@\" -c 'import csv'"
        for text, expected in (
            (f"set -- -I\n{isolated}", ["PPA009"]),
            (f"set -- -I\nshift\n{isolated}", ["PPA009"]),
            ("set foo -I\npython3 \"$2\" -c 'import csv'", ["PPA009"]),
            (
                "read -r x\nf() { python3 \"$2\" -c 'import csv'; }\nf $x -I",
                ["PPA009"],
            ),
            (
                'set -e\nread -r o\nset $o\ncd "$GITHUB_ACTION_PATH/missing"\n'
                "python3 -m x",
                ["PPA001"],
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_directory_stack(self) -> None:
        """pushd and popd earn nothing, like cd."""
        for text in (
            'set -e\ncd "$GITHUB_ACTION_PATH"\npushd -n sub\n'
            'cd "$GITHUB_WORKSPACE"\npopd\npython3 -m x',
            # FALSE POSITIVE: the stack ends where it began.
            'set -e\npushd -n "$GITHUB_ACTION_PATH"\npopd\npython3 -m x',
            'set -e\ncd "$GITHUB_ACTION_PATH"\npushd "$GITHUB_ACTION_PATH"\n'
            'popd +1\ncd "$OLDPWD"\npython3 -m x',
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["PPA001"])


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

    def test_windows_separators(self) -> None:
        """os.path.relpath gives backslashes on Windows."""
        self.assertEqual(
            audit.classify_kind(".github\\workflows\\ci.yaml"), "workflow"
        )
        self.assertEqual(audit.classify_kind("sub\\action.yml"), "action")
        self.assertIsNone(audit.classify_kind("docs\\workflows\\ci.yaml"))

    def test_named_file_finds_its_repository(self) -> None:
        """A file named on its own still gets its path within its repository."""
        script = os.path.join(self.root, "repo-a", "scripts", "run.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("python3 -I -m tool\n")
        self.assertEqual(audit.scan([script]), [])
        findings = audit.scan(
            [os.path.join(self.root, "repo-a", "scripts", "go.sh")]
        )
        self.assertEqual(
            [(f.repo, f.path) for f in findings], [("repo-a", "scripts/go.sh")]
        )


UV_STEP_ENV = (
    "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
    "          UV_NO_CONFIG: '1'\n          UV_NO_PROJECT: '1'\n"
    "          UV_PYTHON: /opt/python\n        run: {}\n"
)


def workflow_step(line: str, working_directory: str | None = None) -> str:
    """A workflow whose one step runs ``line``."""
    where = (
        f"        working-directory: {working_directory}\n"
        if working_directory
        else ""
    )
    return f"on: push\njobs:\n  a:\n    steps:\n      - run: {line}\n{where}"


class SilentPassTest(unittest.TestCase):
    """Commands an earlier version of the scan passed as clean."""

    def test_variables_are_never_read(self) -> None:
        """A deciding $name is PPA009 whatever the block does to it (R2)."""
        run = "python3 $flags -c 'import csv'"
        for before in (
            "",
            "flags=-I; ",
            "trap 'flags=-E' DEBUG; flags=-I; ",
            "flags=-I; builtin read -r flags; ",
            "flags='-I *'; ",
        ):
            with self.subTest(before=before):
                self.assertEqual(rules(before + run), ["PPA009"])

    def test_no_cd_earns_trust(self) -> None:
        """A cd earns nothing, so no wrapper or trap can take it back (R1)."""
        run = "python3 -c 'import csv'"
        for before in (
            'set -e; cd "$GITHUB_ACTION_PATH"; ',
            'set -e; cd "$GITHUB_ACTION_PATH"; command -p -- cd "$OLDPWD"; ',
            "set -e; cd \"$GITHUB_ACTION_PATH\"; trap 'echo done' EXIT; ",
            'sudo --chdir "$GITHUB_ACTION_PATH" ',
        ):
            with self.subTest(before=before):
                self.assertEqual(rules(before + run), ["PPA002"])

    def test_env_file_redirect_forms(self) -> None:
        """Each way of sending stdout to $GITHUB_ENV is read."""
        for line in (
            'echo >> "$GITHUB_ENV" PYTHONPATH=/opt/x:',
            "printf '%s\\n' >> \"$GITHUB_ENV\" 'PYTHONPATH=/opt/x:'",
            'echo PYTHONPATH=/opt/x: 1>> "$GITHUB_ENV"',
            'echo PYTHONPATH=/opt/x: &>> "$GITHUB_ENV"',
            'echo PYTHONPATH=/opt/x: >| "$GITHUB_ENV"',
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA004"])
        self.assertEqual(rules('echo PYTHONPATH=/opt/x: 2>> "$GITHUB_ENV"'), [])

    def test_wrapper_long_options(self) -> None:
        """Wrapper options that take a value are skipped with it."""
        for line in (
            "sudo --user runner python3 -m x",
            "sudo --user=runner python3 -m x",
            "sudo -Eu root python3 -m x",
            "sudo -R /srv python3 -m x",
            "sudo -D /srv python3 -m x",
            "nice --adjustment 10 python3 -m x",
            "nice --adj=5 python3 -m x",
            "timeout --signal KILL 5 python3 -m x",
            "/usr/bin/time -o out python3 -m x",
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA001"])
        self.assertEqual(rules("sudo --user runner python3 -I -m x"), [])

    def test_unknown_wrapper_options(self) -> None:
        """An option not in the wrapper's table is PPA009, not skipped (R3)."""
        for line in (
            "sudo --frobnicate python3 -m x",
            "sudo -X python3 -m x",
            "sudo -h python3 -m x",
            "sudo -Ex python3 -m x",
            'sudo "$opt" python3 -m x',
            "nice -10 python3 -m x",
            "timeout -z 5 python3 -m x",
            "env -x python3 -m x",
            "env --frobnicate python3 -m x",
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA009"])

    def test_uv_directory_and_project(self) -> None:
        """--directory and --project exempt nothing (R1)."""
        run = "python3 -c 'import csv'"
        for line in (
            f"uv run --directory sub {run}",
            f"uv run --directory /opt/tool --project . {run}",
            f"uv run --directory /opt/tool --project /opt/tool {run}",
        ):
            with self.subTest(line=line):
                self.assertIn("PPA007", rules(line))
        safe = "uv run --no-config --no-project --python /usr/bin/python3 "
        self.assertEqual(
            rules(safe + f"--directory /opt/tool {run}"), ["PPA002"]
        )
        self.assertEqual(
            rules(safe + "--directory /opt/tool python3 -I s.py"), []
        )

    def test_literal_outside_paths(self) -> None:
        """An outside path is literal, absolute, normalised and not a workspace."""
        for path, expected in (
            ("/usr/bin/python3", []),
            ("/opt/py/bin/python3/", []),
            ("/home/runner//work/x/.venv/bin/python", ["PPA007"]),
            ("//home/runner/work/x/.venv/bin/python", ["PPA007"]),
            ("/opt/../home/runner/work/x/python", ["PPA007"]),
            ("/home/runner/work/x/.venv/bin/python", ["PPA007"]),
            ("/__w/x/.venv/bin/python", ["PPA007"]),
            ("/github/workspace/.venv/bin/python", ["PPA007"]),
            ("'$HOME/bin/python'", ["PPA007"]),
            ("python3", ["PPA007"]),
        ):
            line = (
                f"uv run --no-config --no-project --python {path} python s.py"
            )
            with self.subTest(path=path):
                self.assertEqual(rules(line), expected)

    def test_uv_inner_wrappers_and_subcommand(self) -> None:
        """Wrappers inside uv run count, and an unread subcommand is unread."""
        self.assertEqual(
            rules(
                UV_STEP_ENV.format(
                    "uv run --no-config --no-project --python /usr/bin/python3 "
                    "env -u UV_NO_CONFIG uv python find --system"
                ),
                "workflow",
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(
                workflow_step("uv ${{ inputs.command }} python s.py"),
                "workflow",
            ),
            ["PPA009"],
        )

    def test_env_wrapper_order(self) -> None:
        """env reads its words in order; -i before uv is PPA009 (R3)."""
        self.assertEqual(
            rules(
                UV_STEP_ENV.format(
                    'env UV_NO_CONFIG=1 env -i PATH="$PATH" uv python find --system'
                ),
                "workflow",
            ),
            ["PPA009"],
        )
        # Before Python, -i and -u cannot add to sys.path.
        self.assertEqual(rules("env -i -u X python3 -I s.py"), [])
        self.assertEqual(rules("env -u X python3 -m x"), ["PPA001"])
        self.assertEqual(
            rules(
                UV_STEP_ENV.format(
                    "env X=1 UV_PYTHON=.venv/bin/python uv run python s.py"
                ),
                "workflow",
            ),
            ["PPA007"],
        )
        # Unresolved: a word env reads that the scan cannot (R3).
        self.assertEqual(
            rules(
                UV_STEP_ENV.format(
                    'env X="$x" UV_PYTHON=/usr/bin/python3 uv run python s.py'
                ),
                "workflow",
            ),
            ["PPA009"],
        )

    def test_literal_working_directory_in_the_workspace(self) -> None:
        """A runner workspace path is not outside the checkout."""
        run = "python3 -c 'import csv'"
        for path in ("/home/runner/work/demo/demo", "/__w/demo/demo"):
            with self.subTest(path=path):
                self.assertEqual(
                    rules(workflow_step(run, path), "workflow"), ["PPA002"]
                )

    def test_pythonpath_fallback_operand(self) -> None:
        """A default operand of ${PYTHONPATH:-...} is judged too."""
        self.assertEqual(
            rules('PYTHONPATH="${PYTHONPATH:-/opt/x:}" python3 s.py'),
            ["PPA004"],
        )
        # Unresolved: $fallback is not a name the scan knows (R2).
        self.assertEqual(
            rules(
                'fallback="$T:"; '
                'PYTHONPATH="${PYTHONPATH:-$fallback}" python3 "$T/script.py"'
            ),
            ["PPA009"],
        )

    def test_unusual_spellings(self) -> None:
        """A backslash or ANSI-C string in a deciding word is PPA009 (R4)."""
        for line in (
            "python\\3 -c 'import csv'",
            "python3 \\-c 'import csv'",
            "$'python3' -c 'import csv'",
            "python3 $'-c' 'import csv'",
            "PYTHONPATH=/opt/x\\: python3 s.py",
            "PYTHONPATH=$'/opt/x:' python3 s.py",
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA009"])


def step_with_env(env: dict[str, str], line: str) -> str:
    """A workflow whose one step sets ``env`` and runs ``line``."""
    block = "".join(f"          {k}: {v}\n" for k, v in env.items())
    return (
        "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
        f"{block}        run: {line}\n"
    )


class ReviewRoundFourTest(unittest.TestCase):
    """The fourth review round's findings that are not known limits."""

    def test_sudo_environment(self) -> None:
        """sudo's NAME=value words count, and sudo drops the rest."""
        safe = "uv run --no-config --no-project python s.py"
        outside = {"UV_PYTHON": "/usr/bin/python3"}
        for line, expected in (
            (f"sudo UV_PYTHON=.venv/bin/python {safe}", ["PPA007"]),
            (f"sudo {safe}", ["PPA007"]),
            (f"sudo -E {safe}", []),
            (f"sudo --preserve-env {safe}", []),
            (f"sudo --preserve-env=UV_PYTHON {safe}", []),
            (f"sudo --preserve-env=HOME {safe}", ["PPA007"]),
            (f"sudo -u root UV_PYTHON=/opt/py/bin/python {safe}", []),
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    rules(step_with_env(outside, line), "workflow"), expected
                )
        self.assertEqual(rules("sudo uv pip install --system x"), [])

    def test_exec_clears_the_environment(self) -> None:
        """exec -c drops the step's uv settings."""
        env = {"UV_NO_CONFIG": "'1'"}
        for line, expected in (
            ("exec -c uv python find --system", ["PPA006"]),
            ("exec -cl uv python find --system", ["PPA006"]),
            ("exec -a name uv python find --system", []),
            ("exec uv python find --system", []),
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    rules(step_with_env(env, line), "workflow"), expected
                )

    def test_python_request_wins_over_virtual_env(self) -> None:
        """VIRTUAL_ENV protects only with no --python or UV_PYTHON."""
        for line, expected in (
            ("VIRTUAL_ENV=/opt/safe uv pip list", []),
            (
                "VIRTUAL_ENV=/opt/safe UV_PYTHON=.venv/bin/python uv pip list",
                ["PPA007"],
            ),
            (
                "VIRTUAL_ENV=/opt/safe uv pip list --python .venv/bin/python",
                ["PPA007"],
            ),
            (
                "VIRTUAL_ENV=/opt/safe uv run --no-config --no-project "
                "--python .venv/bin/python s.py",
                ["PPA007"],
            ),
            (
                "VIRTUAL_ENV=/opt/safe uv run --no-config --no-project s.py",
                [],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)
        # A UV_PYTHON the scan cannot read is still a request.
        unread = {"VIRTUAL_ENV": "/opt/safe", "UV_PYTHON": "${{ inputs.py }}"}
        self.assertEqual(
            rules(step_with_env(unread, "uv pip list"), "workflow"),
            ["PPA007"],
        )

    def test_action_pythonpath_in_the_workspace(self) -> None:
        """A literal workspace PYTHONPATH entry in an action is PPA005."""
        for value, expected in (
            ("/github/workspace/lib", ["PPA005"]),
            ("/home/runner/work/repo/repo/lib", ["PPA005"]),
            ("/opt/../home/runner/work/x", ["PPA005"]),
            ("//github/workspace", ["PPA005"]),
            ("/__w/repo/repo", ["PPA005"]),
            ("/home/runner/workspace", []),
            ("/opt/lib", []),
            ('"$RUNNER_TEMP/lib"', []),
        ):
            with self.subTest(value=value):
                line = f"PYTHONPATH={value} python3 s.py"
                self.assertEqual(rules(action_step(line), "action"), expected)
        yaml_env = (
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n"
            "      env:\n        PYTHONPATH: /github/workspace/lib\n"
            "      run: python3 s.py\n"
        )
        self.assertEqual(rules(yaml_env, "action"), ["PPA005"])
        # Workflows run in their own checkout: no PPA005.
        self.assertEqual(
            rules(
                workflow_step("PYTHONPATH=/github/workspace/lib python3 s.py"),
                "workflow",
            ),
            [],
        )

    def test_unread_word_before_the_uv_run_program(self) -> None:
        """An unread word may be a uv option until a literal -- ends them."""
        safe = "UV_PYTHON=/usr/bin/python3 uv run --no-config --no-project"
        self.assertEqual(rules(f'{safe} "$opts" true'), ["PPA009"])
        self.assertEqual(rules(f"{safe} $opts python3 -I s.py"), ["PPA009"])
        self.assertEqual(rules(f'{safe} -- "$tool" x'), [])
        self.assertEqual(rules(f"{safe} -- python3 -I s.py"), [])

    def test_env_file_expression_lines(self) -> None:
        """An expression starting an env-file line could name PYTHONPATH."""
        for line, expected in (
            ('echo "${{ inputs.line }}" >> "$GITHUB_ENV"', ["PPA009"]),
            ("echo ${{ inputs.line }} >> $GITHUB_ENV", ["PPA009"]),
            (
                'printf \'%s\\n\' "${{ inputs.line }}" >> "$GITHUB_ENV"',
                ["PPA009"],
            ),
            ('echo "X=${{ inputs.line }}" >> "$GITHUB_ENV"', []),
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    rules(workflow_step(line), "workflow"), expected
                )

    def test_printf_option_terminator(self) -> None:
        """printf -- is skipped before the format."""
        self.assertEqual(
            rules("printf -- 'PYTHONPATH=/opt/x:\\n' >> \"$GITHUB_ENV\""),
            ["PPA004"],
        )
        self.assertEqual(
            rules("printf -- 'PYTHONPATH=/opt/x\\n' >> \"$GITHUB_ENV\""), []
        )

    def test_setup_uv_ignore_mark(self) -> None:
        """PPA008 honours the ignore mark on its line or the line above."""
        head = "on: push\njobs:\n  a:\n    steps:\n"
        uses = "      - uses: astral-sh/setup-uv@v1"
        mark = "# python-path-audit: ignore"
        self.assertEqual(rules(head + uses + "\n", "workflow"), ["PPA008"])
        self.assertEqual(rules(f"{head}{uses}  {mark}\n", "workflow"), [])
        self.assertEqual(rules(f"{head}      {mark}\n{uses}\n", "workflow"), [])

    def test_known_limits(self) -> None:
        """Documented limits (DESIGN.md, Known limits) stay unreported."""
        for line in (
            'set -- python3 -m planted; "$@"',
            "args='name python3 -m planted'; exec -a $args echo",
            '"${PUBLISH[@]}" --repository-url "$URL" dist/*',
            "${compose_cmd} up -d",
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), [])


class ReviewRoundFiveTest(unittest.TestCase):
    """The fifth review round: table, reader and marker gaps."""

    def test_pathed_writers_and_tee(self) -> None:
        """echo, printf and tee are known by the program's basename."""
        for line in (
            "echo 'PYTHONPATH=/opt/x:' | /usr/bin/tee -a \"$GITHUB_ENV\"",
            "echo 'PYTHONPATH=/opt/x:' | 'tee' -a \"$GITHUB_ENV\"",
            "/usr/bin/printf 'PYTHONPATH=/opt/x:\\n' >> \"$GITHUB_ENV\"",
            "/bin/echo 'PYTHONPATH=/opt/x:' >> \"$GITHUB_ENV\"",
            'tee -a "$GITHUB_ENV" <<EOF\nPYTHONPATH=/opt/x:\nEOF',
            '/usr/bin/tee "${GITHUB_ENV}" <<EOF\nPYTHONPATH=/opt/x:\nEOF',
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA004"])
        self.assertEqual(
            rules('tee -a "$GITHUB_ENV" <<EOF\nPYTHONPATH=/opt/x\nEOF'), []
        )
        self.assertEqual(rules("tee -a out.txt <<EOF\nPYTHONPATH=:\nEOF"), [])

    def test_declaration_words(self) -> None:
        """Single-quoted and += declaration words are judged."""
        for line, expected in (
            ("export 'PYTHONPATH=/opt/x:'; python3 /opt/s.py", ["PPA004"]),
            ("readonly 'PYTHONPATH=/opt/x'", []),
            ('export "PYTHONPATH+=:/opt/x"', ["PPA004"]),
            ("export 'PYTHONPATH+=:/opt/x'", ["PPA004"]),
            ('builtin export "PYTHONPATH+=:/opt/x"', ["PPA004"]),
            ('export "PYTHONPATH+=/opt/x"', []),
            # env sets a variable named "PYTHONPATH+", not PYTHONPATH.
            ('env "PYTHONPATH+=:/opt/x" python3 s.py', []),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_blank_lines_in_a_record(self) -> None:
        """A blank line inside NAME<<DELIMITER is part of the value."""
        line = (
            "printf 'PYTHONPATH<<END\\n\\n/opt/lib\\nEND\\n' >> \"$GITHUB_ENV\""
        )
        self.assertEqual(rules(action_step(line), "action"), ["PPA005"])
        heredoc = (
            'cat >> "$GITHUB_ENV" <<EOF\nPYTHONPATH<<END\n\n/opt/lib\nEND\nEOF'
        )
        body = "".join(
            f"        {ln}\n" if ln else "\n" for ln in heredoc.split("\n")
        )
        action = action_step("true") + body
        self.assertEqual(rules(action, "action"), ["PPA005"])

    def test_wrapper_operands_are_not_settings(self) -> None:
        """An option's operand (exec -a NAME=1) sets nothing."""
        env = {"X": "'1'"}
        for line, expected in (
            ("exec -a UV_NO_CONFIG=1 uv python find --system", ["PPA006"]),
            (
                "exec -a UV_PYTHON=/usr/bin/python3 "
                "uv run --no-config --no-project python s.py",
                ["PPA007"],
            ),
            ("sudo -u root UV_NO_CONFIG=1 uv python find --system", []),
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    rules(step_with_env(env, line), "workflow"), expected
                )

    def test_program_name_stem_is_case_insensitive(self) -> None:
        """$Python and $Py are Python-looking names."""
        for line in ('"$Python" s', '"$Py" x', '"$Python3" t'):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA009"])
        self.assertEqual(rules('"$HELPER" run'), [])

    def test_python_options_come_first(self) -> None:
        """Only the first argument's option is a Python signal."""
        for line, expected in (
            ('$K exec "$BP" -c bridge', []),
            ('"$X" status -m msg', []),
            ('"$X" -m tool', ["PPA009"]),
            ('"$X" -Im tool', ["PPA009"]),
            ('"$X" a b c tool.py', ["PPA009"]),
            ('"$X" python3 -m tool', ["PPA009"]),
            ('"$X" /usr/bin/uv run s', ["PPA009"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_normalised_partial_literals(self) -> None:
        """Complete literal components are normalised before an expansion."""
        for value, expected in (
            ('"/home/runner//work/repo/repo$HOME"', ["PPA005"]),
            ('"/opt/../github/workspace/$HOME"', ["PPA005"]),
            ('"/home/runner/work$HOME"', ["PPA005"]),
            ('"/opt/./lib/$HOME"', []),
            ('"/home/runner/work-$HOME"', []),
        ):
            with self.subTest(value=value):
                line = f"PYTHONPATH={value} python3 s.py"
                self.assertEqual(rules(action_step(line), "action"), expected)

    def test_expression_before_the_uv_run_program(self) -> None:
        """A ${{ }} expression may be uv options until a literal --."""
        safe = "UV_PYTHON=/usr/bin/python3 uv run --no-config --no-project"
        self.assertEqual(
            rules(
                workflow_step(f"{safe} ${{{{ inputs.opts }}}} true"), "workflow"
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(
                workflow_step(f"{safe} -- ${{{{ inputs.tool }}}} x"),
                "workflow",
            ),
            [],
        )


class ReviewRoundSixTest(unittest.TestCase):
    """The sixth review round: reader and table gaps."""

    def test_attached_python_operands(self) -> None:
        """-pPATH, -p=PATH and -qpPATH are Python requests, as uv reads them."""
        venv = "VIRTUAL_ENV=/opt/safe uv pip list"
        for line, expected in (
            (f"{venv} -p.venv/bin/python", ["PPA007"]),
            (f"{venv} -qp.venv/bin/python", ["PPA007"]),
            (f"{venv} -p=.venv/bin/python", ["PPA007"]),
            ("uv pip list -p/usr/bin/python3", []),
            ("uv pip list -p=/usr/bin/python3", []),
            (
                "uv run --no-config --no-project -p/usr/bin/python3 python s.py",
                [],
            ),
            (f'{venv} -p"$PY"', ["PPA009"]),
            (f'{venv} --python="$PY"', ["PPA009"]),
            (f'{venv} "--python=$PY"', ["PPA009"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_append_assignments_are_not_read(self) -> None:
        """NAME+=value appends to a value the scan does not follow."""
        env = {"UV_PROJECT_ENVIRONMENT": ".venv"}
        for line, expected in (
            (
                "UV_PROJECT_ENVIRONMENT+=/opt/safe uv export --no-config --locked",
                ["PPA007"],
            ),
            ("UV_PROJECT_ENVIRONMENT=/opt/safe uv export --locked", []),
            ("VIRTUAL_ENV+=/opt/safe uv pip list", ["PPA007"]),
            (
                "UV_PYTHON+=/usr/bin/python3 "
                "uv run --no-config --no-project python s.py",
                ["PPA007"],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    rules(step_with_env(env, line), "workflow"), expected
                )

    def test_cat_forwards_a_pipe_into_the_env_file(self) -> None:
        """cat or tee writing $GITHUB_ENV inside a group forwards its input."""
        for line, expected in (
            ("printf 'PYTHONPATH=/opt/x:\\n' | cat >> \"$GITHUB_ENV\"", 1),
            ('echo PYTHONPATH=/opt/x: | { cat >> "$GITHUB_ENV"; }', 1),
            ('echo PYTHONPATH=/opt/x: | (cat - >> "$GITHUB_ENV")', 1),
            ('echo PYTHONPATH=/opt/x: | (cat) >> "$GITHUB_ENV"', 1),
            ('echo PYTHONPATH=/opt/x: | { tee -a "$GITHUB_ENV"; }', 1),
            ('echo PYTHONPATH=/opt/x: | { cat f >> "$GITHUB_ENV"; }', 0),
            ("echo PYTHONPATH=/opt/x: | { cat >> out.txt; }", 0),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA004"] * expected)

    def test_quoted_unread_env_assignments(self) -> None:
        """An unread NAME= word is judged whichever quote opens it."""
        for line in (
            "env 'PYTHONPATH='\"$VALUE\" python3 /opt/script.py",
            'env "PYTHONPATH=$VALUE" python3 /opt/script.py',
            "sudo 'PYTHONPATH='\"$VALUE\" python3 /opt/script.py",
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), ["PPA009"])

    def test_wrapper_operands_set_no_pythonpath(self) -> None:
        """Only env and sudo NAME=value words assign; exec -a's operand does not."""
        for line, expected in (
            ("exec -a PYTHONPATH=/opt/lib: python3 /opt/script.py", []),
            ("nohup PYTHONPATH=/opt/lib: python3 /opt/script.py", []),
            ("env PYTHONPATH=/opt/lib: python3 /opt/script.py", ["PPA004"]),
            ("sudo PYTHONPATH=/opt/lib: python3 /opt/script.py", ["PPA004"]),
            (
                "nice -n 5 env PYTHONPATH=/opt/lib: python3 /opt/script.py",
                ["PPA004"],
            ),
            (
                "exec -a x env PYTHONPATH=/opt/lib: python3 /opt/script.py",
                ["PPA004"],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_heredoc_is_input_only_to_cat_and_tee(self) -> None:
        """A heredoc reaches $GITHUB_ENV only through cat or tee."""
        body = "\nPYTHONPATH=/opt/lib:\nEOF"
        for head, expected in (
            ('true <<EOF >> "$GITHUB_ENV"', []),
            ('echo <<EOF >> "$GITHUB_ENV"', []),
            ('cat notes.txt <<EOF >> "$GITHUB_ENV"', []),
            ('cat <<EOF >> "$GITHUB_ENV"', ["PPA004"]),
            ('cat - <<EOF >> "$GITHUB_ENV"', ["PPA004"]),
            ('/bin/cat <<EOF >> "$GITHUB_ENV"', ["PPA004"]),
            ('tee <<EOF >> "$GITHUB_ENV"', ["PPA004"]),
            ('"$WRITER" <<EOF >> "$GITHUB_ENV"', ["PPA004"]),
        ):
            with self.subTest(head=head):
                self.assertEqual(rules(head + body), expected)

    def test_other_records_are_skipped(self) -> None:
        """Another variable's NAME<<DELIMITER body sets no PYTHONPATH."""
        for fmt, expected in (
            ("OTHER<<END\\nPYTHONPATH=/opt/lib:\\nEND\\n", []),
            ("OTHER<<END\\nx\\nEND\\nPYTHONPATH=/opt/lib:\\n", ["PPA004"]),
            ("OTHER<<END\\nPYTHONPATH=/opt/lib:\\n", []),
            ("OTHER=a<<b\\nPYTHONPATH=/opt/lib:\\n", ["PPA004"]),
            ("PYTHONPATH<<END\\n/opt/lib:\\nEND\\n", ["PPA004"]),
        ):
            with self.subTest(fmt=fmt):
                line = f"printf '{fmt}' >> \"$GITHUB_ENV\""
                self.assertEqual(rules(line), expected)

    def test_any_unknown_expression_before_the_uv_run_program(self) -> None:
        """${{ inputs.python }} there may hold uv options too."""
        safe = "uv run --no-config --no-project --python /usr/bin/python3"
        for rest, expected in (
            ("${{ inputs.python }} true", ["PPA009"]),
            ("${{ env.PYTHONPATH }} true", ["PPA009"]),
            ("-- ${{ inputs.python }} s.py", []),
        ):
            with self.subTest(rest=rest):
                self.assertEqual(
                    rules(workflow_step(f"{safe} {rest}"), "workflow"),
                    expected,
                )
        # The action path is a path, not options.
        line = f"{safe} ${{{{ github.action_path }}}}/tool"
        self.assertEqual(rules(action_step(line), "action"), [])


class ReviewRoundSevenTest(unittest.TestCase):
    """The seventh review round: reader gaps."""

    def test_literal_assignment_names_are_kept(self) -> None:
        """A quote inside a literal NAME= word is part of the name."""
        settings = "UV_NO_CONFIG=1 UV_NO_PROJECT=1 UV_PYTHON=/usr/bin/python3"
        odd = " ".join(f'"\'{word}"' for word in settings.split())
        for line, expected in (
            (f"env {odd} uv run python s.py", ["PPA006", "PPA007"]),
            (f"sudo {odd} uv run python s.py", ["PPA006", "PPA007"]),
            (f"env {settings} uv run python s.py", []),
            (f"env 'UV_NO_CONFIG'=1 {settings} uv run python s.py", []),
            ('env "\'PYTHONPATH=/opt/lib:" python3 /opt/script.py', []),
            ('env "UV_PYTHON=$P" uv run --no-config python s.py', ["PPA009"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_pipe_reaches_the_env_file_from_the_last_stage(self) -> None:
        """Only stages that forward their input carry a line to the file."""
        line = "printf 'PYTHONPATH=/opt/lib:\\n'"
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"{line} | cat | tee {env}", 1),
            (f"{line} | cat | cat >> {env}", 1),
            (f"{line} | (cat | cat) >> {env}", 1),
            (f"{line} | {{ cat; }} | tee -a {env} > /dev/null", 1),
            (f"{{ {line} | cat; }} >> {env}", 1),
            (f"{{ {line} | true; }} >> {env}", 0),
            (f"{line} | true >> {env}", 0),
            (f"{line} | cat | cat > out.txt", 0),
            (f"{line} | cat > /dev/null | cat >> {env}", 0),
            (f"{line} | cat < /dev/null >> {env}", 0),
            (f"{line} | cat <<< x >> {env}", 0),
            (f"{line} | cat <&0 >> {env}", 1),
            (f"{line} > out.txt | cat >> {env}", 0),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["PPA004"] * expected)

    def test_last_stdout_redirect_wins(self) -> None:
        """A command's own stdout redirect overrides its group's."""
        echo = "echo PYTHONPATH=/opt/lib:"
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"{{ {echo} > out.txt; }} >> {env}", 0),
            (f"{{ {echo} >&2; }} >> {env}", 0),
            (f'{{ {echo} > "$OUT"; }} >> {env}', 1),
            (f"{{ {echo} 2>/dev/null; }} >> {env}", 1),
            (f"{echo} >> {env} > /dev/null", 0),
            (f"{echo} > /dev/null >> {env}", 1),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["PPA004"] * expected)

    def test_cat_reads_input_named_by_a_dash(self) -> None:
        """cat copies its input when "-" is among its file operands."""
        line = "printf 'PYTHONPATH=/opt/lib:\\n'"
        body = "\nPYTHONPATH=/opt/lib:\nEOF"
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"{line} | cat /dev/null - >> {env}", 1),
            (f"{line} | cat -- - >> {env}", 1),
            (f"{line} | cat /dev/null >> {env}", 0),
            (f"cat /dev/null - <<EOF >> {env}{body}", 1),
            (f"cat /dev/null <<EOF >> {env}{body}", 0),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["PPA004"] * expected)

    def test_uvx_options_end_at_its_program(self) -> None:
        """The tool's own options are not uvx's."""
        for line, expected in (
            ('uvx virtualenv --python "$PY" /tmp/venv', []),
            ('uvx virtualenv -p"$PY" /tmp/venv', []),
            ('uvx --python "$PY" virtualenv /tmp/venv', ["PPA009"]),
            ('uvx -p"$PY" virtualenv /tmp/venv', ["PPA009"]),
            ('uvx --python="$PY" virtualenv /tmp/venv', ["PPA009"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_unread_attached_option_before_the_program(self) -> None:
        """-p"$PY" right before the uv run program names its option."""
        line = 'uv run --no-config --no-project -p"$PY" python s.py'
        found = audit.scan_text(line, "script", "repo", "file")
        self.assertEqual([f.rule for f in found], ["PPA009"])
        self.assertIn("uv --python", found[0].detail)


class ReviewRoundEightTest(unittest.TestCase):
    """The eighth review round: reader and discovery gaps."""

    def test_pipeline_redirects_belong_to_the_last_stage(self) -> None:
        """A heredoc on a pipeline is the last stage's input."""
        body = "\nPYTHONPATH=/opt/lib:\nEOF\n"
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"true | cat <<EOF >> {env}{body}", ["PPA004"]),
            (f"true | cat - <<EOF >> {env}{body}", ["PPA004"]),
            (f"true | tee -a {env} <<EOF{body}", ["PPA004"]),
            (f"true | grep x <<EOF >> {env}{body}", []),
            (f"true | cat <<EOF > out.txt{body}", []),
            ("true | python3 < f -I -c x", []),
            ("true | python3 0< f -c x", ["PPA002"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_equals_in_a_program_path(self) -> None:
        """Only sudo, time and coproc read NAME=value words as assignments."""
        for line, expected in (
            ("/opt/runtime=3/bin/python3 -c 'import csv'", ["PPA002"]),
            ("nice /opt/runtime=3/bin/python3 -c x", ["PPA002"]),
            # nice runs a program named "A=b".
            ("nice A=b python3 -c x", []),
            ("sudo A=b python3 -c x", ["PPA002"]),
            ("time A=b python3 -c x", ["PPA002"]),
            ("time -p PYTHONPATH=/opt: python3 /opt/s.py", ["PPA004"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_scan_root_inside_github(self) -> None:
        """A root of .github or .github/workflows still finds workflows."""
        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, ".github", "workflows")
            os.makedirs(folder)
            with open(
                os.path.join(folder, "ci.yaml"), "w", encoding="utf-8"
            ) as handle:
                handle.write(workflow_step("python3 -c 'import csv'"))
            for scanned in (root, os.path.join(root, ".github"), folder):
                with self.subTest(root=scanned):
                    found = audit.scan([scanned])
                    self.assertEqual([f.rule for f in found], ["PPA002"])

    def test_here_strings_into_the_env_file(self) -> None:
        """A here-string into cat or tee is written like a heredoc."""
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"cat <<< 'PYTHONPATH=/opt/x:' >> {env}", ["PPA004"]),
            (f"true | cat <<< 'PYTHONPATH=/opt/x:' >> {env}", ["PPA004"]),
            (f"tee -a {env} <<< 'PYTHONPATH=/opt/x:'", ["PPA004"]),
            (f'cat <<< "PYTHONPATH=$X" >> {env}', ["PPA009"]),
            (f"cat <<< 'PYTHONPATH=/opt/x' >> {env}", []),
            (f"grep x <<< 'PYTHONPATH=/opt/x:' >> {env}", []),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_yaml_env_text_is_not_an_expression(self) -> None:
        """Literal YAML text that looks like a swapped expression is text."""
        for value, expected in (
            ("GHEXPR_TEMP", ["PPA005"]),
            ("GHEXPR_ACTION_PATH/lib", ["PPA005"]),
            ("${{ runner.temp }}", []),
        ):
            with self.subTest(value=value):
                action = (
                    "runs:\n  using: composite\n  steps:\n    - shell: bash\n"
                    f"      env:\n        PYTHONPATH: {value}\n"
                    "      run: echo hi\n"
                )
                self.assertEqual(rules(action, "action"), expected)

    def test_descriptor_before_a_redirect(self) -> None:
        """The descriptor of "0<" is not an argument, whatever follows."""
        for line, expected in (
            ("python3 0< /dev/null -c 'import csv'", ["PPA002"]),
            ("python3 0< /dev/null -I -c 'import csv'", []),
            ("python3 2>/dev/null -c x", ["PPA002"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_command_substitution_output_is_captured(self) -> None:
        """A substitution's output does not go where its command's does."""
        env = '"$GITHUB_ENV"'
        for text, expected in (
            (f"{{ value=$(echo 'PYTHONPATH=/opt/lib:'); }} >> {env}", []),
            (f"echo \"$(python3 -c 'import x')\" >> {env}", ["PPA002"]),
            (f"{{ echo 'PYTHONPATH=/opt/lib:'; }} >> {env}", ["PPA004"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), expected)

    def test_descriptor_duplication_is_a_known_limit(self) -> None:
        """The scan does not follow >&2 or 2>&1 onto an env-file redirect."""
        line = "echo 'PYTHONPATH=/opt/lib:' 2>> \"$GITHUB_ENV\" >&2"
        self.assertEqual(rules(line), [])


class ReviewRoundNineTest(unittest.TestCase):
    """The ninth review round: assignments, markers and discovery."""

    def test_prefix_assignments_after_time_and_coproc(self) -> None:
        """Only an unquoted NAME= or NAME+= opening is an assignment there."""
        for line, expected in (
            ("time /opt/runtime=3/bin/python3 -c 'import csv'", ["PPA002"]),
            ("coproc /opt/runtime=3/bin/python3 -c x", ["PPA002"]),
            ("time 'A=b/python3' -c x", ["PPA002"]),
            # A quoted name is no assignment: bash runs a program "A=b".
            ('time "A"=b python3 -c x', []),
            ("time A=b python3 -c x", ["PPA002"]),
            ("time A+=b python3 -c x", ["PPA002"]),
            ("time A[1]=b python3 -c x", ["PPA002"]),
            ("time -p PYTHONPATH=/opt: python3 /opt/s.py", ["PPA004"]),
            ("time PYTHONPATH=/opt: python3 /opt/s.py", ["PPA004"]),
            (
                "time A+=b uv run --no-config --no-project python s.py",
                ["PPA009"],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_literal_text_is_not_an_expression_in_shell(self) -> None:
        """Text spelled like an old expression marker stays text."""
        env = '"$GITHUB_ENV"'
        for line, expected in (
            ("export PYTHONPATH=GHEXPR_TEMP/lib", ["PPA005"]),
            (f"echo PYTHONPATH=GHEXPR_TEMP/lib >> {env}", ["PPA005"]),
            ("export PYTHONPATH=${{ runner.temp }}/lib", []),
            (f"echo PYTHONPATH=${{{{ runner.temp }}}}/lib >> {env}", []),
            ("GHEXPR_PYTHON -c 'import csv'", []),
            ("${{ inputs.python }} -c 'import csv'", ["PPA002"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)

    def test_multiline_expression_in_yaml(self) -> None:
        """An expression body that spans lines is still an expression."""
        workflow = (
            "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
            "          PYTHONPATH: |-\n"
            "            /opt/lib:${{ inputs.extra ||\n"
            "            '' }}\n"
            "        run: echo hi\n"
        )
        self.assertEqual(rules(workflow, "workflow"), ["PPA009"])
        step = (
            "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
            "          echo ${{ inputs.a ||\n"
            "            'b' }}\n"
            "          python3 -c 'import csv'\n"
        )
        found = audit.scan_text(step, "workflow", "repo", "ci.yaml")
        self.assertEqual([(f.rule, f.line) for f in found], [("PPA002", 8)])

    def test_action_named_workflow(self) -> None:
        """A YAML file directly in .github/workflows is a workflow."""
        for path, kind in (
            (".github/workflows/action.yml", "workflow"),
            (".github/workflows/action.yaml", "workflow"),
            (".github\\workflows\\action.yml", "workflow"),
            (".github/workflows/sub/action.yml", "action"),
            ("sub/action.yml", "action"),
        ):
            with self.subTest(path=path):
                self.assertEqual(audit.classify_kind(path), kind)
        text = "on: push\nenv:\n  PYTHONPATH: src\njobs:\n  a:\n    steps:\n"
        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, ".github", "workflows")
            os.makedirs(folder)
            with open(
                os.path.join(folder, "action.yml"), "w", encoding="utf-8"
            ) as handle:
                handle.write(text + "      - run: python3 -c x\n")
            found = audit.scan([root])
            self.assertEqual(
                [(f.kind, f.rule) for f in found], [("workflow", "PPA002")]
            )

    def test_env_split_string_shebang(self) -> None:
        """A shell named after env's options and NAME= words is found."""
        for shebang, found in (
            ("#!/usr/bin/env -S bash -eu", True),
            ("#!/usr/bin/env -Sbash", True),
            ("#!/usr/bin/env -S LC_ALL=C bash", True),
            ("#!/usr/bin/env -i sh", True),
            ("#!/usr/bin/env bash", True),
            ("#!/usr/bin/env -S python3 -u", False),
            ("#!/usr/bin/env shellcheck", False),
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                rules_found = [f.rule for f in audit.scan([root])]
                self.assertEqual(rules_found, ["PPA002"] if found else [])

    def test_setup_uv_owner_in_any_case(self) -> None:
        """GitHub resolves the action's owner and name in any case."""
        for uses, expected in (
            ("Astral-Sh/setup-uv@abc", ["PPA008"]),
            ("ASTRAL-SH/SETUP-UV@abc", ["PPA008"]),
            ("astral-sh/setup-uv@abc", ["PPA008"]),
            ("astral-sh/setup-uv-other@abc", []),
        ):
            with self.subTest(uses=uses):
                workflow = (
                    f"on: push\njobs:\n  a:\n    steps:\n      - uses: {uses}\n"
                )
                self.assertEqual(rules(workflow, "workflow"), expected)


class ReviewRoundTenTest(unittest.TestCase):
    """The tenth review round: shebangs, lines, expressions, sudo."""

    def test_long_split_string_shebang(self) -> None:
        """env's --split-string= and its abbreviations name the shell."""
        for shebang, found in (
            ("#!/usr/bin/env --split-string=bash -eu", True),
            ("#!/usr/bin/env --split=bash -eu", True),
            ("#!/usr/bin/env --s=sh", True),
            ("#!/usr/bin/env -iSbash", True),
            ("#!/usr/bin/env --split-string bash", True),
            ("#!/usr/bin/env --split-string=python3 -u", False),
            ("#!/usr/bin/env --unset=bash", False),
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                rules_found = [f.rule for f in audit.scan([root])]
                self.assertEqual(rules_found, ["PPA002"] if found else [])

    def test_command_on_expression_closing_line(self) -> None:
        """Text after a multi-line expression is on its closing line."""
        head = "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
        step = (
            head + "          echo ${{ inputs.a ||\n"
            "            'b' }}; python3 -c 'import csv'\n"
        )
        found = audit.scan_text(step, "workflow", "repo", "ci.yaml")
        self.assertEqual([(f.rule, f.line) for f in found], [("PPA002", 7)])
        # Three lines: the middle one starts inside the expression too.
        step = (
            head + "          echo ${{ inputs.a ||\n"
            "            inputs.b ||\n"
            "            'c' }}; python3 -m pip\n"
            "          python3 -c 'import csv'\n"
        )
        found = audit.scan_text(step, "workflow", "repo", "ci.yaml")
        self.assertEqual(
            [(f.rule, f.line) for f in found],
            [("PPA001", 8), ("PPA002", 9)],
        )
        # An ignore mark above the closing line covers its command,
        # and one above the opening line no longer does.
        marked = (
            head + "          # python-path-audit: ignore\n"
            "          echo ${{ inputs.a ||\n"
            "            'b' }}; python3 -c 'import csv'\n"
        )
        self.assertEqual(rules(marked, "workflow"), ["PPA002"])
        marked = (
            head
            + "          echo ${{ inputs.a || # python-path-audit: ignore\n"
            "            'b' }}; python3 -c 'import csv'\n"
        )
        self.assertEqual(rules(marked, "workflow"), [])

    def test_pythonpath_expression_as_python_argument(self) -> None:
        """${{ env.PYTHONPATH }} among Python's options is unknown."""
        for run, expected in (
            ("python3 \"${{ env.PYTHONPATH }}\" -c 'import csv'", ["PPA009"]),
            ("python3 -I \"${{ env.PYTHONPATH }}\" -c 'import csv'", []),
            ('python3 /opt/s.py "${{ env.PYTHONPATH }}"', []),
            ('uv "${{ env.PYTHONPATH }}" run --no-project s.py', ["PPA009"]),
        ):
            with self.subTest(run=run):
                workflow = (
                    "on: push\njobs:\n  a:\n    steps:\n      - env:\n"
                    "          PYTHONPATH: -B\n"
                    f"        run: {run}\n"
                )
                self.assertEqual(rules(workflow, "workflow"), expected)

    def test_sudo_assignment_ending_in_wrapper_name(self) -> None:
        """A NAME=value word after sudo is an assignment, whatever its tail."""
        for line, expected in (
            ("sudo PYTHONPATH=src/env python3 /opt/script.py", ["PPA005"]),
            ("sudo PYTHONPATH=src/nice python3 /opt/script.py", ["PPA005"]),
            ("sudo PYTHONPATH=src/sudo python3 /opt/script.py", ["PPA005"]),
            ("sudo PYTHONPATH=/opt/env python3 /opt/script.py", []),
            ("sudo -E env PYTHONPATH=src python3 /opt/script.py", ["PPA005"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)


if __name__ == "__main__":
    unittest.main()


class ReviewRoundElevenTest(unittest.TestCase):
    """The eleventh review round: shebang paths, markers, ``~+``."""

    def test_shebang_shell_by_path_after_env_options(self) -> None:
        """env may name the shell by path after its options."""
        for shebang, found in (
            ("#!/usr/bin/env -S /bin/bash -eu", True),
            ("#!/usr/bin/env --split-string=/bin/bash -eu", True),
            ("#!/usr/bin/env -S /usr/local/bin/zsh", True),
            ("#!/usr/bin/env -S /usr/bin/python3", False),
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                rules_found = [f.rule for f in audit.scan([root])]
                self.assertEqual(rules_found, ["PPA002"] if found else [])

    def test_marker_characters_in_authored_text(self) -> None:
        """Private-use characters in a file cannot pose as a marker."""
        head = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n"
        step = head + "        echo \ue000temp:0\ue001\n        python3 -m x\n"
        found = audit.scan_text(step, "action", "repo", "action.yaml")
        self.assertEqual([(f.rule, f.line) for f in found], [("PPA001", 7)])
        # Nor can they name an interpreter, in a script or a step.
        self.assertEqual(rules("\ue002PYTHON\ue003 -m x\n"), [])
        self.assertEqual(
            rules(head + "        \ue002PYTHON\ue003 -m x\n", "action"), []
        )
        # A real expression still reads as one.
        self.assertEqual(
            rules(
                head + "        ${{ steps.py.outputs.python-path }} -m x\n",
                "action",
            ),
            ["PPA001"],
        )

    def test_tilde_plus_is_the_working_directory(self) -> None:
        """``~+`` expands to $PWD; an action's PYTHONPATH there is PPA005."""
        for value, expected in (
            ("~+", ["PPA005"]),
            ("~+/lib", ["PPA005"]),
            ("~-", ["PPA005"]),
            ("~", []),
            ("~/lib", []),
            ("/opt/x:~+", ["PPA005"]),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    rules(
                        action_step(f"PYTHONPATH={value} python3 /opt/s.py"),
                        "action",
                    ),
                    expected,
                )

    def test_option_word_ending_in_py_is_not_the_script(self) -> None:
        """A word written as an option is not the script, whatever its tail."""
        self.assertEqual(
            rules("python3 -X\"pycache_prefix=${cache}.py\" -c 'import csv'"),
            ["PPA009"],
        )
        self.assertEqual(rules('python3 "$dir/x.py" -c "import csv"'), [])

    def test_expression_naming_uv_is_an_unread_program(self) -> None:
        """setup-uv's uv-path output runs uv the scan cannot read."""
        for line, expected in (
            ("${{ steps.setup.outputs.uv-path }} pip list", ["PPA009"]),
            (
                "${{ steps.setup.outputs.uv-path }} python install 3.13",
                ["PPA009"],
            ),
            ("${{ steps.x.outputs.other }} pip list", []),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)

    def test_numbered_tildes_name_the_directory_stack(self) -> None:
        for value, expected in (
            ("~0", ["PPA005"]),
            ("~+0/lib", ["PPA005"]),
            ("~-1", ["PPA005"]),
            ("~bob", ["PPA009"]),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    rules(
                        action_step(f"PYTHONPATH={value} python3 /opt/s.py"),
                        "action",
                    ),
                    expected,
                )

    def test_unread_uv_option_words(self) -> None:
        """An option word uv gets that the scan cannot read is PPA009."""
        safe = "UV_PYTHON=/usr/bin/python3 "
        for line, expected in (
            (safe + "uv pip list $'-p.venv/bin/python'", ["PPA009"]),
            (
                safe
                + "uv run --no-config --no-project --${{ inputs.option }} python3 -I s.py",
                ["PPA009"],
            ),
            # Operands, read or not, are not options.
            (safe + 'uv pip list --python /usr/bin/python3 "$pkg"', []),
            ("uv pip install --system ${{ inputs.pkg }}", []),
            (
                "uv run --no-config --no-project --python /usr/bin/python3 "
                '--with "$dep" python -I s.py',
                [],
            ),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)

    def test_quoted_option_word_ending_in_py(self) -> None:
        """Quoting or ``$'`` before an option prefix does not hide it."""
        for word in (
            '"-Xpycache_prefix=${cache}.py"',
            "$'-Xpycache_prefix=${cache}.py'",
        ):
            with self.subTest(word=word):
                self.assertEqual(
                    rules(f"python3 {word} -c 'import csv'"), ["PPA009"]
                )

    def test_suffix_climbing_above_an_unknown_base(self) -> None:
        """``$RUNNER_TEMP/../x`` may be the checkout; the scan cannot place it."""
        for value, expected in (
            ('"$RUNNER_TEMP/../repo/repo"', ["PPA009"]),
            ('"${{ runner.temp }}/../repo"', ["PPA009"]),
            ('"$RUNNER_TEMP/lib"', []),
            ('"$RUNNER_TEMP/a..b"', []),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    rules(
                        action_step(f"PYTHONPATH={value} python3 /opt/s.py"),
                        "action",
                    ),
                    expected,
                )
        # In a workflow too: the location is as unknown there.
        self.assertEqual(
            rules('PYTHONPATH="$HOME/../x" python3 /opt/s.py'), ["PPA009"]
        )

    def test_runner_run_with_option_terminator(self) -> None:
        self.assertEqual(rules("pipenv run -- python3 -m package"), ["PPA001"])
        self.assertEqual(
            rules("poetry run -- python3 -c 'import csv'"), ["PPA002"]
        )
        self.assertEqual(rules("pipenv run -- ruff check"), [])

    def test_quoted_shell_in_split_string_shebang(self) -> None:
        for shebang, found in (
            ('#!/usr/bin/env -S "bash" -eu', True),
            ("#!/usr/bin/env --split-string='bash' -eu", True),
            ('#!/usr/bin/env -S "/bin/bash" -eu', True),
            ('#!/usr/bin/env -S "python3"', False),
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                rules_found = [f.rule for f in audit.scan([root])]
                self.assertEqual(rules_found, ["PPA002"] if found else [])

    @unittest.skipIf(
        not hasattr(os, "geteuid") or os.geteuid() == 0,
        "needs POSIX permissions, as a user other than root",
    )
    def test_unreadable_helper_makes_the_scan_incomplete(self) -> None:
        """A shebang probe the scan cannot read is a problem, not a miss."""
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "helper")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/bash\npython3 -c 'import csv'\n")
            os.chmod(path, 0)
            try:
                problems: list[str] = []
                audit.scan([root], problems)
            finally:
                os.chmod(path, 0o644)
            self.assertEqual(len(problems), 1)
            self.assertIn("helper", problems[0])

    def test_help_and_version_in_option_clusters(self) -> None:
        """``-BV`` and ``-Bh`` print and exit before any code runs."""
        for line, expected in (
            ("python3 -BV -c 'import csv'", []),
            ("python3 -Bh -c 'import csv'", []),
            ("python3 -B? -c 'import csv'", []),
            ("python3 -B -c 'import csv'", ["PPA002"]),
            ("python3 -Wignore -c 'import csv'", ["PPA002"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(line), expected)

    def test_expression_inside_the_program_word(self) -> None:
        """``python${{ inputs.major }}`` may run Python; a tool name may not."""
        self.assertEqual(
            rules(action_step("python${{ inputs.major }} -m pip"), "action"),
            ["PPA009"],
        )
        self.assertEqual(
            rules(action_step("tool${{ inputs.v }} --help"), "action"), []
        )

    def test_decoded_words_take_no_script_shortcut(self) -> None:
        """An ANSI-C or backslash word ending in .py is not read as the script."""
        self.assertEqual(
            rules("python3 -S $'\\x2dcimport csv# .py'"), ["PPA009"]
        )
        self.assertEqual(
            rules("python3 /opt/x\\ y.py -c 'import csv'"), ["PPA009"]
        )
        self.assertEqual(rules('python3 "$T/script.py"'), [])

    def test_shebang_env_options_with_operands(self) -> None:
        for shebang, found in (
            ("#!/usr/bin/env -S -u PYTHONPATH sh", True),
            ("#!/usr/bin/env -S --unset PYTHONPATH -C /tmp bash -eu", True),
            ("#!/usr/bin/env -u PATH python3", False),
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                rules_found = [f.rule for f in audit.scan([root])]
                self.assertEqual(rules_found, ["PPA002"] if found else [])

    def test_explicit_yaml_kind_from_the_parsed_document(self) -> None:
        """A quoted or flow-style ``jobs`` key still marks a workflow."""
        for text, kind in (
            ('"jobs":\n  a:\n    steps: []\n', "workflow"),
            ("{jobs: {a: {steps: []}}}\n", "workflow"),
            ("runs:\n  steps: []\n", "action"),
            ("jobs: [\n", "action"),
        ):
            with (
                self.subTest(text=text),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "saved.yml")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
                self.assertEqual(audit.explicit_kind(path), kind)

    def test_expression_option_with_inline_value(self) -> None:
        safe = "UV_PYTHON=/usr/bin/python3 "
        self.assertEqual(
            rules(
                action_step(
                    safe + "uv run --no-config --no-project "
                    "--${{ inputs.option }}=.venv/bin/python python3 -I s.py"
                ),
                "action",
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(
                "uv run --no-config --no-project --python=/usr/bin/python3 python3 -I s.py"
            ),
            [],
        )

    def test_shebang_env_operands_quoted(self) -> None:
        for shebang in (
            "#!/usr/bin/env -S -C '/tmp/dir with space' bash",
            '#!/usr/bin/env -S -u "PYTHON PATH" sh -eu',
        ):
            with (
                self.subTest(shebang=shebang),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "helper")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f"{shebang}\npython3 -c 'import csv'\n")
                self.assertEqual(
                    [f.rule for f in audit.scan([root])], ["PPA002"]
                )

    def test_deep_explicit_yaml_is_reported_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "deep.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("a: " + "[" * 5000 + "]" * 5000 + "\n")
            problems: list[str] = []
            self.assertEqual(audit.explicit_kind(path), "action")
            audit.scan([path], problems)
            self.assertEqual(len(problems), 1)

    def test_escape_that_may_hold_a_newline_before_pythonpath(self) -> None:
        self.assertEqual(
            rules(
                "printf 'OTHER=1\\x0aPYTHONPATH=/opt/x:\\n' >> \"$GITHUB_ENV\""
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules("printf 'OTHER=1\\x0aFOO=2\\n' >> \"$GITHUB_ENV\""), []
        )

    def test_printf_conversion_keeps_its_operand_text(self) -> None:
        env = '>> "$GITHUB_ENV"'
        self.assertEqual(
            rules(f"printf 'OTHER=%b\\n' '1\\nPYTHONPATH=/opt/x:' {env}"),
            ["PPA009"],
        )
        self.assertEqual(rules(f"printf 'OTHER=%b\\n' '1' {env}"), [])

    def test_record_header_with_unread_delimiter(self) -> None:
        env = '>> "$GITHUB_ENV"'
        self.assertEqual(
            rules(
                f'printf \'PYTHONPATH<<%s\\n/opt/lib:\\n%s\\n\' "$RUNNER_TEMP" "$RUNNER_TEMP" {env}'
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(f'printf \'OTHER<<%s\\nx\\n%s\\n\' "$D" "$D" {env}'), []
        )

    def test_climb_split_across_quoted_fragments(self) -> None:
        self.assertEqual(
            rules(
                action_step(
                    'PYTHONPATH="${RUNNER_TEMP}/."\'.\'"/repo/repo" python3 /opt/c.py'
                ),
                "action",
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(
                action_step(
                    'PYTHONPATH="${RUNNER_TEMP}/a"\'.\'"b" python3 /opt/c.py'
                ),
                "action",
            ),
            [],
        )

    def test_shebang_probe_is_linear_and_reads_long_lines(self) -> None:
        """A crafted shebang costs its length; a long one still names its shell."""
        import time

        for line, found in (
            ("#!/usr/bin/env " + "-u " * 36 + "x\n", False),
            ("#!/usr/bin/env -S NOTE=" + "x" * 120 + " /bin/sh\n", True),
            ("#!/usr/bin/env -S " + "A=1 " * 60 + "bash -eu\n", True),
            ("#!/usr/bin/env -S -u PYTHONPATH sh\n", True),
            ("#!/usr/bin/env -S 'bash\n", False),
        ):
            with self.subTest(line=line[:50]):
                started = time.monotonic()
                self.assertEqual(audit.shebang_names_shell(line), found)
                self.assertLess(time.monotonic() - started, 0.1)
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "helper")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "#!/usr/bin/env -S NOTE=" + "x" * 120 + " /bin/sh\n"
                )
                handle.write("python3 -c 'import csv'\n")
            self.assertEqual([f.rule for f in audit.scan([root])], ["PPA002"])

    def test_explicit_kind_composes_without_constructing(self) -> None:
        """A bad scalar or a wide alias in an explicit file does not abort."""
        for text, kind in (
            ("jobs:\n  a: 2026-13-01\n", "workflow"),
            (
                "x: &a [1, 2]\ny: &b [*a, *a]\nz: &c [*b, *b]\njobs: *c\n",
                "workflow",
            ),
            ("runs:\n  when: 2026-13-01\n", "action"),
        ):
            with (
                self.subTest(text=text),
                tempfile.TemporaryDirectory() as root,
            ):
                path = os.path.join(root, "saved.yml")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
                self.assertEqual(audit.explicit_kind(path), kind)

    def test_tilde_prefix_cut_by_a_quoted_fragment(self) -> None:
        """``~'root'/lib`` is not a home directory in bash."""
        for value, expected in (
            ("~'root'/lib", ["PPA005"]),
            ("~root/lib", ["PPA009"]),
            ("~/lib", []),
            ("~+'x'", ["PPA005"]),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    rules(
                        action_step(f"PYTHONPATH={value} python3 /opt/s.py"),
                        "action",
                    ),
                    expected,
                )

    def test_quoted_slash_stops_tilde_expansion(self) -> None:
        self.assertEqual(
            rules(
                action_step('PYTHONPATH=~"/lib" python3 /opt/s.py'), "action"
            ),
            ["PPA005"],
        )
        self.assertEqual(
            rules(action_step("PYTHONPATH=~/lib python3 /opt/s.py"), "action"),
            [],
        )

    def test_shebang_env_split_string_clusters_and_abbreviations(self) -> None:
        for line, found in (
            ("#!/usr/bin/env --split-string=LC_ALL=C bash", True),
            ("#!/usr/bin/env -S -iC /tmp /bin/sh", True),
            ("#!/usr/bin/env -S --chd /tmp /bin/sh", True),
            # Single quotes make one word: a program of that name.
            ("#!/usr/bin/env -S 'A=1 bash -eu'", False),
            ("#!/usr/bin/env --split-string 'bash -eu'", False),
            ("#!/usr/bin/env -S A=1 bash -eu", True),
            ("#!/usr/bin/env -S -C /tmp python3", False),
            ("#!/usr/bin/env -S", False),
            ("#!/usr/bin/env " + "-S " * 200 + "x", False),
        ):
            with self.subTest(line=line[:50]):
                self.assertEqual(audit.shebang_names_shell(line), found)

    def test_lone_dash_is_env_ignore_environment(self) -> None:
        self.assertTrue(audit.shebang_names_shell("#!/usr/bin/env -S - bash"))
        self.assertFalse(audit.shebang_names_shell("#!/usr/bin/env - python3"))

    def test_python_expression_names_in_any_case(self) -> None:
        self.assertEqual(
            rules(
                action_step('printf "import csv\\n" | "${{ inputs.PYTHON }}"'),
                "action",
            ),
            ["PPA003"],
        )
        self.assertEqual(
            rules(action_step('"${{ inputs.Python_Path }}" -m x'), "action"),
            ["PPA001"],
        )

    def test_named_user_tilde_is_unresolved(self) -> None:
        """``~user`` is that home, or literal text when no such user exists."""
        self.assertEqual(
            rules(
                action_step("PYTHONPATH=~missing/lib python3 /opt/s.py"),
                "action",
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules("PYTHONPATH=~missing/lib python3 /opt/s.py"), ["PPA009"]
        )
        self.assertEqual(
            rules(action_step("PYTHONPATH=~/lib python3 /opt/s.py"), "action"),
            [],
        )

    def test_free_threaded_interpreter_names(self) -> None:
        self.assertEqual(rules("python3.13t -c 'import csv'"), ["PPA002"])
        self.assertEqual(rules("/usr/bin/python3.14t -m x"), ["PPA001"])
        step = (
            "on: push\njobs:\n  a:\n    steps:\n      - shell: python3.13t {0}\n"
            "        run: |\n          import os\n"
        )
        self.assertEqual(rules(step, "workflow"), [])

    def test_env_split_string_quoting(self) -> None:
        """env splits -S text with quotes, backslashes and ``\\_`` itself."""
        for line, found in (
            ("#!/usr/bin/env -S NOTE='hello world' sh", True),
            ("#!/usr/bin/env -S bash\\_-e", True),
            ("#!/usr/bin/env --split-string=A='x y' bash", True),
            ('#!/usr/bin/env -S "NOTE=a\\_b" sh', True),
            ("#!/usr/bin/env -S bash # a comment", True),
            ("#!/usr/bin/env -S 'bash", False),
        ):
            with self.subTest(line=line):
                self.assertEqual(audit.shebang_names_shell(line), found)
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "helper")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env -S NOTE='hello world' sh\n")
                handle.write("python3 -c 'import csv'\n")
            self.assertEqual([f.rule for f in audit.scan([root])], ["PPA002"])

    def test_heredoc_backslash_newline_joins_lines(self) -> None:
        env = '>> "$GITHUB_ENV"'
        self.assertEqual(
            rules(f"cat {env} <<EOF\nPYTHONPATH=/opt/lib\\\n:\nEOF"), ["PPA004"]
        )
        # Quoted: literal; escaped backslash: no join.
        self.assertEqual(
            rules(f"cat {env} <<'EOF'\nPYTHONPATH=/opt/lib\\\n:\nEOF"), []
        )
        self.assertEqual(
            rules(f"cat {env} <<EOF\nPYTHONPATH=/opt/lib\\\\\n:\nEOF"), []
        )

    def test_later_stdin_redirect_replaces_a_heredoc(self) -> None:
        env = '>> "$GITHUB_ENV"'
        self.assertEqual(
            rules(f"cat <<< 'PYTHONPATH=/opt/x:' < /dev/null {env}"), []
        )
        self.assertEqual(
            rules(f"cat <<EOF < /dev/null {env}\nPYTHONPATH=/opt/x:\nEOF"), []
        )
        # A here-string after a file redirect is a tree-sitter grammar
        # gap: the block is reported as not fully scanned, never clean.
        self.assertEqual(
            rules(f"cat < /dev/null <<< 'PYTHONPATH=/opt/x:' {env}"), ["PPA010"]
        )
        self.assertEqual(
            rules(f"cat <<EOF {env}\nPYTHONPATH=/opt/x:\nEOF"), ["PPA004"]
        )

    def test_backslash_c_ends_the_split_string(self) -> None:
        self.assertTrue(
            audit.shebang_names_shell("#!/usr/bin/env -S sh\\c ignored")
        )
        self.assertFalse(
            audit.shebang_names_shell("#!/usr/bin/env -S 'sh\\c' x")
        )

    def test_module_flag_in_a_uv_run_cluster(self) -> None:
        safe = "uv run --no-config --no-project --python=/usr/bin/python3 "
        self.assertEqual(rules(safe + "-qm csv"), ["PPA001"])
        self.assertEqual(rules(safe + "-q -m csv"), ["PPA001"])
        self.assertEqual(rules(safe + "python -I s.py"), [])

    def test_expression_string_may_hold_closing_braces(self) -> None:
        head = "on: push\njobs:\n  a:\n    steps:\n      - run: |\n          "
        self.assertEqual(
            rules(
                head
                + "echo ${{ contains('}} #', 'x') }}; python3 -c 'import csv'",
                "workflow",
            ),
            ["PPA002"],
        )
        self.assertEqual(
            rules(head + "echo ${{ a }} ${{ b }}; python3 -m x", "workflow"),
            ["PPA001"],
        )

    def test_pythonpath_only_from_environment_scopes(self) -> None:
        """Matrix data and inputs named env are not an environment."""
        matrix = (
            "on: push\njobs:\n  build:\n    strategy:\n      matrix:\n        include:\n"
            "          - env: {PYTHONPATH: '/opt/lib:'}\n    steps:\n      - run: echo ok\n"
        )
        self.assertEqual(rules(matrix, "workflow"), [])
        with_input = (
            "on: push\njobs:\n  a:\n    steps:\n      - uses: x/y@"
            + "0" * 40
            + "\n"
            "        with:\n          env: {PYTHONPATH: '/x:'}\n"
        )
        self.assertEqual(rules(with_input, "workflow"), [])
        for text in (
            "on: push\nenv: {PYTHONPATH: '/opt/lib:'}\njobs:\n  a:\n    steps:\n      - run: echo\n",
            "on: push\njobs:\n  a:\n    env: {PYTHONPATH: '/opt/lib:'}\n    steps:\n      - run: echo\n",
            "on: push\njobs:\n  a:\n    steps:\n      - env: {PYTHONPATH: '/opt/lib:'}\n        run: echo\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text, "workflow"), ["PPA004"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_fifos_are_not_scanned(self) -> None:
        """A FIFO would block the probe or the read; only regular files count."""
        with tempfile.TemporaryDirectory() as root:
            os.mkfifo(os.path.join(root, "pipe"))
            os.mkfifo(os.path.join(root, "pipe.sh"))
            with open(
                os.path.join(root, "ok.sh"), "w", encoding="utf-8"
            ) as handle:
                handle.write("python3 -c 'import csv'\n")
            self.assertEqual([f.rule for f in audit.scan([root])], ["PPA002"])

    def test_expression_scan_is_linear(self) -> None:
        import time

        from gha_workflow_linter.python_path import _yaml

        started = time.monotonic()
        marked = _yaml.mark_expressions("${{ " + "'" * 5000 + " x", [])
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(marked.startswith("${{ "))
        self.assertEqual(
            [
                body
                for _s, _e, body in _yaml.find_expressions(
                    "a ${{ contains('}} #', 'x') }} ${{ b }}"
                )
            ],
            ["contains('}} #', 'x')", "b"],
        )

    def test_expansion_in_a_tilde_prefix_stops_expansion(self) -> None:
        self.assertEqual(
            rules(
                action_step('PYTHONPATH=~"$RUNNER_TEMP"/lib python3 /opt/s.py'),
                "action",
            ),
            ["PPA005"],
        )
        self.assertEqual(
            rules(action_step("PYTHONPATH=~/lib python3 /opt/s.py"), "action"),
            [],
        )

    def test_line_mapping_is_linear_and_keeps_multibyte_text(self) -> None:
        import time

        head = "on: push\njobs:\n  a:\n    steps:\n      - run: |\n"
        body = (
            "          echo 'héllo wörld ✓'\n"
            "          echo ${{ inputs.a ||\n"
            "            'b' }}; python3 -c 'import csv'\n"
            "          echo 'ünïcode'\n"
            "          python3 -m x\n"
        )
        found = audit.scan_text(head + body, "workflow", "repo", "ci.yaml")
        self.assertEqual(
            [(f.rule, f.line) for f in found], [("PPA002", 8), ("PPA001", 10)]
        )
        for text, kind in (
            (
                head
                + "".join(f"          python3 -m m{i}\n" for i in range(3000)),
                "workflow",
            ),
            ("".join(f"python3 -m m{i}\n" for i in range(6000)), "script"),
        ):
            with self.subTest(kind=kind):
                started = time.monotonic()
                count = len(audit.scan_text(text, kind, "repo", "f"))
                self.assertLess(time.monotonic() - started, 2.0)
                self.assertEqual(count, 3000 if kind == "workflow" else 6000)

    def test_single_quote_escapes_in_env_split_string(self) -> None:
        self.assertTrue(
            audit.shebang_names_shell("#!/usr/bin/env -S -u 'DON\\'T' sh")
        )
        self.assertTrue(
            audit.shebang_names_shell("#!/usr/bin/env -S -u 'A\\\\B' sh")
        )

    def test_line_starting_at_an_expression_keeps_its_number(self) -> None:
        """An ignore mark two lines above a command does not reach it."""
        head = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n"
        text = (
            head + "        # python-path-audit: ignore\n        echo ready\n"
            "        ${{ steps.py.outputs.python-path }} -m pip\n"
        )
        found = audit.scan_text(text, "action", "repo", "action.yaml")
        self.assertEqual([(f.rule, f.line) for f in found], [("PPA001", 8)])
        marked = (
            head + "        echo a\n"
            "        ${{ steps.py.outputs.python-path }} -m pip # python-path-audit: ignore\n"
        )
        self.assertEqual(rules(marked, "action"), [])

    def test_input_process_substitution_inherits_no_sink(self) -> None:
        env = '>> "$GITHUB_ENV"'
        self.assertEqual(
            rules("{ true <(printf 'PYTHONPATH=/opt/x:\\n'); } " + env), []
        )
        self.assertEqual(
            rules("{ echo 'PYTHONPATH=/opt/x:'; } " + env), ["PPA004"]
        )

    def test_shell_prefix_assignment_after_time_expands_tilde(self) -> None:
        """bash expands ~ in its own assignments, not in env's words."""
        for line, expected in (
            ("time PYTHONPATH=~/lib python3 /opt/s.py", []),
            ("PYTHONPATH=~/lib python3 /opt/s.py", []),
            ("env PYTHONPATH=~/lib python3 /opt/s.py", ["PPA005"]),
            ("time PYTHONPATH=lib python3 /opt/s.py", ["PPA005"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(rules(action_step(line), "action"), expected)

    def test_empty_prefix_assignment_is_a_known_empty_value(self) -> None:
        self.assertEqual(
            rules("VIRTUAL_ENV=/opt/safe UV_PYTHON= uv pip list"), []
        )
        self.assertEqual(
            rules("VIRTUAL_ENV=/opt/safe UV_PYTHON='' uv pip list"), []
        )
        self.assertEqual(
            rules(
                "VIRTUAL_ENV=/opt/safe UV_PYTHON=.venv/bin/python uv pip list"
            ),
            ["PPA007"],
        )

    def test_action_path_is_empty_in_a_workflow(self) -> None:
        """A workflow has no action path: the expression expands to nothing."""
        env = (
            "on: push\nenv:\n  PYTHONPATH: '${{ github.action_path }}:/opt/lib'\n"
            "jobs:\n  a:\n    steps:\n      - run: echo\n"
        )
        self.assertEqual(rules(env, "workflow"), ["PPA004"])
        head = "on: push\njobs:\n  a:\n    steps:\n      - run: |\n          "
        self.assertEqual(
            rules(
                head + "python3 ${{ github.action_path }} -c 'import csv'",
                "workflow",
            ),
            ["PPA009"],
        )
        # In an action it is the action's own directory.
        self.assertEqual(
            rules(
                action_step("python3 ${{ github.action_path }}/s.py"), "action"
            ),
            [],
        )

    def test_xargs_process_slot_var_unsets_a_setting(self) -> None:
        """xargs gives the named variable a number; the setting is gone."""
        head = (
            "runs:\n  steps:\n    - env: {UV_NO_CONFIG: '1'}\n      shell: bash\n"
            "      run: "
        )
        for options in (
            "--process-slot-var=UV_NO_CONFIG",
            "-n 1 --process-slot-var=UV_NO_CONFIG",
            "--process-slot-var UV_NO_CONFIG",
            "--process-slot UV_NO_CONFIG",
        ):
            with self.subTest(options=options):
                step = head + f"xargs {options} uv python find --system\n"
                self.assertEqual(rules(step, "action"), ["PPA006"])
        self.assertEqual(
            rules(head + "xargs -n 1 uv python find --system\n", "action"), []
        )
        self.assertEqual(
            rules(
                head
                + "xargs -I X --process-slot-var=OTHER uv python find --system\n",
                "action",
            ),
            [],
        )
        # PYTHONPATH itself: a number is a relative entry the scan cannot see.
        self.assertEqual(
            rules(
                action_step(
                    "xargs --process-slot-var=PYTHONPATH python3 /opt/h.py"
                ),
                "action",
            ),
            ["PPA009"],
        )
        self.assertEqual(
            rules(action_step("xargs python3 /opt/h.py"), "action"), []
        )

    def test_steps_in_matrix_data_are_not_steps(self) -> None:
        matrix = (
            "on: push\njobs:\n  build:\n    strategy:\n      matrix:\n"
            "        steps: [{run: 'python3 -m unused', env: {PYTHONPATH: '/opt/lib:'}}]\n"
            "    steps:\n      - run: echo ok\n"
        )
        self.assertEqual(rules(matrix, "workflow"), [])
        nested = (
            "on: push\njobs:\n  a:\n    with:\n      steps:\n"
            "        - uses: astral-sh/setup-uv@"
            + "0" * 40
            + "\n    steps: []\n"
        )
        self.assertEqual(rules(nested, "workflow"), [])
        for text, kind in (
            (
                "on: push\njobs:\n  a:\n    steps:\n      - run: python3 -m x\n",
                "workflow",
            ),
            (
                "runs:\n  steps:\n    - shell: bash\n      run: python3 -m x\n",
                "action",
            ),
            ("- run: python3 -m x\n", "workflow"),
        ):
            with self.subTest(kind=kind):
                self.assertEqual(rules(text, kind), ["PPA001"])

    def test_uv_run_reads_stdin_as_python(self) -> None:
        safe = "uv run --no-config --no-project --python /usr/bin/python3 "
        self.assertEqual(rules(safe + "-"), ["PPA003"])
        self.assertEqual(rules(safe + "-- -"), ["PPA003"])
        self.assertEqual(rules(safe + "python -I -"), [])

    def test_python_named_expressions_are_interpreters(self) -> None:
        """``${{ env.PY }}``, ``${{ inputs.python3 }}``: names that say Python."""
        for expression in (
            "env.PY",
            "inputs.python3",
            "steps.x.outputs.my_py",
            "env.PYTHON",
        ):
            with self.subTest(expression=expression):
                self.assertEqual(
                    rules(
                        action_step(
                            "printf 'import csv\\n' | \"${{ "
                            + expression
                            + ' }}"'
                        ),
                        "action",
                    ),
                    ["PPA003"],
                )
                self.assertEqual(
                    rules(
                        action_step('"${{ ' + expression + ' }}" -I -m x'),
                        "action",
                    ),
                    [],
                )
        self.assertEqual(
            rules(
                action_step("printf 'import csv\\n' | \"${{ inputs.tool }}\""),
                "action",
            ),
            [],
        )
