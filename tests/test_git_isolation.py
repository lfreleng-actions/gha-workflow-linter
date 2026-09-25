# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The suite's isolation from a git process that runs it.

``isolate_from_enclosing_git`` in ``conftest`` clears the variables git
exports to its hooks. A hand-written list of them missed eight, among
them ``GIT_CONFIG_PARAMETERS``, through which ``git -c key=value commit``
hands configuration to every hook it runs. These tests fail if the list
shrinks back, or if the fixture stops clearing it.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import TYPE_CHECKING

from tests import conftest
from tests.conftest import REAL_SUBPROCESS_RUN

if TYPE_CHECKING:
    import pytest

#: The checkout root, so a generated session can import this suite's
#: conftest rather than a copy of it.
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def _reported_by_git() -> list[str]:
    """Ask the installed git which variables it treats as local.

    Returns:
        The names ``git rev-parse --local-env-vars`` prints.
    """
    completed = REAL_SUBPROCESS_RUN(
        ["git", "rev-parse", "--local-env-vars"],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.split()


class TestTheVariableList:
    """What the fixture clears, independent of any test using it."""

    def test_covers_every_variable_the_installed_git_names(self) -> None:
        """A new git release must not reopen the gap."""
        missing = set(_reported_by_git()) - set(conftest._GIT_LOCAL_VARIABLES)

        assert not missing

    def test_falls_back_when_git_cannot_be_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A host without git still gets the full hard-coded list.

        Args:
            monkeypatch: Used to make ``git`` unavailable.
        """

        def no_git(*_args: object, **_kwargs: object) -> None:
            raise FileNotFoundError("git")

        monkeypatch.setattr(subprocess, "run", no_git)

        assert (
            conftest._git_local_variables()
            == conftest._FALLBACK_GIT_LOCAL_VARIABLES
        )

    def test_keeps_fallback_names_an_older_git_omits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A git listing fewer names must not shrink the set.

        Args:
            monkeypatch: Used to impersonate an older git.
        """

        def older_git(
            *_args: object, **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                ["git"], 0, stdout="GIT_DIR\nGIT_NEW_IN_SOME_RELEASE\n"
            )

        monkeypatch.setattr(subprocess, "run", older_git)

        names = conftest._git_local_variables()

        assert names[:2] == ("GIT_DIR", "GIT_NEW_IN_SOME_RELEASE")
        assert set(conftest._FALLBACK_GIT_LOCAL_VARIABLES) <= set(names)
        assert len(names) == len(set(names))


class TestTheFixtureClearsThem:
    """Run a session under a polluted environment, as a hook would be."""

    def test_no_git_variable_reaches_a_test(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every variable git names is gone by the time a test runs.

        Args:
            pytester: Runs a generated test file in a fresh session.
            monkeypatch: Sets the variables an enclosing git would.
        """
        names = _reported_by_git()
        for name in names:
            monkeypatch.setenv(name, "leaked-from-enclosing-git")
        pytester.makeconftest(
            f"import sys; sys.path.insert(0, {str(REPOSITORY_ROOT)!r})\n"
            "from tests.conftest import *  # noqa: F401,F403\n"
        )
        pytester.makepyfile(
            f"""
            import os

            def test_sees_none_of_them():
                leaked = [n for n in {names!r} if n in os.environ]
                assert not leaked, leaked
            """
        )

        result = pytester.runpytest("-p", "no:randomly", "--no-cov")

        result.assert_outcomes(passed=1)

    def test_hook_configuration_does_not_reach_git(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``git -c`` settings from the caller must not steer the suite.

        This is the effect rather than the mechanism: git reading a
        configured value that no file in the test's repository sets.

        Args:
            pytester: Runs a generated test file in a fresh session.
            monkeypatch: Sets the variable ``git -c`` would export.
        """
        monkeypatch.setenv(
            "GIT_CONFIG_PARAMETERS", "'user.name'='Leaked From Hook'"
        )
        pytester.makeconftest(
            f"import sys; sys.path.insert(0, {str(REPOSITORY_ROOT)!r})\n"
            "from tests.conftest import *  # noqa: F401,F403\n"
        )
        pytester.makepyfile(
            """
            import subprocess

            def test_reads_no_injected_name(tmp_path):
                subprocess.run(
                    ["git", "init", "-q", str(tmp_path)], check=True
                )
                shown = subprocess.run(
                    ["git", "-C", str(tmp_path), "config", "user.name"],
                    capture_output=True,
                    text=True,
                )
                assert "Leaked From Hook" not in shown.stdout
            """
        )

        result = pytester.runpytest("-p", "no:randomly", "--no-cov")

        result.assert_outcomes(passed=1)
