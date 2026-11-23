# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Discovery and parsing of Dependabot cooldown configuration.

GitHub Dependabot supports a ``cooldown`` stanza that delays opening
dependency-bump pull requests until a release has been available for a
minimum number of days. This guards against supply-chain attacks and
hastily-retracted releases.

This module locates the repository's ``.github/dependabot.yml`` (or
``.yaml``) file by walking up the directory hierarchy from a starting
path -- stopping at the enclosing repository root, since a cooldown is
that repository's own release policy -- then extracts the
``cooldown.default-days`` value, with the ``exclude`` and ``include``
lists beside it, so the linter can apply the same policy when updating
action calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import logging
import re
from typing import TYPE_CHECKING

import yaml

from .multi_repo import is_repository

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = logging.getLogger(__name__)

# Ecosystem name Dependabot uses for GitHub Actions updates. We prefer the
# cooldown configured for this ecosystem because that is what governs the
# action-call updates this linter performs.
_GITHUB_ACTIONS_ECOSYSTEM = "github-actions"

# Candidate file names, in the order Dependabot itself resolves them.
_DEPENDABOT_FILENAMES = ("dependabot.yml", "dependabot.yaml")

# Dependabot names a dependency by its path as well as its repository for
# a reusable workflow, or for any call pinned by commit SHA.
_WORKFLOW_PATH = re.compile(r"/\.github/workflows/.*\.ya?ml$")
_SHA_REFERENCE = re.compile(r"^[0-9a-f]{6,40}$")
# Dependabot's ``Version.path_based?``: a reference such as
# ``component/v1`` names the whole ``uses:`` value as the dependency.
_PATH_BASED_REFERENCE = re.compile(r".+/v?[0-9]")
# Stands in for the token past the end of a glob, which matches nothing.
_NO_TOKEN = re.compile("(?!)")


@dataclass(frozen=True)
class DependabotCooldown:
    """Result of resolving a Dependabot cooldown value.

    Attributes:
        days: The ``cooldown.default-days`` value that was parsed.
        source: Path to the ``dependabot.yml``/``.yaml`` file the value
            was read from.
        ecosystem: The ``package-ecosystem`` the cooldown was taken from.
        exclude: ``cooldown.exclude`` patterns; a matching dependency
            takes no cooldown.
        include: ``cooldown.include`` patterns; when present, only a
            matching dependency takes the cooldown.
    """

    days: int
    source: Path
    ecosystem: str
    exclude: tuple[str, ...] = ()
    include: tuple[str, ...] = ()


def dependency_name(organization: str, repository: str, reference: str) -> str:
    """Name a ``uses:`` call the way Dependabot's file parser does.

    Mirrors ``github_dependency`` in Dependabot's ``github_actions``
    file parser: the name is ``owner/repo``, extended by the path for a
    reusable workflow and for a call into a subdirectory pinned by
    commit SHA. Failing those, a path-based reference such as
    ``component/v1`` makes the whole ``owner/repo[/path]@ref`` value the
    name. An action in a subdirectory pinned by an ordinary tag keeps the
    bare repository name.

    Args:
        organization: Owner named by the call.
        repository: Repository named by the call, including any path.
        reference: The reference after ``@``.

    Returns:
        The dependency name cooldown patterns are matched against.
    """
    repo, _, path = repository.partition("/")
    name = f"{organization}/{repo}"
    if path and (
        _WORKFLOW_PATH.search(f"/{path}") or _SHA_REFERENCE.match(reference)
    ):
        return f"{name}/{path}"
    if _PATH_BASED_REFERENCE.match(reference):
        return f"{organization}/{repository}@{reference}"
    return name


def cooldown_applies(
    name: str, exclude: tuple[str, ...], include: tuple[str, ...]
) -> bool:
    """Report whether a dependency is subject to the cooldown.

    Mirrors Dependabot's ``ReleaseCooldownOptions#included?``: an
    ``exclude`` match exempts the dependency, and a non-empty
    ``include`` list exempts anything it does not match. ``exclude``
    wins over ``include``. Patterns follow :func:`fnmatch_ruby`.

    Args:
        name: Dependency name from :func:`dependency_name`.
        exclude: Patterns exempting a dependency.
        include: Patterns a dependency must match, when any are given.

    Returns:
        ``True`` when the cooldown applies to ``name``.
    """
    if any(fnmatch_ruby(name, pattern) for pattern in exclude):
        return False
    return not include or any(
        fnmatch_ruby(name, pattern) for pattern in include
    )


def fnmatch_ruby(name: str, pattern: str) -> bool:
    """Match ``name`` as Ruby's ``File.fnmatch?(pattern, name)`` does.

    Dependabot matches cooldown patterns with no flags: case-sensitive,
    ``*`` and ``?`` also match ``/``, a backslash escapes the next
    character, ``[!...]`` and ``[^...]`` both negate a bracket, and a
    leading ``.`` in ``name`` matches only a literal ``.``. Python's
    ``fnmatchcase`` differs on the last three, so it is not used.

    Args:
        name: The string to test.
        pattern: The glob pattern.

    Returns:
        ``True`` when ``pattern`` matches the whole of ``name``.
    """
    if name.startswith(".") and pattern.removeprefix("\\")[:1] != ".":
        return False
    return _match_tokens(_ruby_glob_tokens(pattern), name)


def _match_tokens(
    tokens: tuple[re.Pattern[str] | None, ...], name: str
) -> bool:
    """Match ``name`` against glob tokens without exponential backtracking.

    Each token is a one-character regex, or ``None`` for ``*``. On a
    mismatch only the most recent ``*`` grows by one character, which
    is enough for globs, so the run is bounded by
    ``len(name) * len(tokens)`` steps whatever the pattern.
    """
    t = n = 0
    star_t, star_n = -1, 0
    while n < len(name):
        token = tokens[t] if t < len(tokens) else _NO_TOKEN
        if token is None:
            star_t, star_n = t, n
            t += 1
        elif token.match(name, n):
            t += 1
            n += 1
        elif star_t >= 0:
            star_n += 1
            t, n = star_t + 1, star_n
        else:
            return False
    while t < len(tokens) and tokens[t] is None:
        t += 1
    return t == len(tokens)


@lru_cache(maxsize=256)
def _ruby_glob_tokens(pattern: str) -> tuple[re.Pattern[str] | None, ...]:
    """Split a flagless Ruby ``fnmatch`` pattern into matcher tokens."""
    tokens: list[re.Pattern[str] | None] = []
    i, end = 0, len(pattern)
    while i < end:
        char = pattern[i]
        i += 1
        if char == "*":
            if not tokens or tokens[-1] is not None:
                tokens.append(None)
            continue
        regex, i = _TOKEN_READERS.get(char, _literal)(pattern, i)
        if regex is not None:
            tokens.append(re.compile(regex, re.DOTALL))
    return tuple(tokens)


def _literal(pattern: str, start: int) -> tuple[str | None, int]:
    """Match the character before ``start`` literally."""
    return re.escape(pattern[start - 1]), start


def _any_char(_pattern: str, start: int) -> tuple[str | None, int]:
    """Match any one character, ``/`` included, for ``?``."""
    return ".", start


def _escaped(pattern: str, start: int) -> tuple[str | None, int]:
    """Match the character after a backslash literally.

    A trailing backslash escapes nothing and matches nothing.
    """
    if start >= len(pattern):
        return None, start
    return re.escape(pattern[start]), start + 1


def _ruby_bracket(pattern: str, start: int) -> tuple[str, int]:
    """Translate the bracket expression after the ``[`` at ``start``.

    Follows ``bracket()`` in Ruby's ``dir.c``: ``]`` straight after the
    ``[`` (or its negation) closes an empty set, ``-`` before ``]`` is
    literal, a reversed range matches only its two ends, and a bracket
    with no closing ``]`` can never match.

    Returns:
        The regex for the bracket and the index after its ``]``.
    """
    end = len(pattern)
    i = start
    negate = i < end and pattern[i] in "!^"
    if negate:
        i += 1
    items: list[str] = []

    def take(index: int) -> tuple[str | None, int]:
        if index < end and pattern[index] == "\\":
            index += 1
        if index >= end:
            return None, index
        return pattern[index], index + 1

    while i < end and pattern[i] != "]":
        low, i = take(i)
        if low is None or i >= end:
            return "(?!)", end
        if pattern[i] == "-" and i + 1 < end and pattern[i + 1] != "]":
            high, i = take(i + 1)
            if high is None:
                return "(?!)", end
            if low <= high:
                items.append(f"{re.escape(low)}-{re.escape(high)}")
            else:
                items.extend((re.escape(low), re.escape(high)))
        else:
            items.append(re.escape(low))
    if i >= end:
        return "(?!)", end
    if not items:
        return ("." if negate else "(?!)"), i + 1
    return f"[{'^' if negate else ''}{''.join(items)}]", i + 1


# Readers for the pattern characters that are not literals, ``*`` aside.
_TOKEN_READERS: dict[str, Callable[[str, int], tuple[str | None, int]]] = {
    "?": _any_char,
    "[": _ruby_bracket,
    "\\": _escaped,
}


def find_dependabot_config(start_path: Path) -> Path | None:
    """Locate the nearest ``.github/dependabot.{yml,yaml}`` file.

    Walks up the directory hierarchy from ``start_path`` (or its parent if
    ``start_path`` is a file) until a Dependabot configuration file is
    found, a repository root is passed, or the filesystem root is
    reached.

    The search stops at a repository root because a cooldown is that
    repository's own release policy. Without the boundary, a checkout
    lacking a Dependabot file inherits whatever directory happens to
    contain it -- so a multi-repository sweep whose container carries a
    configuration would silently apply it to every repository beneath,
    and a lone checkout would answer differently depending on where it
    was cloned.

    Args:
        start_path: Path to begin searching from (typically the directory
            being linted).

    Returns:
        Path to the Dependabot configuration file, or ``None`` if no file
        is found at or below the enclosing repository root.
    """
    start = start_path.resolve()
    search_dir = start if start.is_dir() else start.parent

    for directory in (search_dir, *search_dir.parents):
        github_dir = directory / ".github"
        if github_dir.is_dir():
            for filename in _DEPENDABOT_FILENAMES:
                candidate = github_dir / filename
                if candidate.is_file():
                    return candidate
        # Checked after this directory's own configuration, so a
        # repository root's file is still found -- it is ascending
        # *past* the root that leaks policy across the boundary.
        if is_repository(directory):
            break

    return None


def _pattern_list(
    cooldown: dict[object, object], key: str, config_path: Path
) -> tuple[str, ...]:
    """Read one ``cooldown`` pattern list, ignoring an unusable value.

    Args:
        cooldown: The ``cooldown`` block of an ``updates`` entry.
        key: ``exclude`` or ``include``.
        config_path: File the block came from, for the log line.

    Returns:
        The patterns, or an empty tuple when the key is absent or does
        not hold a list of strings.
    """
    value = cooldown.get(key)
    if value is None:
        return ()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    logger.debug(
        "Ignoring cooldown.%s in %s: not a list of strings", key, config_path
    )
    return ()


def _extract_cooldown(
    config_path: Path,
) -> tuple[int, str, dict[object, object]] | None:
    """Find the cooldown block to apply in a Dependabot config file.

    Prefers the cooldown configured for the ``github-actions`` ecosystem,
    falling back to the first ecosystem that declares a usable
    ``cooldown.default-days``.

    Args:
        config_path: Path to the Dependabot configuration file.

    Returns:
        A ``(days, ecosystem, cooldown)`` tuple, ``cooldown`` being the
        whole block the days came from, or ``None`` if no cooldown is
        configured or the file cannot be parsed.
    """
    try:
        with open(config_path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        logger.debug(
            "Could not read Dependabot config %s: %s", config_path, exc
        )
        return None

    if not isinstance(data, dict):
        return None

    updates = data.get("updates")
    if not isinstance(updates, list):
        return None

    fallback: tuple[int, str, dict[object, object]] | None = None

    for update in updates:
        if not isinstance(update, dict):
            continue
        cooldown = update.get("cooldown")
        if not isinstance(cooldown, dict):
            continue
        days = cooldown.get("default-days")
        if not isinstance(days, int) or isinstance(days, bool) or days < 0:
            continue

        ecosystem = str(update.get("package-ecosystem", ""))
        if ecosystem == _GITHUB_ACTIONS_ECOSYSTEM:
            return days, ecosystem, cooldown
        if fallback is None:
            fallback = (days, ecosystem, cooldown)

    return fallback


def resolve_cooldown(start_path: Path) -> DependabotCooldown | None:
    """Resolve the Dependabot cooldown applicable to ``start_path``.

    Args:
        start_path: Path being linted; used to locate the repository's
            Dependabot configuration.

    Returns:
        A :class:`DependabotCooldown` describing the parsed value, or
        ``None`` when no usable cooldown configuration is found.
    """
    config_path = find_dependabot_config(start_path)
    if config_path is None:
        return None

    extracted = _extract_cooldown(config_path)
    if extracted is None:
        return None

    days, ecosystem, cooldown = extracted
    return DependabotCooldown(
        days=days,
        source=config_path,
        ecosystem=ecosystem,
        exclude=_pattern_list(cooldown, "exclude", config_path),
        include=_pattern_list(cooldown, "include", config_path),
    )
