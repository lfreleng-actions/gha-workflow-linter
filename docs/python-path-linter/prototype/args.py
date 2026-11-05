# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Python and uv command-line reading, from literal words."""

from __future__ import annotations

from dataclasses import dataclass

from tables import PY_INFO, UV_VALUE


def parse_python(words: list[str]) -> tuple[str, set[str]]:
    """Mode ("module", "command", "stdin", "script", "info") and flags of ``python <words>``."""
    flags: set[str] = set()
    index = 0
    while index < len(words):
        word = words[index]
        if word in PY_INFO:
            return "info", flags
        if word == "-":
            return "stdin", flags
        if word == "--":
            return (
                "stdin"
                if words[index + 1 : index + 2] in ([], ["-"])
                else "script"
            ), flags
        if word.startswith("--"):
            index += 2 if word == "--check-hash-based-pycs" else 1
            continue
        if word.startswith("-") and len(word) > 1:
            for position, letter in enumerate(word[1:], start=1):
                if letter in "mc":
                    return ("module" if letter == "m" else "command"), flags
                if letter in "WX":
                    index += 1 if position == len(word) - 1 else 0
                    break
                flags.add(letter)
            index += 1
            continue
        return "script", flags
    return "stdin", flags


def risky(mode: str, flags: set[str]) -> bool:
    return "I" not in flags and mode not in ("info", "script")


@dataclass
class UvCommand:
    subcommand: list[str]
    options: set[str]
    values: dict[str, int]  # option -> index of its value word in `words`
    program: int  # index where uv run's program starts, or -1


def parse_uv(words: list[str]) -> UvCommand:
    command = UvCommand([], set(), {}, -1)
    i = 0
    while i < len(words):
        word = words[i]
        running = command.subcommand[:1] == ["run"] or command.subcommand[
            :2
        ] == ["tool", "run"]
        if word == "--":
            command.program = i + 1 if running else -1
            break
        if not word.startswith("-"):
            if running:
                command.program = i
                break
            if len(command.subcommand) < 2:
                command.subcommand.append(word)
            i += 1
            continue
        name = word.split("=", 1)[0]
        name = "--python" if name == "-p" else name
        command.options.add(name)
        if running and name in ("-m", "--module"):
            command.program = -2  # module: uv itself runs python -m
            break
        if "=" in word:
            command.values[name] = i
        elif word in UV_VALUE:
            command.values[name] = i + 1
            i += 1
        i += 1
    return command


def parse_uvx(words: list[str]) -> UvCommand:
    """Split ``uvx``'s arguments: its options, then the program."""
    command = UvCommand(["tool", "run"], set(), {}, 0)
    i = 0
    while i < len(words) and words[i].startswith("-"):
        name = words[i].split("=", 1)[0]
        command.options.add(name)
        if "=" not in words[i] and words[i] in UV_VALUE:
            command.values[name] = i + 1
            i += 1
        i += 1
    command.program = i
    return command


def uv_findings(
    command: UvCommand, settings: dict[str, bool], is_uvx: bool
) -> list[str]:
    """The rules a uv command breaks, from its subcommand and settings.

    Measured on uv 0.11 and 0.13 with planted interpreters (see the
    oracle tests on #434): 'uv run' and 'uv venv' read a workspace
    .python-version unless --no-config or any --python; 'uv run' uses
    a workspace .venv unless --python names a path outside it and
    project mode is off (or the project environment is elsewhere), or
    VIRTUAL_ENV is active; 'uv python find' needs --no-config and
    --system; 'uv pip' needs --system, a --python path or VIRTUAL_ENV.
    uvx and 'uv tool' use neither.
    """
    head = command.subcommand[:1]
    options = command.options
    found: list[str] = []
    if is_uvx:
        return found
    if head in (["run"], ["venv"]) and not (
        settings["no_config"] or settings["any_python"]
    ):
        found.append("PPA006")
    if head == ["run"]:
        active = settings["venv"] and (
            settings["no_project"] or "--active" in options
        )
        isolated = settings["python_path"] and (
            settings["no_project"] or settings["project_env"]
        )
        if not (isolated or active):
            found.append("PPA007")
    elif head == ["export"] and not settings["project_env"]:
        found.append("PPA007")
    elif head == ["python"] and command.subcommand[1:2] == ["find"]:
        if not settings["no_config"]:
            found.append("PPA006")
        if not settings["system"]:
            found.append("PPA007")
    elif head == ["pip"]:
        venv = settings["venv"] and "--python" not in options
        if not (settings["system"] or settings["python_path"] or venv):
            found.append("PPA007")
    return found
