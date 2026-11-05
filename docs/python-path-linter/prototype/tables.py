# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Rule texts and option tables the prototype linter judges commands by."""

from __future__ import annotations

import re

RULES = {
    "PPA001": "python -m without -I: the working directory leads sys.path",
    "PPA002": "python -c without -I: the working directory leads sys.path",
    "PPA003": "python reading stdin without -I: the working directory leads sys.path",
    "PPA004": "PYTHONPATH may hold an empty entry",
    "PPA005": "PYTHONPATH names the caller's checkout",
    "PPA006": "uv reads .python-version from the workspace",
    "PPA007": "uv uses a .venv in the workspace",
    "PPA008": "setup-uv works in the workspace",
    "PPA009": "unresolved: the command's effect depends on a value the scan cannot read",
    "PPA010": "not fully scanned: shell the parser could not read",
}
INTERPRETER = re.compile(r"^(?:.*/)?python(?:3(?:\.\d+)?)?$")
# Node types that may appear as one word of a command.
WORD_TYPES = {
    "word",
    "string",
    "raw_string",
    "concatenation",
    "number",
    "simple_expansion",
    "expansion",
    "command_substitution",
    "process_substitution",
    "ansi_c_string",
    "translated_string",
    "arithmetic_expansion",
    "brace_expression",
}
# Wrappers whose program follows their options; option -> takes a value.
WRAPPERS: dict[str, frozenset[str]] = {
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n"}),
    "nohup": frozenset(),
    "time": frozenset(),
    "sudo": frozenset(
        {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}
    ),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "xargs": frozenset({"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
}
POSITIONAL = {"timeout": 1}
ENV_VALUE = frozenset(
    {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
)
RUNNERS = frozenset({"poetry", "pipenv", "pdm", "hatch", "rye"})
UV_VALUE = frozenset(
    {
        "--directory",
        "--project",
        "--python",
        "-p",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--from",
        "--extra",
        "--group",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--cache-dir",
        "--config-file",
        "--constraints",
        "-c",
        "--overrides",
        "--package",
        "--env-file",
        "--color",
        "-w",
        "-i",
        "-f",
        "-C",
        "--config-setting",
        "--resolution",
        "--prerelease",
        "--exclude-newer",
        "--link-mode",
        "--python-preference",
        "--python-platform",
        "--only-group",
        "--no-group",
        "--no-extra",
        "--keyring-provider",
        "--allow-insecure-host",
        "--default-index",
        "--index-strategy",
        "--fork-strategy",
        "--build-constraints",
        "-b",
        "--refresh-package",
        "--upgrade-package",
        "-P",
        "--reinstall-package",
        "--no-binary-package",
        "--no-build-package",
    }
)
UV_INFO = frozenset({"-h", "--help", "-V", "--version"})
# uv options whose value decides what interpreter or directory uv uses.
UV_DECIDING = frozenset({"--python", "--directory", "--project"})
PY_INFO = frozenset(
    {
        "-h",
        "-?",
        "--help",
        "--help-all",
        "--help-env",
        "--help-xoptions",
        "-V",
        "-VV",
        "--version",
    }
)
# Commands that make a block's trust (from a leading cd) unprovable:
# they change the directory, or run code the parser does not see.
TRUST_BREAKERS = frozenset(
    {"cd", "pushd", "popd", "exec", "eval", "source", "."}
)
# Builtins that assign their NAME=value words.
DECLARATIONS = frozenset({"export", "declare", "typeset", "local", "readonly"})
IGNORE_MARK = "python-path-audit: ignore"
