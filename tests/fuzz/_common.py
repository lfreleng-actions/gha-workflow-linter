# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""What the fuzz harnesses share; the fuzzer itself stays in each harness.

Each harness exposes ``check(data)``, a plain function that raises
:class:`ContractBreach` when an input breaks the contract it names,
and ``SEEDS``, the inputs the unit suite replays through it.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class ContractBreach(Exception):
    """An input that breaks the documented contract under test."""


def ensure(condition: bool, message: str) -> None:
    """Raise :class:`ContractBreach` with ``message`` unless ``condition``.

    Not ``assert``, which ``python -O`` strips.
    """
    if not condition:
        raise ContractBreach(message)


def as_read(data: bytes) -> str:
    """The text a scan reads from a file holding ``data``.

    The scans read with ``Path.read_text(encoding="utf-8",
    errors="replace")``, which also translates ``\\r\\n`` and ``\\r``
    to ``\\n``; this decodes the same way.
    """
    stream = io.TextIOWrapper(
        io.BytesIO(data), encoding="utf-8", errors="replace"
    )
    return stream.read()


def fuzzer_args(argv: list[str], seed_dir: str) -> list[str]:
    """The libFuzzer arguments: ``argv``, plus the seeds unless it names a file.

    Seeds go after any corpus directories, so libFuzzer still writes
    the inputs it keeps to the first directory it was given.
    """
    names_file = any(
        not arg.startswith("-") and Path(arg).is_file() for arg in argv[1:]
    )
    return list(argv) if names_file else [*argv, seed_dir]


def run(
    argv: list[str],
    seeds: Iterable[bytes],
    fuzz: Callable[[list[str]], None],
) -> None:
    """Write ``seeds`` to a temporary directory and call ``fuzz`` with args."""
    with tempfile.TemporaryDirectory(prefix="fuzz-seeds-") as seed_dir:
        for number, seed in enumerate(seeds):
            (Path(seed_dir) / f"seed-{number:03d}").write_bytes(seed)
        fuzz(fuzzer_args(argv, seed_dir))
