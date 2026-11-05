# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run the prototype linter over a folder of repositories and save findings.

Usage: run_estate.py REPOS_ROOT OUT.json
"""

from dataclasses import asdict
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from discovery import candidate_files, repo_root_of  # noqa: E402
import scan  # noqa: E402

SKIP = {"project-reporting-artefacts"}


def main() -> None:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    roots = sorted(
        str(p)
        for p in root.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name not in SKIP
    )
    started = time.monotonic()
    findings = []
    problems = []
    for root in roots:
        for path, kind in candidate_files(root):
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            repo_root = repo_root_of(path, root)
            relpath = str(Path(path).resolve().relative_to(repo_root))
            try:
                findings.extend(
                    scan.scan_text(text, kind, Path(repo_root).name, relpath)
                )
            except Exception as error:  # noqa: BLE001
                problems.append(f"{path}: {type(error).__name__}: {error}")
    out.write_text(json.dumps([asdict(f) for f in findings], indent=1))
    print(
        f"{len(roots)} repos, {len(findings)} findings, {len(problems)} problems in {time.monotonic() - started:.1f}s -> {out}"
    )
    for problem in problems[:20]:
        print("  ", problem)


if __name__ == "__main__":
    main()
