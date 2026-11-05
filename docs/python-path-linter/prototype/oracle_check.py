# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run the engine suite's oracle case tables against the prototype.

Prints each case where the prototype's rules differ from the expected
ones, grouped by kind of difference. Does not run bash: the tables
already record what bash did.
"""

from collections import Counter
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scan  # noqa: E402

TESTS = HERE.parent / "reference/test_python_path_engine.py"
spec = importlib.util.spec_from_file_location("suite", TESTS)
assert spec is not None and spec.loader is not None
suite = importlib.util.module_from_spec(spec)
sys.modules["gha_workflow_linter.python_path._engine"] = None  # type: ignore[assignment]
try:
    spec.loader.exec_module(suite)
except Exception:
    # The suite imports the engine; load the source text instead.
    import ast

    tree = ast.parse(TESTS.read_text())
    ns = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in (
            "OracleTest",
            "UvOracleTest",
        ):
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                target = item.targets[0]
                if isinstance(target, ast.Name) and target.id in (
                    "CASES",
                    "PROJECT_CASES",
                ):
                    ns[(node.name, target.id)] = ast.literal_eval(item.value)
else:
    ns = {
        ("OracleTest", "CASES"): suite.OracleTest.CASES,
        ("UvOracleTest", "CASES"): suite.UvOracleTest.CASES,
        ("UvOracleTest", "PROJECT_CASES"): suite.UvOracleTest.PROJECT_CASES,
    }


def rules(text: str, kind: str = "script") -> list[str]:
    try:
        return sorted(
            {f.rule for f in scan.scan_text(text, kind, "repo", "file")}
        )
    except Exception as error:  # noqa: BLE001
        return [f"ERROR {type(error).__name__}: {error}"]


def main() -> None:
    buckets = Counter()
    rows = []
    for shell, rule, _ran in ns[("OracleTest", "CASES")]:
        expected = sorted(
            list(rule) if isinstance(rule, tuple) else [rule] if rule else []
        )
        got = rules(shell)
        real = [r for r in got if r not in ("PPA009", "PPA010")]
        if got == expected:
            buckets["same"] += 1
        elif real == expected and "PPA009" in got:
            buckets["same + unresolved"] += 1
        elif not expected and got == ["PPA009"]:
            buckets["clean -> unresolved"] += 1
        elif expected and got == ["PPA009"]:
            buckets["finding -> unresolved"] += 1
            rows.append(("unresolved", shell, expected, got))
        elif expected and not got:
            buckets["MISSED"] += 1
            rows.append(("MISSED", shell, expected, got))
        elif not expected and real:
            buckets["FALSE POSITIVE"] += 1
            rows.append(("FALSE POSITIVE", shell, expected, got))
        else:
            buckets["other"] += 1
            rows.append(("other", shell, expected, got))
    print("bash oracle cases:", dict(buckets))
    for tag, shell, expected, got in rows:
        print(f"  [{tag}] {shell}\n      expected {expected} got {got}")


if __name__ == "__main__":
    main()
