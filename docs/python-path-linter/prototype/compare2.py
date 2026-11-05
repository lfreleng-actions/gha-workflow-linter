# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Compare walker and prototype findings, tolerating line shifts within ±4.

Usage: compare2.py WALKER.json PROTO.json
"""

from collections import Counter
import json
import sys
from typing import Any


def main() -> None:
    with open(sys.argv[1]) as handle:
        walker = json.load(handle)
    with open(sys.argv[2]) as handle:
        proto = json.load(handle)

    def match(a: dict[str, Any], b: dict[str, Any]) -> bool:
        same = all(a[key] == b[key] for key in ("repo", "path", "rule"))
        return same and abs(int(a["line"]) - int(b["line"])) <= 4

    unmatched_w = []
    used = set()
    for f in walker:
        hit = next(
            (i for i, g in enumerate(proto) if i not in used and match(f, g)),
            None,
        )
        if hit is None:
            unmatched_w.append(f)
        else:
            used.add(hit)
    unmatched_p = [g for i, g in enumerate(proto) if i not in used]
    print(f"walker={len(walker)} proto={len(proto)} matched={len(used)}")
    print(
        f"walker-only={len(unmatched_w)} by rule {dict(sorted(Counter(f['rule'] for f in unmatched_w).items()))}"
    )
    print(
        f"proto-only={len(unmatched_p)} by rule {dict(sorted(Counter(f['rule'] for f in unmatched_p).items()))}"
    )
    print("\n== walker-only (prototype misses)")
    for f in unmatched_w:
        print(
            f"  {f['rule']} {f['repo']}/{f['path']}:{f['line']}  {f['snippet'][:100]}"
        )
    print("\n== proto-only, real rules")
    for f in unmatched_p:
        if f["rule"] in ("PPA009", "PPA010"):
            continue
        print(
            f"  {f['rule']} {f['repo']}/{f['path']}:{f['line']}  {f['snippet'][:100]}"
        )
    nine = [f for f in unmatched_p if f["rule"] == "PPA009"]
    print(f"\n== PPA009 unresolved: {len(nine)}; by detail kind:")
    kinds = Counter(
        f["detail"].split(":")[0].split(" is ")[0][:40] for f in nine
    )
    for k, c in kinds.most_common():
        print(f"  {c:4} {k}")
    print("\n== PPA009 by repo")
    for repo, c in Counter(f["repo"] for f in nine).most_common(25):
        print(f"  {c:4} {repo}")
    print("\n== PPA009 sample (program unresolved), distinct programs")
    progs = Counter()
    for f in nine:
        if f["detail"].startswith("program is"):
            progs[f["detail"].split("'")[1]] += 1
    for p, c in progs.most_common(40):
        print(f"  {c:4} {p}")
    ten = [f for f in unmatched_p if f["rule"] == "PPA010"]
    print(f"\n== PPA010 parse errors: {len(ten)}")
    for f in ten:
        print(f"  {f['repo']}/{f['path']}:{f['line']}  {f['snippet'][:90]}")


if __name__ == "__main__":
    main()
