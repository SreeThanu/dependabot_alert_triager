"""G2 and G4 (plan §2.6) from the 50-sample labels and fix-commit results.

Usage:
    uv run python scripts/g2_g4.py

Inputs: data/validation/labels_v1.csv (package_type, usable, classify_source),
data/validation/fix_commits_v1.csv (fix_verified, fix_commit_source) and the pinned GHSA
snapshot (HEAD verified) for whether each advisory lists a fixed version.
Output: data/validation/g2_g4_v1.json.

L follows the definition recorded in docs/VALIDATION.md: usable = yes and
package_type = library. A secondary view also counts usable native_ext rows. G4 is reported
automated-only (manual candidates ignored) and including manual candidates.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import subprocess
from collections import Counter
from datetime import UTC, datetime

from triager import advisories, snapshots
from triager.fsutil import atomic_write_text

ROOT = snapshots.ROOT
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
VAL = ROOT / "data" / "validation"
LABELS = VAL / "labels_v1.csv"
FIX_COMMITS = VAL / "fix_commits_v1.csv"
OUT = VAL / "g2_g4_v1.json"

VIEWS = {"library": ("library",), "library_native_ext": ("library", "native_ext")}


def wilson(k: int, n: int, z: float = 1.959964) -> dict:
    """Proportion with a 95% Wilson score interval."""
    if n == 0:
        return {"k": k, "n": n, "p": None, "ci95": None}
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    ci = [round(centre - half, 4), round(centre + half, 4)]
    return {"k": k, "n": n, "p": round(p, 4), "ci95": ci}


def lists_fixed_version(gid: str) -> bool:
    paths = list((SNAPSHOT_DIR / "advisories" / "github-reviewed").glob(f"*/*/{gid}/{gid}.json"))
    if len(paths) != 1:
        raise FileNotFoundError(f"{gid}: expected one snapshot record, found {len(paths)}")
    adv = advisories.parse(json.loads(paths[0].read_text()))
    return adv is not None and any(r.fixed for r in adv.ranges)


def read(path):
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def view(labels: list[dict], fixes: dict[str, dict], types: tuple[str, ...]) -> dict:
    usable = [r for r in labels if r["usable"] == "yes" and r["package_type"] in types]
    denom = [r for r in usable if lists_fixed_version(r["ghsa_id"])]
    fx = [fixes[r["ghsa_id"]] for r in denom]
    sources = Counter(f["fix_commit_source"] for f in fx if f["fix_verified"] == "yes")
    automated = sum(n for s, n in sources.items() if s != "manual")
    return {
        "package_types": list(types),
        "G2": wilson(len(usable), len(labels)),
        "unfixed": sorted(r["ghsa_id"] for r in usable if r not in denom),
        "G4_automated": wilson(automated, len(denom)),
        "G4_including_manual": wilson(sum(sources.values()), len(denom)),
        "verified_by_source": dict(sorted(sources.items())),
        "not_verified": sorted(f["ghsa_id"] for f in fx if f["fix_verified"] != "yes"),
    }


def main() -> None:
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    labels = read(LABELS)
    fixes = {r["ghsa_id"]: r for r in read(FIX_COMMITS)}
    missing = [r["ghsa_id"] for r in labels if r["ghsa_id"] not in fixes]
    if missing:
        raise SystemExit(f"labels without a fix_commits row: {missing}")
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    out = {
        "script": "scripts/g2_g4.py",
        "repo_commit": head,
        "run_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "snapshot": {"repo": snap.repo_url, "commit": snap.commit},
        "inputs_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (LABELS, FIX_COMMITS)
        },
        "n_sample": len(labels),
        "package_type": dict(Counter(r["package_type"] for r in labels).most_common()),
        "classify_source": dict(Counter(r["classify_source"] for r in labels).most_common()),
        "views": {name: view(labels, fixes, types) for name, types in VIEWS.items()},
    }
    atomic_write_text(OUT, json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
