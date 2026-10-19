"""Fetch a pinned snapshot from config/snapshots.yaml and verify HEAD.

Usage:
    uv run python scripts/fetch_snapshot.py github_advisory_database

Only github-reviewed advisories for 2025 and 2026 are checked out (sparse) for the GHSA database.
"""

from __future__ import annotations

import sys

from triager import snapshots

# The pool is published >= 2025-01-01; GHSA files live under github-reviewed/<year>/<month>/.
# scripts/sample.py checks the pool size, which guards against advisories filed elsewhere.
DESTS = {
    "github_advisory_database": (
        "data/raw/ghsa",
        ["/advisories/github-reviewed/2025/", "/advisories/github-reviewed/2026/"],
    )
}


def main() -> None:
    name = sys.argv[1]
    if name not in DESTS:
        sys.exit(f"no destination configured for {name}; add it when a task needs it")
    rel, sparse = DESTS[name]
    snap = snapshots.load(name)
    dest = snapshots.ROOT / rel
    snapshots.fetch(snap, dest, sparse)
    print(f"{name}: HEAD {snapshots.head(dest)} == pinned {snap.commit} -> OK ({rel})")


if __name__ == "__main__":
    main()
