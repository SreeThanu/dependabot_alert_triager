"""G1 measurement: how many reviewed pip advisories carry GitHub's vulnerable_functions.

Usage:
    uv run python scripts/count_vulnerable_functions.py [--refresh]

Reads GITHUB_TOKEN from the environment if set (never written anywhere). Raw pages
are cached in data/cache/github_advisories/; the summary goes to
data/validation/g1_coverage.json.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from triager.fsutil import atomic_write_text
from triager.sources.github_api import API_VERSION, advisories_url, fetch_all, summarise

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "cache" / "github_advisories"
OUT = ROOT / "data" / "validation" / "g1_coverage.json"

# (name, GitHub `published` filter, inclusive start, inclusive end, note)
WINDOWS = [
    (
        "published_2025_onward",
        ">=2025-01-01",
        "2025-01-01",
        None,
        "Published 2025-01-01 or later (plan Phase 2.1 sampling pool).",
    ),
    (
        "vulnerable_calls_live",
        "2022-04-14..2024-12-13",
        "2022-04-14",
        "2024-12-13",
        "Period when Dependabot's Python vulnerable-calls feature was live "
        "(changelog 2022-04-14; docs removed 2024-12-13).",
    ),
]


def git_head() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true", help="ignore cached pages")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN") or None

    run_started = datetime.now(UTC).isoformat(timespec="seconds")
    windows = {}
    for name, published, start, end, note in WINDOWS:
        url = advisories_url(ecosystem="pip", type="reviewed", published=published)
        res = fetch_all(url, cache_dir=CACHE_DIR, token=token, refresh=args.refresh)
        windows[name] = {
            "note": note,
            "published_filter": published,
            "query_url": url,
            "page_urls": res.page_urls,
            "pages": len(res.page_urls),
            "pages_from_cache": res.pages_from_cache,
            "pages_fetched": res.pages_fetched,
            "pages_fetched_at_min": min(res.fetched_at) if res.fetched_at else None,
            "pages_fetched_at_max": max(res.fetched_at) if res.fetched_at else None,
            **summarise(res.advisories, start, end),
        }
        w = windows[name]
        print(
            f"{name}: {w['with_vulnerable_functions']}/{w['advisories']} advisories have "
            f"pip vulnerable_functions ({w['pages']} pages, {w['pages_from_cache']} from cache)"
        )

    out = {
        "script": "scripts/count_vulnerable_functions.py",
        "repo_commit": git_head(),
        "run_started_utc": run_started,
        "api_version": API_VERSION,
        "authenticated": token is not None,
        "definition": (
            "An advisory counts as having vulnerable_functions if any entry in its "
            "'vulnerabilities' list has package.ecosystem == 'pip' and a non-empty "
            "vulnerable_functions list."
        ),
        "windows": windows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(OUT, json.dumps(out, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
