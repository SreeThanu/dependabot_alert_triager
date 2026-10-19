"""T3: resolve and verify fix commits for the 50 advisories in sample_v1.txt.

Usage:
    uv run python scripts/resolve_fix_commits.py

Inputs: the pinned GHSA snapshot (HEAD verified), data/validation/sample_v1.txt, cached
PyPI metadata (data/cache/pypi/). Does NOT read or write data/validation/labels_v1.csv.

Outputs (crash-safe writes):
  data/validation/fix_commits_v1.csv            one row per ghsa_id
  data/validation/fix_commit_candidates_v1.csv  one row per candidate commit checked
  data/validation/fix_commits_v1.meta.json      provenance and counts

Repos are cloned blobless into data/raw/repos/. PR lookups use GITHUB_TOKEN if set
(never written anywhere) and are cached in data/cache/github_pulls/.

Optional human input: data/validation/manual_fix_candidates.csv with columns
ghsa_id, commit_url, how_found. Each row gets the same four checks with source = manual.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime

from triager import advisories, fixcommit, snapshots
from triager.fsutil import atomic_write_text
from triager.sources import github_api, pypi

ROOT = snapshots.ROOT
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
REPOS = ROOT / "data" / "raw" / "repos"
PR_CACHE = ROOT / "data" / "cache" / "github_pulls"
REPO_CACHE = ROOT / "data" / "cache" / "github_repos"
PYPI_CACHE = ROOT / "data" / "cache" / "pypi"
VAL = ROOT / "data" / "validation"
SAMPLE = VAL / "sample_v1.txt"
OUT = VAL / "fix_commits_v1.csv"
OUT_CANDS = VAL / "fix_commit_candidates_v1.csv"
OUT_META = VAL / "fix_commits_v1.meta.json"
MANUAL = VAL / "manual_fix_candidates.csv"  # human-maintained; optional
MANUAL_COLUMNS = ["ghsa_id", "commit_url", "how_found"]

ADV_COLUMNS = [
    "ghsa_id", "packages", "repo", "fix_links_commit", "fix_links_pr", "fix_commits_linked",
    "stages_tried", "fix_commit_source", "fix_verified", "fix_commits", "n_candidates",
    "check_repo_matches_pypi", "check_in_fixed_tag", "check_not_in_affected_tag",
    "check_changes_src", "fixed_version", "fixed_tag", "last_affected_tag",
    "diff_files_total", "diff_files_src", "diff_files_test", "failure_reason",
]  # fmt: skip
CAND_COLUMNS = [
    "ghsa_id", "source", "repo", "sha", "link", "verified",
    "check_repo_matches_pypi", "check_in_fixed_tag", "check_not_in_affected_tag",
    "check_changes_src", "fixed_version", "fixed_tag", "last_affected_tag",
    "files_total", "files_src", "files_test", "details",
]  # fmt: skip


def sample_ids() -> list[str]:
    return [ln.split()[0] for ln in SAMPLE.read_text().splitlines() if ln and ln[0] != "#"]


def load_advisories(ids: list[str]) -> dict[str, advisories.Advisory]:
    wanted = set(ids)
    out = {a.ghsa_id: a for a in advisories.iter_pypi(SNAPSHOT_DIR) if a.ghsa_id in wanted}
    missing = wanted - set(out)
    if missing:
        sys.exit(f"sample IDs missing from snapshot: {sorted(missing)}")
    return out


def load_manual(ids: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Rows of manual_fix_candidates.csv grouped by ghsa_id (empty if the file is absent)."""
    if not MANUAL.exists():
        return {}
    with MANUAL.open(newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != MANUAL_COLUMNS:
            sys.exit(f"{MANUAL.name}: columns must be {MANUAL_COLUMNS}, got {reader.fieldnames}")
        rows = [r for r in reader if any((v or "").strip() for v in r.values())]
    unknown = sorted({r["ghsa_id"] for r in rows} - set(ids))
    if unknown:
        sys.exit(f"{MANUAL.name}: ghsa_id not in sample_v1: {unknown}")
    out: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        out.setdefault(r["ghsa_id"].strip(), []).append(
            (r["commit_url"].strip(), (r["how_found"] or "").strip())
        )
    return out


def make_pr_lookup(token: str | None, stats: Counter):
    def lookup(repo_slug: str, number: int) -> tuple[str | None, str]:
        owner, repo = repo_slug.split("/")
        url = f"{github_api.API_ROOT}/repos/{owner}/{repo}/pulls/{number}"
        path = PR_CACHE / f"{owner}__{repo}__{number}.json"
        try:
            rec = github_api.get_cached_json(url, path, token=token)
        except github_api.GitHubAPIError as e:
            stats["pr_api_error"] += 1
            return None, f"GitHub API error (not cached; re-run to retry): {str(e)[:160]}"
        stats["pr_lookups"] += 1
        if rec["status"] == 404:
            return None, "PR not found (404)"
        body = rec["body"] or {}
        if not body.get("merged"):
            return None, "PR not merged"
        return body.get("merge_commit_sha"), "merged"

    return lookup


def make_canonical(token: str | None, stats: Counter):
    def canonical(repo_slug: str) -> str | None:
        owner, repo = repo_slug.split("/")
        url = f"{github_api.API_ROOT}/repos/{owner}/{repo}"
        path = REPO_CACHE / f"{owner}__{repo}.json"
        try:
            rec = github_api.get_cached_json(url, path, token=token)
        except github_api.GitHubAPIError:
            stats["repo_api_error"] += 1
            return None
        stats["repo_lookups"] += 1
        body = rec["body"] or {}
        if rec["status"] != 200:
            return None
        return (body.get("full_name") or "").lower() or None

    return canonical


def csv_text(columns: list[str], rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def advisory_row(res: fixcommit.Resolution) -> dict:
    adv = res.adv
    best = res.best()
    used = res.verified or ([best] if best else [])
    files = sorted({f for c in used for f in c.files})
    reasons = []
    if not res.verified:
        if best:
            failed = [k for k, v in best.checks.items() if v != fixcommit.PASS]
            reasons.append(f"best candidate {best.sha[:12]} ({best.source}): " + ", ".join(
                f"{k}={best.checks[k]}" for k in failed))  # fmt: skip
            reasons += best.details
        reasons += res.errors
        if not res.candidates and not res.errors:
            reasons.append("no candidate commits")
    return {
        "ghsa_id": adv.ghsa_id,
        "packages": "; ".join(adv.packages),
        "repo": best.repo if best else (fixcommit.package_repo(adv, {}) or ""),
        "fix_links_commit": len(res.commit_links),
        "fix_links_pr": len(res.pr_links),
        "fix_commits_linked": len(res.commit_links) + len(res.pr_links),
        "stages_tried": "; ".join(res.stages_tried),
        "fix_commit_source": res.source,
        "fix_verified": "yes" if res.verified else "no",
        "fix_commits": "; ".join(c.sha for c in used),
        "n_candidates": len(res.candidates),
        **{f"check_{k}": (best.checks.get(k, "") if best else "") for k in fixcommit.CHECKS},
        "fixed_version": best.fixed_version if best else "",
        "fixed_tag": best.fixed_tag if best else "",
        "last_affected_tag": best.last_affected_tag if best else "",
        "diff_files_total": len(files) if used else "",
        "diff_files_src": sum(fixcommit.classify(f) == "source" for f in files) if used else "",
        "diff_files_test": sum(fixcommit.classify(f) == "test" for f in files) if used else "",
        "failure_reason": " | ".join(dict.fromkeys(reasons)),
    }


def candidate_row(c: fixcommit.Candidate) -> dict:
    return {
        "ghsa_id": c.ghsa_id,
        "source": c.source,
        "repo": c.repo,
        "sha": c.sha,
        "link": c.link,
        "verified": "yes" if c.verified else "no",
        **{f"check_{k}": c.checks.get(k, "") for k in fixcommit.CHECKS},
        "fixed_version": c.fixed_version,
        "fixed_tag": c.fixed_tag,
        "last_affected_tag": c.last_affected_tag,
        "files_total": len(c.files),
        "files_src": len(c.files_of("source")),
        "files_test": len(c.files_of("test")),
        "details": " | ".join(c.details),
    }


def main() -> None:
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    ids = sample_ids()
    advs = load_advisories(ids)
    manual = load_manual(ids)
    token = os.environ.get("GITHUB_TOKEN") or None
    stats: Counter = Counter()
    lookup = make_pr_lookup(token, stats)
    canonical = make_canonical(token, stats)
    started = datetime.now(UTC).isoformat(timespec="seconds")

    results = []
    for i, gid in enumerate(ids, 1):
        adv = advs[gid]
        infos = {p: pypi.fetch(p, PYPI_CACHE).get("info") for p in adv.packages}
        res = fixcommit.resolve(adv, infos, REPOS, lookup, canonical, manual=manual.get(gid, []))
        results.append(res)
        status = "VERIFIED" if res.verified else "not verified"
        print(f"[{i:2}/{len(ids)}] {gid} {', '.join(adv.packages)}: {res.source} {status}",
              flush=True)  # fmt: skip

    adv_rows = [advisory_row(r) for r in results]
    cand_rows = [candidate_row(c) for r in results for c in r.candidates]
    atomic_write_text(OUT, csv_text(ADV_COLUMNS, adv_rows))
    atomic_write_text(OUT_CANDS, csv_text(CAND_COLUMNS, cand_rows))

    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    by_source = Counter(r.source for r in results)
    meta = {
        "script": "scripts/resolve_fix_commits.py",
        "repo_commit": head,
        "run_started_utc": started,
        "snapshot": {"repo": snap.repo_url, "commit": snap.commit},
        "sample": "data/validation/sample_v1.txt",
        "advisories": len(results),
        "verified": sum(bool(r.verified) for r in results),
        "verified_by_source": {k: v for k, v in sorted(by_source.items()) if k != "none"},
        "not_verified": by_source.get("none", 0),
        "github_api_authenticated": token is not None,
        "pr_lookups": stats["pr_lookups"],
        "pr_lookup_api_errors": stats["pr_api_error"],
        "repo_rename_lookups": stats["repo_lookups"],
        "repo_rename_lookup_api_errors": stats["repo_api_error"],
        "candidates_checked": len(cand_rows),
        "manual_candidates": sum(len(v) for v in manual.values()),
        "manual_file_sha256": (
            hashlib.sha256(MANUAL.read_bytes()).hexdigest() if MANUAL.exists() else None
        ),
    }
    atomic_write_text(OUT_META, json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
