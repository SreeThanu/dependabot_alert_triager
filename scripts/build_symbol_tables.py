"""T5: AST symbol tables at the vulnerable version for each sampled advisory.

Usage:
    uv run python scripts/build_symbol_tables.py

Vulnerable ref: first parent of the verified fix commit (fix_commits_v1.csv), else the
last affected release tag (triager.symbols.vulnerable_ref). Repo: the T3 repo, else the
advisory's PACKAGE reference / PyPI project URL.

Writes data/validation/symbol_tables/<ghsa_id>.json.gz, symbol_tables_v1.csv (one row
per advisory) and symbol_tables_v1.meta.json. Does not read labels_v1.csv.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime

import yaml

from triager import advisories, fixcommit, snapshots, symbols
from triager.fsutil import atomic_write_text
from triager.sources import pypi

ROOT = snapshots.ROOT
VAL = ROOT / "data" / "validation"
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
REPOS = ROOT / "data" / "raw" / "repos"
PYPI_CACHE = ROOT / "data" / "cache" / "pypi"
TABLES = VAL / "symbol_tables"
OUT = VAL / "symbol_tables_v1.csv"
OUT_META = VAL / "symbol_tables_v1.meta.json"
OVERRIDES = ROOT / "config" / "import_paths.yaml"
NO_ROOT = "import root unresolved"

COLUMNS = [
    "ghsa_id", "packages", "repo", "ref_kind", "ref", "commit", "import_roots",
    "import_root_method", "files_parsed", "files_unparsed", "n_symbols", "n_functions",
    "n_classes", "n_modules", "note",
]  # fmt: skip


def sample_ids() -> list[str]:
    text = (VAL / "sample_v1.txt").read_text()
    return [ln.split()[0] for ln in text.splitlines() if ln and ln[0] != "#"]


def main() -> None:
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    ids = sample_ids()
    advs = advisories.load_ids(SNAPSHOT_DIR, ids)
    with (VAL / "fix_commits_v1.csv").open(newline="") as fh:
        fix = {r["ghsa_id"]: r for r in csv.DictReader(fh)}
    overrides = (yaml.safe_load(OVERRIDES.read_text()) or {}).get("overrides") or {}

    rows = []
    for gid in ids:
        adv, fr = advs[gid], fix[gid]
        infos = {p: pypi.fetch(p, PYPI_CACHE).get("info") for p in adv.packages}
        row = dict.fromkeys(COLUMNS, "")
        row.update(ghsa_id=gid, packages="; ".join(adv.packages))
        repo_slug = fr["repo"] or fixcommit.package_repo(adv, infos)
        if not repo_slug:
            row["note"] = "no source repo known"
            rows.append(row)
            print(f"{gid}: skipped (no repo)", flush=True)
            continue
        row["repo"] = repo_slug
        try:
            repo = fixcommit.ensure_clone(REPOS, repo_slug)
        except fixcommit.GitError as e:
            row["note"] = str(e)
            rows.append(row)
            continue
        fix_commit = fr["fix_commits"].split("; ")[0] if fr["fix_verified"] == "yes" else None

        def parent_of(sha, repo=repo):
            return fixcommit.git(repo, "rev-parse", f"{sha}^1").stdout.strip()

        ref = symbols.vulnerable_ref(adv, fixcommit.list_tags(repo), fix_commit, parent_of)
        if ref is None:
            row["note"] = "no vulnerable ref (no fix parent and no usable tag)"
            rows.append(row)
            print(f"{gid}: skipped (no ref)", flush=True)
            continue
        kind, ref_name, note = ref
        table = symbols.build_table(repo, ref_name, list(adv.packages), overrides)
        table.update(ghsa_id=gid, repo=repo_slug, ref_kind=kind, ref=ref_name, ref_note=note)
        symbols.save(TABLES / f"{gid}.json.gz", table)
        kinds = Counter(s["kind"] for s in table["symbols"])
        row.update(
            ref_kind=kind,
            ref=ref_name,
            commit=table["commit"],
            import_roots="; ".join(table["import_roots"]),
            import_root_method=table["import_root_method"],
            files_parsed=table["files_parsed"],
            files_unparsed=len(table["files_unparsed"]),
            n_symbols=len(table["symbols"]),
            n_functions=kinds["function"],
            n_classes=kinds["class"],
            n_modules=kinds["module"],
            note="; ".join(x for x in (note, "" if table["import_roots"] else NO_ROOT) if x),
        )
        rows.append(row)
        print(f"{gid} {repo_slug} {kind}={ref_name[:20]} roots={table['import_roots']} "
              f"symbols={len(table['symbols'])}", flush=True)  # fmt: skip

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    atomic_write_text(OUT, buf.getvalue())
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    meta = {
        "script": "scripts/build_symbol_tables.py",
        "repo_commit": head,
        "run_started_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "snapshot": snap.commit,
        "advisories": len(rows),
        "with_symbol_table": sum(bool(r["n_symbols"]) for r in rows),
        "ref_kinds": dict(Counter(r["ref_kind"] or "none" for r in rows)),
        "import_root_unresolved": sum(r["import_root_method"] == "unresolved" for r in rows),
    }
    atomic_write_text(OUT_META, json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
