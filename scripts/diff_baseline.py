"""T4: diff baseline over the verified fix commits (data/validation/fix_commits_v1.csv).

Usage:
    uv run python scripts/diff_baseline.py

Writes (crash-safe):
  data/validation/diff_baseline_v1.csv          one row per advisory with a verified fix
  data/validation/diff_baseline_symbols_v1.csv  one row per (advisory, symbol, commit, file)
  data/validation/diff_baseline_v1.meta.json    provenance and the candidate-count distribution

Does not read or write data/validation/labels_v1.csv. Nothing is scored (no gold labels yet).
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime

import yaml

from triager import fixcommit, snapshots
from triager.baselines import diff as db
from triager.fsutil import atomic_write_text

ROOT = snapshots.ROOT
VAL = ROOT / "data" / "validation"
REPOS = ROOT / "data" / "raw" / "repos"
FIX = VAL / "fix_commits_v1.csv"
OVERRIDES = ROOT / "config" / "import_paths.yaml"
OUT = VAL / "diff_baseline_v1.csv"
OUT_SYMBOLS = VAL / "diff_baseline_symbols_v1.csv"
OUT_META = VAL / "diff_baseline_v1.meta.json"

COLUMNS = [
    "ghsa_id", "packages", "repo", "fix_commit_source", "fix_commits",
    "import_roots", "import_root_method",
    "files_changed", "files_python_in_scope", "files_non_python_in_scope", "files_out_of_scope",
    "unparsed_files", "new_files",
    "n_functions", "n_classes", "n_module", "functions", "classes_and_modules", "note",
]  # fmt: skip
SYMBOL_COLUMNS = ["ghsa_id", "symbol", "kind", "commit", "file", "lines"]


def csv_text(columns, rows) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def bucket(n: int) -> str:
    return "0" if n == 0 else "1" if n == 1 else "2-3" if n <= 3 else "4+"


def main() -> None:
    overrides = (yaml.safe_load(OVERRIDES.read_text()) or {}).get("overrides") or {}
    with FIX.open(newline="") as fh:
        verified = [r for r in csv.DictReader(fh) if r["fix_verified"] == "yes"]
    rows, symbol_rows = [], []
    for r in verified:
        repo = fixcommit.clone_dir(REPOS, r["repo"])
        commits = r["fix_commits"].split("; ")
        packages = r["packages"].split("; ")
        parent = db._git(repo, "rev-parse", f"{commits[0]}^1").strip()
        roots, method = db.import_roots(db.tree_paths(repo, parent), packages, overrides)
        analyses = [db.analyse_commit(repo, sha, roots) for sha in commits]
        statuses = {p: s for a in analyses for p, s in a.files.items()}
        combined = db.combine(h for a in analyses for h in a.hits)
        funcs = [s for (s, k) in combined if k == "function"]
        others = [s for (s, k) in combined if k != "function"]
        out_of_scope = Counter(s for s in statuses.values() if s not in ("python",))
        notes = []
        if not roots:
            notes.append("import root unresolved: no files analysed")
        if statuses and not any(s == "python" for s in statuses.values()):
            notes.append("no Python source changed inside the import root")
        rows.append(
            {
                "ghsa_id": r["ghsa_id"],
                "packages": r["packages"],
                "repo": r["repo"],
                "fix_commit_source": r["fix_commit_source"],
                "fix_commits": r["fix_commits"],
                "import_roots": "; ".join(roots),
                "import_root_method": method,
                "files_changed": len(statuses),
                "files_python_in_scope": sum(s == "python" for s in statuses.values()),
                "files_non_python_in_scope": "; ".join(
                    sorted(p for p, s in statuses.items() if s == "non_python_source")
                ),
                "files_out_of_scope": "; ".join(
                    f"{k}={v}" for k, v in sorted(out_of_scope.items()) if k != "non_python_source"
                ),
                "unparsed_files": "; ".join(sorted({p for a in analyses for p in a.unparsed})),
                "new_files": "; ".join(sorted({p for a in analyses for p in a.new_files})),
                "n_functions": len(funcs),
                "n_classes": sum(k == "class" for (_, k) in combined),
                "n_module": sum(k == "module" for (_, k) in combined),
                "functions": "; ".join(funcs),
                "classes_and_modules": "; ".join(others),
                "note": "; ".join(notes),
            }
        )
        for (sym, kind), hits in combined.items():
            for h in hits:
                symbol_rows.append(
                    {
                        "ghsa_id": r["ghsa_id"],
                        "symbol": sym,
                        "kind": kind,
                        "commit": h.commit,
                        "file": h.file,
                        "lines": " ".join(map(str, h.lines)),
                    }
                )
        print(f"{r['ghsa_id']} {r['packages']}: roots={roots or '-'} ({method}) "
              f"functions={len(funcs)} other={len(others)}", flush=True)  # fmt: skip

    atomic_write_text(OUT, csv_text(COLUMNS, rows))
    atomic_write_text(OUT_SYMBOLS, csv_text(SYMBOL_COLUMNS, symbol_rows))
    dist = Counter(bucket(row["n_functions"]) for row in rows)
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    meta = {
        "script": "scripts/diff_baseline.py",
        "repo_commit": head,
        "run_started_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "input": "data/validation/fix_commits_v1.csv (fix_verified = yes)",
        "advisories": len(rows),
        "n_functions_distribution": {k: dist.get(k, 0) for k in ("0", "1", "2-3", "4+")},
        "import_root_methods": dict(Counter(row["import_root_method"] for row in rows)),
    }
    atomic_write_text(OUT_META, json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
