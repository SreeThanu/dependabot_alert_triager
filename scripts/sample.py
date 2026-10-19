"""T2: build the pool, propose families, draw sample_v1, create the label CSV template.

Usage:
    uv run python scripts/sample.py

Reads only the pinned github/advisory-database snapshot (data/raw/ghsa; HEAD is
verified against config/snapshots.yaml). PyPI metadata (live, cached in
data/cache/pypi/) feeds only the package_type_proposed / package_type_reason
helper columns.

Never resamples silently: if sample_v1.txt exists and a fresh draw differs, it
exits with an error. Never overwrites labels_v1.csv.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from pathlib import Path

import yaml

from triager import advisories, families, package_type, sampling, snapshots
from triager.fsutil import atomic_write_text
from triager.sources import pypi

ROOT = snapshots.ROOT
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
FAMILIES = ROOT / "config" / "package_families.yaml"
OUT_DIR = ROOT / "data" / "validation"
SAMPLE = OUT_DIR / "sample_v1.txt"
LABELS = OUT_DIR / "labels_v1.csv"
REVIEW = OUT_DIR / "family_review.yaml"
PYPI_CACHE = ROOT / "data" / "cache" / "pypi"

SEED = 20261019
# Pool size measured on the pinned snapshot; a different value means the input changed.
EXPECTED_POOL = 2953
N = 50
CAP = 2

# Plan §2.2, in order, plus two helper columns.
COLUMNS = [
    "ghsa_id", "aliases", "published", "package_family", "packages",
    "package_type", "usable", "unusable_reason",
    "github_vulnerable_functions",
    "text_names_function", "named_symbols_text",
    "fix_commits", "fix_commit_source", "fix_verified",
    "diff_files_total", "diff_files_src", "diff_funcs_changed_src",
    "gold_vulnerable_symbols", "gold_entry_points",
    "label_confidence", "label_basis",
    "minutes_spent", "labeler", "notes",
    "package_type_proposed", "package_type_reason",
]  # fmt: skip


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample_text(snap, pool, units, chosen, mapping) -> str:
    merged = sum(len(u.advisories) > 1 for u in units)
    lines = [
        "# sample_v1: capped random sample of the validation pool (docs/VALIDATION_AND_PLAN.md §2.1)",  # noqa: E501
        f"# snapshot: {snap.repo_url} @ {snap.commit} ({snap.date})",
        f"# pool: github-reviewed, affects PyPI, published >= {advisories.POOL_START}, "
        f"not withdrawn -> {len(pool)} advisories",
        f"# units after CVE-alias merge: {len(units)} ({merged} merged units)",
        f"# families: config/package_families.yaml sha256 {sha256(FAMILIES)}",
        f"# seed: {SEED}",
        f"# n: {N}, cap: {CAP} per family",
        "# algorithm: triager.sampling.draw (units sorted by id, random.Random(seed).shuffle, "
        "accept while every family of the unit is under the cap)",
        "# generator: scripts/sample.py",
    ]
    for u in chosen:
        extra = [a.ghsa_id for a in u.advisories[1:]]
        lines.append(u.id + (f"  # merged: {' '.join(extra)}" if extra else ""))
    return "\n".join(lines) + "\n"


def read_sample_ids(path: Path) -> list[str]:
    return [ln.split()[0] for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]


def write_family_review(pool, units, mapping, chosen) -> dict:
    names = {p for a in pool for p in a.packages}
    repos = families.repos_by_package(pool)
    entries = families.build_review(
        families.detect_shared_repo(repos, mapping),
        families.detect_candidates(names, mapping),
    )
    chosen_ids = [u.id for u in chosen]
    for e in entries:
        e["repos"] = {m: sorted(repos.get(m, [])) for m in e["members"]}
        alt = families.with_groups(mapping, [e["members"]])
        e["changes_sample_if_merged"] = [
            u.id for u in sampling.draw(units, alt, SEED, N, CAP)
        ] != chosen_ids
    proposed = [e["members"] for e in entries if e["proposed"] == "merge"]
    alt = families.with_groups(mapping, proposed)
    all_merged_ids = [u.id for u in sampling.draw(units, alt, SEED, N, CAP)]
    data = {
        "note": (
            "Candidate package families for human review. Nothing here is applied. "
            "Set decision to merge or reject; merged groups are then copied into "
            "config/package_families.yaml. proposed: shared source repo -> merge, "
            "name pattern only -> pending."
        ),
        "snapshot": snapshots.load("github_advisory_database").commit,
        "families_config_sha256": sha256(FAMILIES),
        "sample_unchanged_if_all_proposed_merges_applied": all_merged_ids == chosen_ids,
        "groups": entries,
    }
    atomic_write_text(REVIEW, yaml.safe_dump(data, sort_keys=False, width=100))
    return data


def write_labels(chosen, mapping) -> None:
    if LABELS.exists():
        print(f"labels: {LABELS.relative_to(ROOT)} exists; not overwritten (human labels)")
        return
    rows = []
    for u in chosen:
        advs = u.advisories
        pkgs = sorted({p for a in advs for p in a.packages})
        meta = {p: pypi.fetch(p, PYPI_CACHE) for p in pkgs}
        proposed, reason = package_type.propose(advs[0], meta)
        row = dict.fromkeys(COLUMNS, "")
        row.update(
            ghsa_id=u.id,
            aliases="; ".join(
                sorted({x for a in advs for x in a.aliases} | {a.ghsa_id for a in advs[1:]})
            ),
            published=advs[0].published,
            package_family="; ".join(sorted(u.families(mapping))),
            packages="; ".join(pkgs),
            github_vulnerable_functions="[]",
            fix_commits="; ".join(dict.fromkeys(x for a in advs for x in a.fix_links)),
            package_type_proposed=proposed,
            package_type_reason=reason,
        )
        rows.append(row)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    atomic_write_text(LABELS, buf.getvalue())
    print(f"labels: wrote {LABELS.relative_to(ROOT)}")


def main() -> None:
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    pool = advisories.build_pool(SNAPSHOT_DIR)
    if len(pool) != EXPECTED_POOL:
        sys.exit(f"pool has {len(pool)} advisories, expected {EXPECTED_POOL}; stopping")
    mapping = families.load(FAMILIES)
    units = sampling.merge_by_cve(pool)
    chosen = sampling.draw(units, mapping, SEED, N, CAP)

    if SAMPLE.exists():
        if read_sample_ids(SAMPLE) != [u.id for u in chosen]:
            sys.exit(f"{SAMPLE.relative_to(ROOT)} exists with different IDs; not resampling")
        print(f"sample: {SAMPLE.relative_to(ROOT)} exists; fresh draw reproduces the same IDs")
    else:
        atomic_write_text(SAMPLE, sample_text(snap, pool, units, chosen, mapping))
        print(f"sample: wrote {SAMPLE.relative_to(ROOT)}")

    review = write_family_review(pool, units, mapping, chosen)
    write_labels(chosen, mapping)

    n_fams = len({f for u in units for f in u.families(mapping)})
    print(f"pool: {len(pool)} advisories; units: {len(units)}; families: {n_fams}")
    print(f"family review: {len(review['groups'])} groups -> {REVIEW.relative_to(ROOT)}")
    print(json.dumps({"seed": SEED, "snapshot": snap.commit}))


if __name__ == "__main__":
    main()
