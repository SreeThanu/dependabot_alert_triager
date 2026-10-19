from collections import Counter
from pathlib import Path

import pytest

from helpers import adv
from triager import advisories, families, sampling, snapshots
from triager.families import family_of

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "validation" / "sample_v1.txt"
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"


def test_alias_merge_is_transitive_and_ignores_non_cve_aliases():
    pool = [
        adv("GHSA-a", ["p1"], ["CVE-2025-1"]),
        adv("GHSA-b", ["p2"], ["CVE-2025-1", "CVE-2025-2"]),
        adv("GHSA-c", ["p3"], ["CVE-2025-2"]),
        adv("GHSA-d", ["p4"], ["PYSEC-2025-9"]),
        adv("GHSA-e", ["p5"], ["PYSEC-2025-9"]),
    ]
    units = sampling.merge_by_cve(pool)
    assert [[a.ghsa_id for a in u.advisories] for u in units] == [
        ["GHSA-a", "GHSA-b", "GHSA-c"],
        ["GHSA-d"],
        ["GHSA-e"],
    ]
    assert units[0].id == "GHSA-a"


def _synthetic_units():
    pool = [adv(f"GHSA-{i:04d}", [f"pkg{i % 30}"]) for i in range(300)]
    pool += [adv("GHSA-tf-1", ["tensorflow"]), adv("GHSA-tf-2", ["tensorflow-gpu"])]
    pool += [adv("GHSA-tf-3", ["tensorflow-cpu"])]
    return sampling.merge_by_cve(pool)


def test_draw_is_deterministic_and_respects_cap():
    units = _synthetic_units()
    mapping = {"tensorflow": "tf", "tensorflow-gpu": "tf", "tensorflow-cpu": "tf"}
    a = sampling.draw(units, mapping, seed=7, n=50, cap=2)
    b = sampling.draw(list(reversed(units)), mapping, seed=7, n=50, cap=2)
    assert [u.id for u in a] == [u.id for u in b]
    counts = Counter(f for u in a for f in u.families(mapping))
    assert max(counts.values()) <= 2
    assert counts["tf"] <= 2
    assert [u.id for u in sampling.draw(units, mapping, seed=8, n=50, cap=2)] != [u.id for u in a]


def test_draw_fails_when_cap_makes_n_impossible():
    units = sampling.merge_by_cve([adv(f"GHSA-{i}", ["one-pkg"]) for i in range(10)])
    with pytest.raises(ValueError, match="only 2 units"):
        sampling.draw(units, {}, seed=1, n=5, cap=2)


def _header(key):
    for line in SAMPLE.read_text().splitlines():
        if line.startswith(f"# {key}:"):
            return line.split(":", 1)[1].strip()
    raise KeyError(key)


@pytest.mark.skipif(
    not (SNAPSHOT_DIR / ".git").exists() or not SAMPLE.exists(),
    reason="needs the pinned snapshot (scripts/fetch_snapshot.py) and sample_v1.txt",
)
def test_sample_v1_reproduces_from_pinned_snapshot():
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    assert snap.commit in _header("snapshot")
    seed = int(_header("seed"))
    mapping = families.load(ROOT / "config" / "package_families.yaml")
    pool = advisories.build_pool(SNAPSHOT_DIR)
    chosen = sampling.draw(sampling.merge_by_cve(pool), mapping, seed, n=50, cap=2)
    expected = [ln.split()[0] for ln in SAMPLE.read_text().splitlines() if ln and ln[0] != "#"]
    assert [u.id for u in chosen] == expected
    assert len(set(expected)) == 50
    counts = Counter(f for u in chosen for f in u.families(mapping))
    assert max(counts.values()) <= 2
    assert all(family_of(p, mapping) for u in chosen for a in u.advisories for p in a.packages)


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample_v1.txt not present")
def test_sample_v1_has_50_unique_ghsa_ids():
    ids = [ln.split()[0] for ln in SAMPLE.read_text().splitlines() if ln and ln[0] != "#"]
    assert len(ids) == 50
    assert len(set(ids)) == 50, [i for i in ids if ids.count(i) > 1]
    assert all(i.startswith("GHSA-") for i in ids)
