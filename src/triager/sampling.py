"""Capped random sample over alias-merged advisory units (plan §2.1).

Units: advisories that share a CVE alias are merged (union-find) and drawn as one.
Draw: units are sorted by id, shuffled with ``random.Random(seed)``, then accepted in
order while every family they touch has fewer than ``cap`` accepted units. The result
depends only on the pool, the family mapping, the seed, ``n`` and ``cap``.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass

from triager.advisories import Advisory
from triager.families import family_of


@dataclass(frozen=True)
class Unit:
    advisories: tuple[Advisory, ...]  # sorted by ghsa_id; [0] is the representative

    @property
    def id(self) -> str:
        return self.advisories[0].ghsa_id

    def families(self, mapping: dict[str, str]) -> frozenset[str]:
        return frozenset(family_of(p, mapping) for a in self.advisories for p in a.packages)


def merge_by_cve(pool: list[Advisory]) -> list[Unit]:
    parent = {a.ghsa_id: a.ghsa_id for a in pool}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_with_cve: dict[str, str] = {}
    for a in pool:
        for cve in a.cve_aliases:
            if cve in first_with_cve:
                parent[find(a.ghsa_id)] = find(first_with_cve[cve])
            else:
                first_with_cve[cve] = a.ghsa_id
    groups: dict[str, list[Advisory]] = {}
    for a in pool:
        groups.setdefault(find(a.ghsa_id), []).append(a)
    units = [Unit(tuple(sorted(g, key=lambda a: a.ghsa_id))) for g in groups.values()]
    return sorted(units, key=lambda u: u.id)


def draw(
    units: list[Unit], mapping: dict[str, str], seed: int, n: int = 50, cap: int = 2
) -> list[Unit]:
    order = sorted(units, key=lambda u: u.id)
    random.Random(seed).shuffle(order)
    counts: Counter[str] = Counter()
    chosen: list[Unit] = []
    for u in order:
        fams = u.families(mapping)
        if all(counts[f] < cap for f in fams):
            chosen.append(u)
            counts.update(fams)
            if len(chosen) == n:
                break
    if len(chosen) < n:
        raise ValueError(f"only {len(chosen)} units satisfy the cap of {cap} per family")
    return chosen
