"""Package families: confirmed mapping from config, plus candidate detection.

Only families listed in config/package_families.yaml are merged. Detected
candidates are reported for a human to confirm; they are never merged silently.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from triager.advisories import Advisory, normalise_name

# Suffixes that usually mark a variant build or sub-distribution of the same project.
VARIANT_SUFFIXES = (
    "cpu", "gpu", "core", "platform", "agents", "agent", "intel", "macos", "aarch64",
    "nightly", "sdk", "lib", "client", "server", "cli", "api", "ng", "slim", "lite", "headless",
)  # fmt: skip


def load(path: Path) -> dict[str, str]:
    """Return {normalised package name: family}."""
    data = yaml.safe_load(path.read_text()) or {}
    mapping: dict[str, str] = {}
    for family, members in (data.get("families") or {}).items():
        for m in members:
            name = normalise_name(m)
            if name in mapping and mapping[name] != family:
                raise ValueError(f"{name} is in families {mapping[name]} and {family}")
            mapping[name] = family
    return mapping


def family_of(package: str, mapping: dict[str, str]) -> str:
    name = normalise_name(package)
    return mapping.get(name, name)


_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)")


def repos_by_package(advisories: Iterable[Advisory]) -> dict[str, set[str]]:
    """GitHub ``owner/repo`` source repos per package, from OSV ``PACKAGE`` references.

    Only advisories naming a single PyPI package are used, so a repo is not
    attributed to an unrelated co-listed package.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for a in advisories:
        if len(a.packages) != 1:
            continue
        for url in a.package_refs:
            m = _REPO_RE.match(url)
            if m:
                out[a.packages[0]].add(f"{m.group(1)}/{m.group(2)}".lower().removesuffix(".git"))
    return out


def detect_shared_repo(
    repos: dict[str, set[str]], mapping: dict[str, str], min_share: int = 1
) -> dict[str, list[str]]:
    """Packages whose advisories reference the same GitHub repo."""
    by_repo: dict[str, set[str]] = defaultdict(set)
    for pkg, rs in repos.items():
        for r in rs:
            by_repo[r].add(pkg)
    return {
        r: sorted(ps)
        for r, ps in sorted(by_repo.items())
        if len(ps) > min_share and len({family_of(p, mapping) for p in ps}) > 1
    }


def detect_candidates(names: Iterable[str], mapping: dict[str, str]) -> dict[str, list[str]]:
    """Propose families among ``names`` that are not already grouped by ``mapping``.

    Two rules, both reported, neither applied:
    - prefix: another package name P is a prefix of Q and the rest of Q starts with '-'
      or is a known variant suffix (``praisonai`` -> ``praisonai-platform``, ``praisonaiagents``);
    - suffix siblings: names that reduce to the same base after stripping a variant suffix,
      even when the base itself is absent (``foo-cpu`` + ``foo-gpu``).
    """
    names = sorted({normalise_name(n) for n in names})
    groups: dict[str, set[str]] = defaultdict(set)
    for p in names:
        if len(p) < 4:
            continue
        for q in names:
            if q == p or not q.startswith(p):
                continue
            rest = q[len(p) :]
            if rest.startswith("-") or rest in VARIANT_SUFFIXES:
                groups[p].update({p, q})
    for q in names:
        for suf in VARIANT_SUFFIXES:
            for sep in ("-", ""):
                tail = sep + suf
                if not q.endswith(tail):
                    continue
                base = q[: -len(tail)].rstrip("-")
                if len(base) >= 3:
                    groups[base].add(q)
    # Keep groups with >= 2 members that are not already one confirmed family.
    out: dict[str, list[str]] = {}
    for base, members in groups.items():
        members = {m for m in members if m in names}
        if len(members) < 2:
            continue
        if len({family_of(m, mapping) for m in members}) == 1:
            continue
        out[base] = sorted(members)
    # Drop groups wholly contained in a larger group.
    return {
        b: m
        for b, m in sorted(out.items())
        if not any(b2 != b and set(m) < set(m2) for b2, m2 in out.items())
    }


def build_review(
    repo_groups: dict[str, list[str]], name_groups: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """One review entry per candidate group, decision always "pending".

    Shared-source-repo groups are proposed for merging. A name-pattern group whose
    members all sit inside one repo group is folded into that entry as extra
    evidence; any other name-pattern group is its own entry, proposed "pending".
    """
    entries: list[dict[str, Any]] = []
    for repo, members in repo_groups.items():
        entries.append(
            {
                "id": f"repo:{repo}",
                "members": members,
                "evidence": [f"shared_source_repo: {repo}"],
                "proposed": "merge",
                "decision": "pending",
            }
        )
    for base, members in name_groups.items():
        home = next((e for e in entries if set(members) <= set(e["members"])), None)
        if home is not None:
            home["evidence"].append(f"name_pattern: {base}")
            continue
        entries.append(
            {
                "id": f"name:{base}",
                "members": members,
                "evidence": [f"name_pattern: {base}"],
                "proposed": "pending",
                "decision": "pending",
            }
        )
    for e in entries:
        others = sorted(
            o["id"] for o in entries if o is not e and set(o["members"]) & set(e["members"])
        )
        e["overlaps"] = others
    return entries


def with_groups(mapping: dict[str, str], groups: Iterable[list[str]]) -> dict[str, str]:
    """Return a copy of ``mapping`` with each group merged into one family.

    The family name is the existing family of the first member that has one,
    else the first member. Groups that touch each other are merged transitively.
    """
    out = dict(mapping)
    for members in groups:
        names = [normalise_name(m) for m in members]
        fams = {out.get(n, n) for n in names}
        target = next((out[n] for n in names if n in out), names[0])
        for pkg, fam in list(out.items()):
            if fam in fams:
                out[pkg] = target
        for n in names:
            out[n] = target
    return out
