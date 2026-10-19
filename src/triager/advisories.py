"""Read GHSA OSV records from the pinned github/advisory-database snapshot."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

POOL_START = "2025-01-01"

_COMMIT_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}\b")
_PULL_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/pull/\d+\b")


def normalise_name(name: str) -> str:
    """PEP 503 normalisation: lower-case, runs of -_. become a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class VersionRange:
    """One affected interval for one PyPI package (OSV ECOSYSTEM range)."""

    package: str  # normalised
    introduced: str  # "0" means from the beginning
    fixed: str | None
    last_affected: str | None  # OSV last_affected event or GHSA "<= X" range


def _ranges(affected: dict) -> list[VersionRange]:
    pkg = normalise_name(affected["package"]["name"])
    lkav = (affected.get("database_specific") or {}).get("last_known_affected_version_range", "")
    lkav_ver = lkav[2:].strip() if lkav.startswith("<=") else None
    out = []
    for r in affected.get("ranges", []):
        if r.get("type") != "ECOSYSTEM":
            continue
        introduced = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif introduced is not None and ("fixed" in ev or "last_affected" in ev):
                out.append(VersionRange(pkg, introduced, ev.get("fixed"), ev.get("last_affected")))
                introduced = None
        if introduced is not None:
            out.append(VersionRange(pkg, introduced, None, lkav_ver))
    return out


@dataclass(frozen=True)
class Advisory:
    ghsa_id: str
    aliases: tuple[str, ...]
    published: str
    withdrawn: str | None
    summary: str
    details: str
    packages: tuple[str, ...]  # PyPI only, normalised, sorted, unique
    references: tuple[str, ...]
    package_refs: tuple[str, ...] = ()  # references of OSV type PACKAGE (source repo)
    ranges: tuple[VersionRange, ...] = ()

    @property
    def cve_aliases(self) -> tuple[str, ...]:
        return tuple(a for a in self.aliases if a.startswith("CVE-"))

    @property
    def fix_links(self) -> list[str]:
        """GitHub commit and pull-request URLs from references, in order, deduplicated."""
        seen: dict[str, None] = {}
        for url in self.references:
            if _COMMIT_RE.match(url) or _PULL_RE.match(url):
                seen.setdefault(url, None)
        return list(seen)


def parse(record: dict) -> Advisory | None:
    """Return an Advisory if the record affects PyPI, else None."""
    pkgs = {
        normalise_name(a["package"]["name"])
        for a in record.get("affected", [])
        if a.get("package", {}).get("ecosystem") == "PyPI"
    }
    if not pkgs:
        return None
    return Advisory(
        ghsa_id=record["id"],
        aliases=tuple(record.get("aliases", [])),
        published=record.get("published", ""),
        withdrawn=record.get("withdrawn"),
        summary=record.get("summary", "") or "",
        details=record.get("details", "") or "",
        packages=tuple(sorted(pkgs)),
        references=tuple(r.get("url", "") for r in record.get("references", [])),
        package_refs=tuple(
            r.get("url", "") for r in record.get("references", []) if r.get("type") == "PACKAGE"
        ),
        ranges=tuple(
            vr
            for a in record.get("affected", [])
            if a.get("package", {}).get("ecosystem") == "PyPI"
            for vr in _ranges(a)
        ),
    )


def iter_pypi(snapshot_dir: Path) -> Iterator[Advisory]:
    for path in sorted((snapshot_dir / "advisories" / "github-reviewed").rglob("*.json")):
        adv = parse(json.loads(path.read_text()))
        if adv is not None:
            yield adv


def in_pool(adv: Advisory, start: str = POOL_START) -> bool:
    return adv.published[:10] >= start and not adv.withdrawn


def build_pool(snapshot_dir: Path, start: str = POOL_START) -> list[Advisory]:
    return sorted(
        (a for a in iter_pypi(snapshot_dir) if in_pool(a, start)), key=lambda a: a.ghsa_id
    )


def load_ids(snapshot_dir: Path, ids: list[str]) -> dict[str, Advisory]:
    """PyPI advisories for ``ids`` from the snapshot; raises KeyError if any is missing."""
    wanted = set(ids)
    out = {a.ghsa_id: a for a in iter_pypi(snapshot_dir) if a.ghsa_id in wanted}
    missing = sorted(wanted - set(out))
    if missing:
        raise KeyError(f"advisories missing from snapshot: {missing}")
    return out
