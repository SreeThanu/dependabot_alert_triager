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
