"""PyPI JSON API metadata with a disk cache.

This is live metadata (not pinned); it feeds only helper columns that a human checks.
"""

from __future__ import annotations

import json
import time
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from triager.fsutil import atomic_write_text
from triager.sources.github_api import Transport, urllib_transport

PYPI_ROOT = "https://pypi.org/pypi"


def fetch(
    name: str, cache_dir: Path, transport: Transport = urllib_transport, retries: int = 3
) -> dict[str, Any]:
    """Return {"name", "fetched_at", "status", "info"}; ``info`` is None when not found."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text())
    url = f"{PYPI_ROOT}/{name}/json"
    for attempt in range(retries + 1):
        try:
            resp = transport(url, {"User-Agent": "dependabot-alert-triager"})
            break
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries:
                raise
            time.sleep(2**attempt)
    if resp.status not in (200, 404):
        raise RuntimeError(f"PyPI {name}: HTTP {resp.status}")
    info = None
    if resp.status == 200:
        full = json.loads(resp.body)["info"]
        keep = ("name", "summary", "classifiers", "keywords", "project_urls", "home_page")
        info = {k: full.get(k) for k in keep}
    record = {
        "name": name,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "status": resp.status,
        "info": info,
    }
    atomic_write_text(path, json.dumps(record))
    return record
