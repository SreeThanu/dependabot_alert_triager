"""GitHub global security advisories API: paged fetch with a raw-page disk cache.

The /advisories endpoint uses cursor pagination, so pages are followed through the
Link header's rel="next" URL rather than by page number. Each successful raw page is
cached under ``cache_dir`` keyed by the SHA-256 of its URL, together with the Link
header needed to continue, so a re-run replays the same pages without the network.

The token is only ever placed in the Authorization request header. It is never
written to the cache, to output files or to error messages.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from triager.fsutil import atomic_write_text

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
PER_PAGE = 100


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]  # lower-cased names
    body: bytes


Transport = Callable[[str, dict[str, str]], Response]


class GitHubAPIError(RuntimeError):
    pass


def urllib_transport(url: str, headers: dict[str, str]) -> Response:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return Response(
                resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
            )
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read())


def advisories_url(**params: str) -> str:
    query = {"per_page": str(PER_PAGE), **params}
    return f"{API_ROOT}/advisories?{urllib.parse.urlencode(query)}"


_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')


def parse_next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for url, rels in _LINK_RE.findall(link_header):
        if "next" in rels.split():
            return url
    return None


def cache_path(cache_dir: Path, url: str) -> Path:
    return cache_dir / f"{hashlib.sha256(url.encode()).hexdigest()}.json"


@dataclass
class FetchResult:
    advisories: list[dict[str, Any]] = field(default_factory=list)
    page_urls: list[str] = field(default_factory=list)
    pages_from_cache: int = 0
    pages_fetched: int = 0
    fetched_at: list[str] = field(default_factory=list)


def _request_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "dependabot-alert-triager",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(url: str, transport: Transport, token: str | None, retries: int, backoff: float):
    for attempt in range(retries + 1):
        resp = transport(url, _request_headers(token))
        if resp.status == 200:
            return resp
        if resp.status >= 500 and attempt < retries:
            time.sleep(backoff * 2**attempt)
            continue
        break
    # Never include request headers (token) in the message.
    detail = resp.body[:300].decode("utf-8", "replace")
    msg = f"GET {url} -> HTTP {resp.status}: {detail}"
    if resp.headers.get("x-ratelimit-remaining") == "0":
        reset = resp.headers.get("x-ratelimit-reset", "")
        if reset.isdigit():
            reset = datetime.fromtimestamp(int(reset), UTC).isoformat()
        msg += f" (rate limit exhausted; resets {reset}; cached pages will be reused on re-run)"
    raise GitHubAPIError(msg)


def fetch_all(
    start_url: str,
    *,
    cache_dir: Path,
    transport: Transport = urllib_transport,
    token: str | None = None,
    refresh: bool = False,
    max_pages: int = 1000,
    retries: int = 3,
    backoff: float = 2.0,
) -> FetchResult:
    """Follow rel="next" links from ``start_url``, caching each raw page."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    result = FetchResult()
    url: str | None = start_url
    while url is not None:
        if len(result.page_urls) >= max_pages:
            raise GitHubAPIError(f"more than {max_pages} pages from {start_url}")
        if url in result.page_urls:
            raise GitHubAPIError(f"pagination loop at {url}")
        path = cache_path(cache_dir, url)
        if path.exists() and not refresh:
            page = json.loads(path.read_text())
            result.pages_from_cache += 1
        else:
            resp = _get(url, transport, token, retries, backoff)
            page = {
                "url": url,
                "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "status": resp.status,
                "link": resp.headers.get("link"),
                "body": json.loads(resp.body),
            }
            atomic_write_text(path, json.dumps(page))
            result.pages_fetched += 1
        result.page_urls.append(url)
        result.fetched_at.append(page["fetched_at"])
        result.advisories.extend(page["body"])
        url = parse_next_link(page["link"])
    return result


def vulnerable_functions(advisory: dict[str, Any], ecosystem: str = "pip") -> dict[str, list[str]]:
    """Non-empty ``vulnerable_functions`` per package, for one ecosystem only."""
    out: dict[str, list[str]] = {}
    for vuln in advisory.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        funcs = vuln.get("vulnerable_functions") or []
        if pkg.get("ecosystem") == ecosystem and funcs:
            out.setdefault(pkg.get("name", ""), []).extend(funcs)
    return out


def summarise(
    advisories: Iterable[dict[str, Any]], start: str | None, end: str | None
) -> dict[str, Any]:
    """Count advisories and those with pip ``vulnerable_functions``.

    ``start``/``end`` are inclusive ISO dates used only as a sanity check that the
    API's ``published`` filter returned what was asked for.
    """
    advisories = list(advisories)
    ids = [a["ghsa_id"] for a in advisories]

    def in_window(a: dict[str, Any]) -> bool:
        day = (a.get("published_at") or "")[:10]
        return (start is None or day >= start) and (end is None or day <= end)

    with_vf = []
    for a in advisories:
        vf = vulnerable_functions(a)
        if vf:
            with_vf.append(
                {
                    "ghsa_id": a["ghsa_id"],
                    "published_at": a.get("published_at"),
                    "withdrawn": a.get("withdrawn_at") is not None,
                    "vulnerable_functions": vf,
                }
            )
    entries = [v for a in advisories for v in a.get("vulnerabilities") or []]
    return {
        "advisories": len(advisories),
        # Distinguishes "field returned but empty" from "field not returned at all".
        "vulnerability_entries_all_ecosystems": len(entries),
        "entries_with_vulnerable_functions_key": sum("vulnerable_functions" in v for v in entries),
        "entries_with_nonempty_vulnerable_functions": sum(
            bool(v.get("vulnerable_functions")) for v in entries
        ),
        "unique_ids": len(set(ids)),
        "withdrawn": sum(a.get("withdrawn_at") is not None for a in advisories),
        "published_outside_window": sum(not in_window(a) for a in advisories),
        "with_vulnerable_functions": len(with_vf),
        "with_vulnerable_functions_not_withdrawn": sum(not v["withdrawn"] for v in with_vf),
        "advisories_with_vulnerable_functions": sorted(with_vf, key=lambda v: v["ghsa_id"]),
    }
