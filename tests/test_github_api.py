import json
from pathlib import Path

import pytest

from triager.sources.github_api import (
    GitHubAPIError,
    Response,
    advisories_url,
    cache_path,
    fetch_all,
    parse_next_link,
    summarise,
)

FIXTURES = Path(__file__).parent / "fixtures" / "github_advisories"
TOKEN = "ghp_TEST_TOKEN_must_not_leak"
START = advisories_url(ecosystem="pip", type="reviewed", published=">=2025-01-01")
PAGE2 = START + "&after=Y3Vyc29yOnYyOpK0"


class FakeTransport:
    """Serves the two recorded pages; page 1 links to page 2 via cursor."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        if url == START:
            link = f'<{PAGE2}>; rel="next", <{START}>; rel="first"'
            return Response(200, {"link": link}, (FIXTURES / "page1.json").read_bytes())
        if url == PAGE2:
            return Response(
                200, {"link": f'<{START}>; rel="first"'}, (FIXTURES / "page2.json").read_bytes()
            )
        raise AssertionError(f"unexpected URL {url}")


def test_parse_next_link():
    assert parse_next_link(None) is None
    assert parse_next_link('<https://x/a>; rel="prev"') is None
    assert parse_next_link('<https://x/a>; rel="prev", <https://x/b>; rel="next"') == "https://x/b"


def test_query_url_is_exact():
    assert START == (
        "https://api.github.com/advisories?per_page=100&ecosystem=pip"
        "&type=reviewed&published=%3E%3D2025-01-01"
    )


def test_follows_cursor_pages_and_counts(tmp_path):
    transport = FakeTransport()
    res = fetch_all(START, cache_dir=tmp_path, transport=transport, token=TOKEN)

    assert res.page_urls == [START, PAGE2]
    assert res.pages_fetched == 2 and res.pages_from_cache == 0
    assert [a["ghsa_id"] for a in res.advisories] == [
        "GHSA-aaaa-aaaa-aaaa",
        "GHSA-bbbb-bbbb-bbbb",
        "GHSA-cccc-cccc-cccc",
        "GHSA-dddd-dddd-dddd",
    ]
    assert all(h["Authorization"] == f"Bearer {TOKEN}" for _, h in transport.calls)

    s = summarise(res.advisories, "2025-01-01", None)
    assert s["advisories"] == 4 and s["unique_ids"] == 4
    assert s["withdrawn"] == 1
    assert s["vulnerability_entries_all_ecosystems"] == 5
    assert s["entries_with_vulnerable_functions_key"] == 5
    assert s["entries_with_nonempty_vulnerable_functions"] == 3  # includes the npm entry
    assert s["published_outside_window"] == 1  # GHSA-dddd published 2024-12-31
    # npm-only vulnerable_functions (GHSA-dddd) and empty list (GHSA-bbbb) do not count.
    assert s["with_vulnerable_functions"] == 2
    assert s["with_vulnerable_functions_not_withdrawn"] == 1
    assert s["advisories_with_vulnerable_functions"] == [
        {
            "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
            "published_at": "2025-03-01T12:00:00Z",
            "withdrawn": False,
            "vulnerable_functions": {"pypdf": ["pypdf.filters.FlateDecode.decode"]},
        },
        {
            "ghsa_id": "GHSA-cccc-cccc-cccc",
            "published_at": "2025-05-01T12:00:00Z",
            "withdrawn": True,
            "vulnerable_functions": {"otherlib": ["otherlib.parse"]},
        },
    ]


def test_cache_replays_without_network_and_holds_no_token(tmp_path):
    fetch_all(START, cache_dir=tmp_path, transport=FakeTransport(), token=TOKEN)
    for p in tmp_path.iterdir():
        assert TOKEN not in p.read_text()
    assert json.loads(cache_path(tmp_path, START).read_text())["url"] == START

    def no_network(url, headers):
        raise AssertionError("network used despite cache")

    res = fetch_all(START, cache_dir=tmp_path, transport=no_network)
    assert res.pages_from_cache == 2 and res.pages_fetched == 0
    assert len(res.advisories) == 4


def test_error_is_not_cached_and_does_not_leak_token(tmp_path):
    def rate_limited(url, headers):
        return Response(
            403,
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"},
            b'{"message": "API rate limit exceeded"}',
        )

    with pytest.raises(GitHubAPIError) as exc:
        fetch_all(START, cache_dir=tmp_path, transport=rate_limited, token=TOKEN)
    assert "rate limit exhausted" in str(exc.value)
    assert TOKEN not in str(exc.value)
    assert list(tmp_path.iterdir()) == []
