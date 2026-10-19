import subprocess

import pytest

from helpers import adv
from triager import fixcommit as fc
from triager.advisories import VersionRange

GHSA = "GHSA-aaaa-bbbb-cccc"
SLUG = "owner/pkg"
PYPI = {"pkg": {"project_urls": {"Source": "https://github.com/Owner/pkg"}, "home_page": None}}


def _git(cwd, *args):
    return subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


def _commit(repo, files, msg):
    for path, text in files.items():
        f = repo / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        _git(repo, "add", path)
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    """History: old -> [v0.9.0] -> base -> [v1.0.0 affected] -> fix, testonly -> [v1.0.1]
    -> after.  Also a 1.1.0rc1 tag (pre-release) and an unrelated other-pkg-5.0 tag."""
    r = tmp_path / "work"
    r.mkdir()
    _git(r, "init", "-q")
    shas = {"old": _commit(r, {"src/pkg/mod.py": "0"}, "old")}
    _git(r, "tag", "v0.9.0")
    shas["base"] = _commit(r, {"src/pkg/mod.py": "1"}, "base")
    _git(r, "tag", "v1.0.0")
    shas["fix"] = _commit(
        r, {"src/pkg/mod.py": "2", "tests/test_mod.py": "t"}, f"Fix path traversal ({GHSA})"
    )
    shas["testonly"] = _commit(r, {"tests/test_more.py": "t", "docs/x.md": "d"}, "tests")
    _git(r, "tag", "-a", "v1.0.1", "-m", "release")
    shas["after"] = _commit(r, {"src/pkg/mod.py": "3"}, "after")
    _git(r, "tag", "1.1.0rc1")
    _git(r, "tag", "other-pkg-5.0")
    return r, shas


@pytest.fixture
def clones(tmp_path, repo):
    """A repos root where owner/pkg is already 'cloned' (bare), so no network is used."""
    work, _ = repo
    root = tmp_path / "repos"
    root.mkdir()
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(fc.clone_dir(root, SLUG))], check=True
    )
    return root


RANGE = VersionRange("pkg", "0", "1.0.1", None)


def _verify(work, sha, ranges=(RANGE,)):
    a = adv(GHSA, ["pkg"], ranges=ranges)
    cand = fc.Candidate(GHSA, "reference", SLUG, sha, "link")
    return fc.verify(cand, work, a, PYPI)


# --- containment checks --------------------------------------------------------------


def test_fix_commit_passes_all_checks(repo):
    work, shas = repo
    c = _verify(work, shas["fix"])
    assert c.checks == dict.fromkeys(fc.CHECKS, fc.PASS)
    assert (c.fixed_tag, c.last_affected_tag) == ("v1.0.1", "v1.0.0")
    assert c.verified
    assert c.files_of("source") == ["src/pkg/mod.py"]
    assert c.files_of("test") == ["tests/test_mod.py"]


def test_commit_after_fixed_tag_fails_containment(repo):
    work, shas = repo
    c = _verify(work, shas["after"])
    assert c.checks["in_fixed_tag"] == fc.FAIL
    assert not c.verified


def test_commit_already_in_last_affected_tag_fails(repo):
    work, shas = repo
    c = _verify(work, shas["base"])
    assert c.checks["in_fixed_tag"] == fc.PASS
    assert c.checks["not_in_affected_tag"] == fc.FAIL


def test_last_affected_respects_introduced(repo):
    work, shas = repo
    # Range introduced at 0.9.0: last affected is still v1.0.0, so 'old' (in v0.9.0) fails.
    c = _verify(work, shas["old"], ranges=(VersionRange("pkg", "0.9.0", "1.0.1", None),))
    assert c.checks["not_in_affected_tag"] == fc.FAIL


def test_missing_fixed_tag_is_unknown_not_fail(repo):
    work, shas = repo
    c = _verify(work, shas["fix"], ranges=(VersionRange("pkg", "0", "9.9.9", None),))
    assert c.checks["in_fixed_tag"] == fc.UNKNOWN
    assert "no tag for fixed 9.9.9" in "; ".join(c.details)
    assert not c.verified


def test_no_fixed_version_is_unknown(repo):
    work, shas = repo
    c = _verify(work, shas["fix"], ranges=(VersionRange("pkg", "0", None, "1.0.0"),))
    assert c.checks["in_fixed_tag"] == fc.UNKNOWN


# --- source-file filter --------------------------------------------------------------


def test_test_and_doc_only_commit_fails_source_check(repo):
    work, shas = repo
    c = _verify(work, shas["testonly"])
    assert c.checks["changes_src"] == fc.FAIL
    assert sorted(c.files) == ["docs/x.md", "tests/test_more.py"]


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("src/pkg/mod.py", "source"),
        ("pkg/_native/parse.c", "source"),
        ("frontend/src/lib/Chat.svelte", "source"),
        ("tests/test_mod.py", "test"),
        ("pkg/tests/helpers.py", "test"),
        ("pkg/test_utils.py", "test"),
        ("conftest.py", "test"),
        ("web/app.spec.ts", "test"),
        ("docs/security.rst", "doc"),
        ("CHANGELOG.md", "doc"),
        ("newsfragments/123.bugfix", "doc"),
        (".github/workflows/ci.yml", "other"),
        ("setup.py", "other"),
        ("pyproject.toml", "other"),
    ],
)
def test_classify(path, kind):
    assert fc.classify(path) == kind


# --- repo check, versions, URLs ---------------------------------------------------------


def test_repo_check_against_pypi(repo):
    work, shas = repo
    assert _verify(work, shas["fix"]).checks["repo_matches_pypi"] == fc.PASS
    a = adv(GHSA, ["pkg"], ranges=(RANGE,))
    other = fc.verify(fc.Candidate(GHSA, "reference", "fork/pkg", shas["fix"], "l"), work, a, PYPI)
    assert other.checks["repo_matches_pypi"] == fc.FAIL
    none = fc.verify(fc.Candidate(GHSA, "reference", SLUG, shas["fix"], "l"), work, a, {})
    assert none.checks["repo_matches_pypi"] == fc.UNKNOWN


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("v1.2.3", (1, 2, 3)),
        ("1.2.0", (1, 2)),
        ("pkg-1.2.3", (1, 2, 3)),
        ("pkg==0.3.1", (0, 3, 1)),
        ("pkg/v2.0", (2,)),
        ("release-4.1", (4, 1)),
        ("other-pkg-5.0", None),
        ("nightly", None),
    ],
)
def test_tag_version(tag, expected):
    v = fc.tag_version(tag, ["pkg"])
    assert (v.release if v else None) == expected


def test_prerelease_is_not_stable_and_orders_before_final():
    rc, final = fc.parse_version("1.1.0rc1"), fc.parse_version("1.1.0")
    assert not rc.stable and final.stable and rc < final


def test_url_parsing():
    assert fc.parse_commit_url("https://github.com/Owner/Pkg/commit/ABCDEF1234567#diff-1") == (
        "owner/pkg",
        "abcdef1234567",
    )
    assert fc.parse_commit_url("https://github.com/o/r/pull/12/commits/" + "a" * 40) == (
        "o/r",
        "a" * 40,
    )
    assert fc.parse_pr_url("https://github.com/o/r/pull/12") == ("o/r", 12)
    assert fc.parse_pr_url("https://github.com/o/r/pull/12/commits/" + "a" * 40) is None


# --- end-to-end resolve on the local fixture (no network) --------------------------------


def _no_pr(repo_slug, number):
    raise AssertionError("PR lookup should not be needed")


def test_resolve_reference_stage(clones, repo):
    _, shas = repo
    a = adv(GHSA, ["pkg"], references=[f"https://github.com/owner/pkg/commit/{shas['fix']}"],
            ranges=(RANGE,))  # fmt: skip
    res = fc.resolve(a, PYPI, clones, _no_pr)
    assert res.source == "reference"
    assert [c.sha for c in res.verified] == [shas["fix"]]
    assert res.stages_tried == ["reference"]


def test_resolve_falls_back_to_pr_then_tag_diff(clones, repo):
    _, shas = repo
    a = adv(
        GHSA,
        ["pkg"],
        references=[
            f"https://github.com/owner/pkg/commit/{shas['testonly']}",  # fails changes_src
            "https://github.com/owner/pkg/pull/7",
        ],
        package_refs=["https://github.com/owner/pkg"],
        ranges=(RANGE,),
    )
    res = fc.resolve(a, PYPI, clones, lambda s, n: (None, "not merged"))
    assert res.stages_tried == ["reference", "pr_merge", "tag_diff_inferred"]
    assert res.source == "tag_diff_inferred"
    assert [c.sha for c in res.verified] == [shas["fix"]]  # found via GHSA id in message
    assert any("not merged" in e for e in res.errors)


def test_resolve_pr_stage(clones, repo):
    _, shas = repo
    a = adv(GHSA, ["pkg"], references=["https://github.com/owner/pkg/pull/7"], ranges=(RANGE,))
    res = fc.resolve(a, PYPI, clones, lambda s, n: (shas["fix"], "merged"))
    assert res.source == "pr_merge"


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("REL-9_2", (9, 2)),
        ("openbabel-3-1-1", (3, 1, 1)),
        ("v0.22.2+canary.20261019T071120Z", (0, 22, 2)),
    ],
)
def test_tag_version_other_schemes(tag, expected):
    assert fc.tag_version(tag, ["openbabel", "pgadmin4"]).release == expected


def test_local_version_is_not_stable_or_equal_to_release():
    canary, final = fc.parse_version("0.22.2+canary.1"), fc.parse_version("0.22.2")
    assert not canary.stable and canary != final


def test_renamed_repo_passes_only_when_both_names_resolve_to_same_repo(repo):
    work, shas = repo
    a = adv(GHSA, ["pkg"], ranges=(RANGE,))
    cand = fc.Candidate(GHSA, "reference", "oldowner/pkg", shas["fix"], "l")
    moved = {"oldowner/pkg": "owner/pkg", "owner/pkg": "owner/pkg"}
    c = fc.verify(cand, work, a, PYPI, canonical=moved.get)
    assert c.checks["repo_matches_pypi"] == fc.PASS
    assert "repo renamed" in c.details[0]
    cand2 = fc.Candidate(GHSA, "reference", "fork/pkg", shas["fix"], "l")
    forked = {"fork/pkg": "fork/pkg", "owner/pkg": "owner/pkg"}
    assert (
        fc.verify(cand2, work, a, PYPI, canonical=forked.get).checks["repo_matches_pypi"] == fc.FAIL
    )


# --- manual candidates ---------------------------------------------------------------


def test_manual_candidate_verifies_when_automated_stages_find_nothing(clones, repo):
    _, shas = repo
    a = adv("GHSA-zzzz-zzzz-zzzz", ["pkg"], ranges=(RANGE,))  # no links, no id in messages
    url = f"https://github.com/owner/pkg/commit/{shas['fix']}"
    res = fc.resolve(a, PYPI, clones, _no_pr, manual=[(url, "read the changelog")])
    assert res.source == "manual"
    assert res.stages_tried == ["tag_diff_inferred", "manual"]
    [m] = [c for c in res.candidates if c.source == "manual"]
    assert m.verified and "how_found: read the changelog" in m.details


def test_manual_candidate_is_checked_but_automated_source_wins(clones, repo):
    _, shas = repo
    a = adv(GHSA, ["pkg"], references=[f"https://github.com/owner/pkg/commit/{shas['fix']}"],
            ranges=(RANGE,))  # fmt: skip
    manual = [
        (f"https://github.com/owner/pkg/commit/{shas['after']}", "guess"),
        (f"https://github.com/owner/pkg/commit/{shas['fix'][:12]}", "same as reference"),
        ("https://example.com/not-a-commit", "typo"),
    ]
    res = fc.resolve(a, PYPI, clones, _no_pr, manual=manual)
    assert res.source == "reference"
    [m] = [c for c in res.candidates if c.source == "manual"]
    assert m.checks["in_fixed_tag"] == fc.FAIL  # 'after' is past the fixed tag
    assert any("already checked as reference" in e for e in res.errors)
    assert any("not a GitHub commit URL" in e for e in res.errors)
