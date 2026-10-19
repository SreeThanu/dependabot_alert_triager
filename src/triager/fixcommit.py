"""Fix-commit resolution and verification (plan §2.3, task T3).

Resolution order per advisory, falling through only when the earlier stage yields
no verified commit:

  (a) ``reference``          commit URLs in the advisory references;
  (b) ``pr_merge``           PR URLs in references -> merge commit (GitHub API);
  (c) ``tag_diff_inferred``  commits between the last affected and first fixed tags
                             whose message names the GHSA or a CVE id (lower trust);
  (d) ``manual``             commit URLs supplied by a human in
                             data/validation/manual_fix_candidates.csv. Always checked;
                             they set the source only if (a)-(c) verified nothing.

Each candidate gets four checks, each ``pass`` / ``fail`` / ``unknown``:

  repo_matches_pypi      the commit's repo is a GitHub repo listed on the PyPI project;
  in_fixed_tag           the commit is an ancestor of the first fixed release tag;
  not_in_affected_tag    the commit is not an ancestor of the last affected release tag;
  changes_src            the commit changes at least one non-test, non-doc source file.

A candidate is verified only if all four pass. ``unknown`` (e.g. no tag found for
a version) is not a pass.

Known limits: "source file" is any code file outside test/doc paths anywhere in the
repo, not only inside the affected package's directory (matters for monorepos).
Tag/version matching is a small PEP 440 subset; tags that do not parse are ignored.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from triager.advisories import Advisory, VersionRange

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"

_COMMIT_URL_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/#?]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})\b", re.I
)
_PR_URL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)/pull/(\d+)/?(?:[#?].*)?$", re.I)
_GH_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)


def slug(owner: str, repo: str) -> str:
    return f"{owner}/{repo}".lower().removesuffix(".git")


def parse_commit_url(url: str) -> tuple[str, str] | None:
    m = _COMMIT_URL_RE.match(url)
    return (slug(m.group(1), m.group(2)), m.group(3).lower()) if m else None


def parse_pr_url(url: str) -> tuple[str, int] | None:
    m = _PR_URL_RE.match(url)
    return (slug(m.group(1), m.group(2)), int(m.group(3))) if m else None


def github_slugs(urls: Iterable[str | None]) -> set[str]:
    out = set()
    for u in urls:
        m = _GH_RE.search(u or "")
        if m and m.group(1).lower() not in ("sponsors", "orgs"):
            out.add(slug(m.group(1), m.group(2)))
    return out


def pypi_repos(pypi_info: dict | None) -> set[str]:
    if not pypi_info:
        return set()
    urls = list((pypi_info.get("project_urls") or {}).values()) + [pypi_info.get("home_page")]
    return github_slugs(urls)


# --- versions and tags -------------------------------------------------------------

_VER_RE = re.compile(
    r"^(\d+(?:[._-]\d+)*)"  # release; '_' and '-' separators seen in REL-9_2, pkg-3-1-1
    r"(?:[-_.]?(dev|a|alpha|b|beta|c|rc|pre|preview|post)[-_.]?(\d*))?"
    r"(?:\+([a-z0-9.]+))?$",  # PEP 440 local version, e.g. +canary.2026...
    re.I,
)
_PHASE = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3,
          "preview": 3, None: 4, "post": 5}  # fmt: skip


@dataclass(frozen=True, order=True)
class Version:
    release: tuple[int, ...]  # trailing zeros trimmed: 1.2 == 1.2.0
    phase: int
    num: int
    local: str = ""

    @property
    def stable(self) -> bool:
        return self.phase >= 4 and not self.local


def parse_version(text: str) -> Version | None:
    m = _VER_RE.match(text.strip().lower().removeprefix("v"))
    if not m:
        return None
    rel = [int(x) for x in re.split(r"[._-]", m.group(1))]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    phase = m.group(2).lower() if m.group(2) else None
    return Version(tuple(rel), _PHASE[phase], int(m.group(3) or 0), (m.group(4) or "").lower())


def tag_version(tag: str, names: Iterable[str]) -> Version | None:
    """Version encoded in ``tag`` for a package known by ``names``, else None.

    Accepts ``1.2.3``, ``v1.2.3``, ``<name><sep>1.2.3`` (sep in -_/@=, optional v) and
    ``release-1.2.3``. A tag prefixed with some other package's name does not parse.
    """
    t = tag.lower()
    variants = set()
    for n in names:
        variants |= {n, n.replace("-", "_"), n.replace("-", "")}
    for n in sorted(variants, key=len, reverse=True):
        if t.startswith(n) and len(t) > len(n) and t[len(n)] in "-_/@=":
            t = t[len(n) :].lstrip("-_/@=")
            break
    else:
        for p in ("release", "rel", "version"):
            if t.startswith(p) and len(t) > len(p) and t[len(p)] in "-_/":
                t = t[len(p) + 1 :]
                break
    return parse_version(t)


def index_tags(tags: Iterable[str], names: Iterable[str]) -> dict[Version, str]:
    """Map version -> tag (shortest tag name wins when several encode one version)."""
    names = list(names)
    out: dict[Version, str] = {}
    for tag in sorted(tags, key=lambda t: (len(t), t)):
        v = tag_version(tag, names)
        if v is not None and v not in out:
            out[v] = tag
    return out


def fixed_and_last_affected_tags(
    rng: VersionRange, tags: dict[Version, str]
) -> tuple[str | None, str | None, str]:
    """Return (fixed_tag, last_affected_tag, note)."""
    notes = []
    fixed_tag = None
    if rng.fixed is None:
        notes.append("advisory lists no fixed version")
        fixed_v = None
    else:
        fixed_v = parse_version(rng.fixed)
        fixed_tag = tags.get(fixed_v) if fixed_v else None
        if fixed_tag is None:
            notes.append(f"no tag for fixed {rng.fixed}")
    last_tag = None
    if rng.last_affected:
        lv = parse_version(rng.last_affected)
        last_tag = tags.get(lv) if lv else None
        if last_tag is None:
            notes.append(f"no tag for last affected {rng.last_affected}")
    elif fixed_v is not None:
        intro = parse_version(rng.introduced) if rng.introduced != "0" else None
        below = [v for v in tags if v.stable and v < fixed_v and (intro is None or v >= intro)]
        if below:
            last_tag = tags[max(below)]
        else:
            notes.append(f"no stable tag in [{rng.introduced}, {rng.fixed})")
    return fixed_tag, last_tag, "; ".join(notes)


# --- files -------------------------------------------------------------------------

TEST_DIRS = {"test", "tests", "testing", "__tests__", "e2e", "spec", "specs"}
DOC_DIRS = {"doc", "docs", "documentation", "changelog.d", "changes", "newsfragments"}
DOC_EXTS = {".md", ".rst", ".txt", ".adoc"}
DOC_NAMES = ("changelog", "changes", "news", "history", "readme", "security", "authors")
SOURCE_EXTS = {
    ".py", ".pyx", ".pxd", ".pyi", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go",
    ".js", ".jsx", ".mjs", ".ts", ".tsx", ".svelte", ".vue", ".html", ".jinja", ".jinja2",
    ".j2",
}  # fmt: skip


def classify(path: str) -> str:
    """'test' | 'doc' | 'source' | 'other' for a repo-relative path."""
    p = PurePosixPath(path.lower())
    parts = set(p.parts[:-1])
    name = p.name
    if (
        parts & TEST_DIRS
        or name.startswith("test_")
        or name.endswith(("_test.py", "_tests.py"))
        or name == "conftest.py"
        or re.search(r"\.(test|spec)\.[jt]sx?$", name)
    ):
        return "test"
    if parts & DOC_DIRS or p.suffix in DOC_EXTS or name.startswith(DOC_NAMES):
        return "doc"
    if p.parts[0] in (".github", ".circleci") or name in ("setup.py", "noxfile.py", "tasks.py"):
        return "other"
    return "source" if p.suffix in SOURCE_EXTS else "other"


# --- git ---------------------------------------------------------------------------


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=1800
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {proc.stderr.strip()[:300]}")
    return proc


def clone_dir(root: Path, repo_slug: str) -> Path:
    return root / (repo_slug.replace("/", "__") + ".git")


def ensure_clone(root: Path, repo_slug: str) -> Path:
    """Blobless bare clone, created in a temp dir and renamed into place."""
    dest = clone_dir(root, repo_slug)
    if dest.exists():
        return dest
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / f".{dest.name}.tmp-{os.getpid()}"
    if tmp.exists():
        shutil.rmtree(tmp)
    url = f"https://github.com/{repo_slug}.git"
    proc = subprocess.run(
        ["git", "clone", "--quiet", "--bare", "--filter=blob:none", url, str(tmp)],
        capture_output=True,
        text=True,
        timeout=3600,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise GitError(f"clone {repo_slug}: {proc.stderr.strip()[:300]}")
    os.rename(tmp, dest)
    return dest


def ensure_commit(repo: Path, sha: str) -> str | None:
    """Full SHA of ``sha`` in ``repo``, fetching it by id if needed; None if unavailable."""
    probe = git(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}", check=False)
    if probe.returncode != 0 and len(sha) == 40:
        git(repo, "fetch", "--quiet", "--filter=blob:none", "origin", sha, check=False)
        probe = git(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}", check=False)
    return probe.stdout.strip() if probe.returncode == 0 else None


def is_ancestor(repo: Path, commit: str, ref: str) -> bool:
    proc = git(repo, "merge-base", "--is-ancestor", commit, ref, check=False)
    if proc.returncode not in (0, 1):
        raise GitError(f"merge-base {commit} {ref}: {proc.stderr.strip()[:300]}")
    return proc.returncode == 0


def list_tags(repo: Path) -> list[str]:
    out = git(repo, "for-each-ref", "--format=%(refname:short)", "refs/tags").stdout
    return [t for t in out.splitlines() if t]


def changed_files(repo: Path, sha: str) -> list[str]:
    """Files changed by ``sha`` against its first parent (root commit: all files)."""
    out = git(
        repo, "diff-tree", "-r", "--no-commit-id", "--name-only", "-m", "--first-parent",
        "--root", sha,
    ).stdout  # fmt: skip
    return sorted(set(out.splitlines()))


def commits_mentioning(repo: Path, start: str, end: str, ids: Iterable[str]) -> list[str]:
    """Commits in ``start..end`` whose message mentions any of ``ids`` (case-insensitive)."""
    log = git(repo, "log", "--format=%H%x1f%B%x1e", f"{start}..{end}").stdout
    pats = [i.lower() for i in ids]
    out = []
    for rec in log.split("\x1e"):
        if "\x1f" not in rec:
            continue
        sha, body = rec.strip().split("\x1f", 1)
        if any(p in body.lower() for p in pats):
            out.append(sha)
    return out


# --- verification ------------------------------------------------------------------


@dataclass
class Candidate:
    ghsa_id: str
    source: str
    repo: str
    sha: str
    link: str
    checks: dict[str, str] = field(default_factory=dict)
    details: list[str] = field(default_factory=list)
    fixed_version: str = ""
    fixed_tag: str = ""
    last_affected_tag: str = ""
    files: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return bool(self.checks) and all(v == PASS for v in self.checks.values())

    @property
    def n_pass(self) -> int:
        return sum(v == PASS for v in self.checks.values())

    def files_of(self, kind: str) -> list[str]:
        return [f for f in self.files if classify(f) == kind]


CHECKS = ("repo_matches_pypi", "in_fixed_tag", "not_in_affected_tag", "changes_src")


Canonical = Callable[[str], "str | None"]  # owner/repo -> current owner/repo (renames)


def verify(
    cand: Candidate,
    repo_dir: Path | None,
    adv: Advisory,
    pypi_infos: dict[str, dict | None],
    canonical: Canonical | None = None,
) -> Candidate:
    c = cand.checks
    listed = set().union(*(pypi_repos(pypi_infos.get(p)) for p in adv.packages))
    if not listed:
        c["repo_matches_pypi"] = UNKNOWN
        cand.details.append("no GitHub repo in PyPI project URLs")
    elif cand.repo in listed:
        c["repo_matches_pypi"] = PASS
    else:
        c["repo_matches_pypi"] = FAIL
        if canonical is not None:
            # Renamed/transferred repos: GitHub reports the current owner/repo for both names.
            here = canonical(cand.repo)
            there = {canonical(r) for r in listed} - {None}
            if here is not None and here in there:
                c["repo_matches_pypi"] = PASS
                cand.details.append(f"repo renamed: {cand.repo} and PyPI's link both -> {here}")
        if c["repo_matches_pypi"] == FAIL:
            cand.details.append(f"PyPI lists {sorted(listed)}")
    if repo_dir is None:
        for k in CHECKS[1:]:
            c[k] = UNKNOWN
        return cand
    full = ensure_commit(repo_dir, cand.sha)
    if full is None:
        for k in CHECKS[1:]:
            c[k] = UNKNOWN
        cand.details.append("commit not found in repo")
        return cand
    cand.sha = full

    tags = index_tags(list_tags(repo_dir), adv.packages)
    c["in_fixed_tag"] = UNKNOWN
    c["not_in_affected_tag"] = UNKNOWN
    if not adv.ranges:
        cand.details.append("advisory has no ECOSYSTEM ranges")
    notes = []
    chosen = None
    checked = missing = 0
    for rng in adv.ranges:
        fixed_tag, last_tag, note = fixed_and_last_affected_tags(rng, tags)
        if note:
            notes.append(note)
        if not fixed_tag:
            missing += 1
            continue
        checked += 1
        if is_ancestor(repo_dir, full, fixed_tag):
            chosen = (rng, fixed_tag, last_tag)
            break
        cand.fixed_version, cand.fixed_tag = rng.fixed or "", fixed_tag
        cand.last_affected_tag = last_tag or ""
    if not chosen and checked and not missing:
        # Every range has a fixed tag and none contains the commit.
        c["in_fixed_tag"] = FAIL
    if chosen:
        rng, fixed_tag, last_tag = chosen
        c["in_fixed_tag"] = PASS
        cand.fixed_version, cand.fixed_tag = rng.fixed or "", fixed_tag
        cand.last_affected_tag = last_tag or ""
        if last_tag:
            c["not_in_affected_tag"] = FAIL if is_ancestor(repo_dir, full, last_tag) else PASS
        else:
            notes.append("no last affected tag")
    elif c["in_fixed_tag"] == FAIL:
        notes.append("not contained in any fixed tag")
    if notes:
        cand.details.append("; ".join(dict.fromkeys(notes)))

    try:
        cand.files = changed_files(repo_dir, full)
    except GitError as e:
        c["changes_src"] = UNKNOWN
        cand.details.append(str(e))
        return cand
    c["changes_src"] = PASS if cand.files_of("source") else FAIL
    if c["changes_src"] == FAIL:
        cand.details.append("no non-test, non-doc source file changed")
    return cand


# --- per-advisory resolution ------------------------------------------------------


@dataclass
class Resolution:
    adv: Advisory
    commit_links: list[str]
    pr_links: list[str]
    candidates: list[Candidate]
    stages_tried: list[str]
    errors: list[str]

    @property
    def verified(self) -> list[Candidate]:
        return [c for c in self.candidates if c.verified]

    @property
    def source(self) -> str:
        v = self.verified
        return v[0].source if v else "none"

    def best(self) -> Candidate | None:
        if self.verified:
            return self.verified[0]
        if not self.candidates:
            return None
        return max(self.candidates, key=lambda c: c.n_pass)


PrLookup = Callable[[str, int], tuple[str | None, str]]  # -> (merge sha or None, note)


def package_repo(adv: Advisory, pypi_infos: dict[str, dict | None]) -> str | None:
    for url in adv.package_refs:
        s = github_slugs([url])
        if s:
            return s.pop()
    listed = sorted(set().union(*(pypi_repos(pypi_infos.get(p)) for p in adv.packages)))
    return listed[0] if listed else None


def resolve(
    adv: Advisory,
    pypi_infos: dict[str, dict | None],
    repos_root: Path,
    pr_lookup: PrLookup,
    canonical: Canonical | None = None,
    manual: Iterable[tuple[str, str]] = (),
) -> Resolution:
    """Resolve and verify fix commits; ``manual`` is [(commit_url, how_found), ...]."""
    commit_links = [u for u in adv.fix_links if parse_commit_url(u)]
    pr_links = [u for u in adv.fix_links if not parse_commit_url(u) and parse_pr_url(u)]
    res = Resolution(adv, commit_links, pr_links, [], [], [])

    def repo_dir(repo_slug: str) -> Path | None:
        try:
            return ensure_clone(repos_root, repo_slug)
        except GitError as e:
            res.errors.append(str(e))
            return None

    def run(source: str, items: list[tuple[str, str, str]]) -> bool:
        seen = {(c.repo, c.sha) for c in res.candidates}
        for repo_slug, sha, link in items:
            if (repo_slug, sha) in seen:
                continue
            seen.add((repo_slug, sha))
            cand = Candidate(adv.ghsa_id, source, repo_slug, sha, link)
            res.candidates.append(verify(cand, repo_dir(repo_slug), adv, pypi_infos, canonical))
        return bool(res.verified)

    def automated() -> None:
        # (a) commit URLs
        if commit_links:
            res.stages_tried.append("reference")
            items = [(*parse_commit_url(u), u) for u in commit_links]
            if run("reference", items):
                return
        # (b) PR URLs -> merge commit
        if pr_links:
            res.stages_tried.append("pr_merge")
            items = []
            for u in pr_links:
                repo_slug, number = parse_pr_url(u)
                sha, note = pr_lookup(repo_slug, number)
                if sha:
                    items.append((repo_slug, sha, u))
                else:
                    res.errors.append(f"{u}: {note}")
            if run("pr_merge", items):
                return
        # (c) tag-diff inference
        res.stages_tried.append("tag_diff_inferred")
        repo_slug = package_repo(adv, pypi_infos)
        if repo_slug is None:
            res.errors.append("tag_diff: no source repo known")
            return
        rd = repo_dir(repo_slug)
        if rd is None:
            return
        tags = index_tags(list_tags(rd), adv.packages)
        ids = [adv.ghsa_id, *adv.cve_aliases]
        items = []
        for rng in adv.ranges:
            fixed_tag, last_tag, note = fixed_and_last_affected_tags(rng, tags)
            if not (fixed_tag and last_tag):
                res.errors.append(f"tag_diff {rng.package} {rng.introduced}..{rng.fixed}: {note}")
                continue
            found = commits_mentioning(rd, last_tag, fixed_tag, ids)
            if not found:
                res.errors.append(
                    f"tag_diff {last_tag}..{fixed_tag}: no commit message names {ids}"
                )
            items += [(repo_slug, sha, f"{last_tag}..{fixed_tag}") for sha in found]
        run("tag_diff_inferred", items)

    automated()

    # (d) manual candidates: always checked and recorded, own trust level. They only
    # determine the advisory's source when no automated candidate verified.
    for url, how_found in manual:
        parsed = parse_commit_url(url)
        if parsed is None:
            res.errors.append(f"manual: not a GitHub commit URL: {url}")
            continue
        repo_slug, sha = parsed
        dup = next((c for c in res.candidates if c.repo == repo_slug and sha in c.sha), None)
        if dup is not None:
            res.errors.append(f"manual: {url} already checked as {dup.source}")
            continue
        if "manual" not in res.stages_tried:
            res.stages_tried.append("manual")
        cand = Candidate(adv.ghsa_id, "manual", repo_slug, sha, url)
        cand.details.append(f"how_found: {how_found}")
        res.candidates.append(verify(cand, repo_dir(repo_slug), adv, pypi_infos, canonical))
    return res
