"""Diff baseline (plan §3, task T4): functions changed by a verified fix commit.

This is *vulnerable-function identification* only; it says nothing about reachability.

For each fix commit, against its first parent (the pre-fix version):

1. ``git diff -M -U0`` is parsed with unidiff.
2. Files are kept only if they are Python source inside the affected package's own
   import root(s) in the repo, and not tests, docs, examples or packaging files.
3. Changed lines are mapped to the innermost enclosing ``def`` / ``async def`` / ``class``
   in the *pre-fix* file using ``ast`` (``lineno``..``end_lineno``, decorators included):
   - removed/replaced lines map by their old line number;
   - pure insertions (no old lines) map to the innermost scope around the insertion
     point whose ``def``/``class`` is indented less than the inserted code;
   - lines outside any def/class map to ``<module>``.
4. Names are fully qualified: ``pkg.mod.Class.method``; nested functions follow Python's
   ``__qualname__`` convention (``pkg.mod.outer.<locals>.inner``).

Multi-commit fixes are combined by taking the union of symbols, keeping every
(commit, file, lines) provenance.
"""

from __future__ import annotations

import ast
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from unidiff import PatchSet

from triager.advisories import normalise_name
from triager.fixcommit import DOC_DIRS, TEST_DIRS, classify

EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos"}
PACKAGING_NAMES = {
    "setup.py", "setup.cfg", "pyproject.toml", "manifest.in", "_version.py", "version.py",
    "__about__.py", "__version__.py",
}  # fmt: skip

MODULE = "<module>"


# --- import roots ------------------------------------------------------------------


def name_variants(package: str) -> list[str]:
    """Candidate import names for a PyPI distribution, most specific first."""
    n = normalise_name(package)
    parts = n.split("-")
    out = [n.replace("-", "_"), n.replace("-", "")]
    for prefix in ("python-", "py-", "py"):
        if n.startswith(prefix) and len(n) > len(prefix) + 2:
            out.append(n[len(prefix) :].replace("-", "_"))
    out += [parts[-1], parts[0]] if len(parts) > 1 else []
    return list(dict.fromkeys(out))


def top_level_packages(paths: Iterable[str]) -> list[str]:
    """Directories with ``__init__.py`` whose parent has none (repo-relative)."""
    pkg_dirs = {str(PurePosixPath(p).parent) for p in paths if p.endswith("/__init__.py")}
    pkg_dirs |= {"" for p in paths if p == "__init__.py"}
    tops = []
    for d in sorted(pkg_dirs):
        parent = str(PurePosixPath(d).parent)
        if d and (parent == "." or parent not in pkg_dirs):
            tops.append(d)
    return tops


def import_roots(
    paths: Iterable[str], packages: Iterable[str], overrides: dict[str, list[str]] | None = None
) -> tuple[list[str], str]:
    """Return (repo-relative import root dirs, method) for the affected packages.

    ``overrides`` maps a normalised package name to explicit root dirs. Otherwise the
    first name variant that matches the last component of a top-level package dir
    (case-insensitive, outside test/doc/example dirs, e.g. not docs/theme/mlflow) wins.
    """
    packages = [normalise_name(p) for p in packages]
    overrides = overrides or {}
    explicit = [r for p in packages for r in overrides.get(p, [])]
    if explicit:
        return sorted(set(explicit)), "override"
    excluded = EXAMPLE_DIRS | TEST_DIRS | DOC_DIRS
    tops = [
        t
        for t in top_level_packages(paths)
        if not ({x.lower() for x in PurePosixPath(t).parts} & excluded)
    ]
    for pkg in packages:
        for variant in name_variants(pkg):
            hits = [t for t in tops if PurePosixPath(t).name.lower() == variant.lower()]
            if hits:
                return sorted(hits), f"auto:{variant}"
    return [], "unresolved"


def under(path: str, roots: Iterable[str]) -> str | None:
    for r in roots:
        if path == r or path.startswith(r.rstrip("/") + "/"):
            return r
    return None


def file_status(path: str, roots: list[str]) -> str:
    """'python' (analysed), or why the file is out of scope."""
    p = PurePosixPath(path)
    lower_parts = {x.lower() for x in p.parts[:-1]}
    if under(path, roots) is None:
        return "outside_import_root"
    kind = classify(path)
    if kind in ("test", "doc"):
        return kind
    if lower_parts & EXAMPLE_DIRS:
        return "example"
    if p.name.lower() in PACKAGING_NAMES:
        return "packaging"
    if kind != "source":
        return "other"
    return "python" if p.suffix == ".py" else "non_python_source"


def module_name(path: str, root: str) -> str:
    """``src/urllib3/util/url.py`` with root ``src/urllib3`` -> ``urllib3.util.url``."""
    base = PurePosixPath(root).parent
    rel = PurePosixPath(path).relative_to(base) if str(base) != "." else PurePosixPath(path)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


# --- ast scopes --------------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    start: int  # first decorator line, else the def/class line
    end: int
    qualname: str
    kind: str  # "function" | "class"
    col: int
    depth: int


def scopes(source: str) -> list[Scope]:
    """All def/async def/class scopes in ``source`` (raises SyntaxError)."""
    tree = ast.parse(source)
    out: list[Scope] = []

    def visit(node: ast.AST, prefix: str, depth: int) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                is_fn = not isinstance(child, ast.ClassDef)
                qual = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out.append(
                    Scope(start, child.end_lineno or child.lineno, qual,
                          "function" if is_fn else "class", child.col_offset, depth)
                )  # fmt: skip
                visit(child, f"{qual}.<locals>." if is_fn else f"{qual}.", depth + 1)
            else:
                visit(child, prefix, depth)

    visit(tree, "", 0)
    return out


def innermost(scope_list: list[Scope], line: int) -> Scope | None:
    inside = [s for s in scope_list if s.start <= line <= s.end]
    return max(inside, key=lambda s: s.depth) if inside else None


def scope_for_insertion(scope_list: list[Scope], after_line: int, indent: int) -> Scope | None:
    """Innermost scope containing ``after_line`` whose header is indented less than ``indent``."""
    inside = sorted(
        (s for s in scope_list if s.start <= after_line <= s.end),
        key=lambda s: s.depth,
        reverse=True,
    )
    return next((s for s in inside if s.col < indent), None)


# --- diff -> changed lines ---------------------------------------------------------


@dataclass
class FileChanges:
    old_path: str | None  # None for added files
    new_path: str | None  # None for removed files
    removed: set[int] = field(default_factory=set)  # old line numbers
    insertions: list[tuple[int, int]] = field(default_factory=list)  # (after old line, indent)


_INDENT_RE = re.compile(r"^[ \t]*")


def parse_diff(diff_text: str) -> list[FileChanges]:
    out = []
    for pf in PatchSet(diff_text):
        old = None if pf.is_added_file else pf.source_file.removeprefix("a/")
        new = None if pf.is_removed_file else pf.target_file.removeprefix("b/")
        fc = FileChanges(old, new)
        for hunk in pf:
            removed = [ln.source_line_no for ln in hunk if ln.is_removed]
            fc.removed.update(n for n in removed if n is not None)
            if not removed:
                added = [ln.value for ln in hunk if ln.is_added and ln.value.strip()]
                if added:
                    indent = len(_INDENT_RE.match(added[0].expandtabs(4)).group(0))
                    fc.insertions.append((hunk.source_start, indent))
        out.append(fc)
    return out


@dataclass(frozen=True)
class Hit:
    symbol: str  # fully qualified
    kind: str  # "function" | "class" | "module"
    commit: str
    file: str  # pre-fix path
    lines: tuple[int, ...]


def map_changes(fc: FileChanges, source: str, module: str, commit: str) -> list[Hit]:
    """Map one file's changed lines to symbols (raises SyntaxError if unparsable)."""
    sc = scopes(source)
    found: dict[tuple[str, str], set[int]] = {}

    def add(s: Scope | None, line: int) -> None:
        key = (f"{module}.{s.qualname}", s.kind) if s else (f"{module}.{MODULE}", "module")
        found.setdefault(key, set()).add(line)

    for line in sorted(fc.removed):
        add(innermost(sc, line), line)
    for after, indent in fc.insertions:
        add(scope_for_insertion(sc, after, indent), after)
    return [
        Hit(sym, kind, commit, fc.old_path or "", tuple(sorted(lines)))
        for (sym, kind), lines in sorted(found.items())
    ]


# --- git-backed analysis -------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=1800
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])}: {proc.stderr.strip()[:300]}")
    return proc.stdout


@dataclass
class CommitAnalysis:
    commit: str
    parent: str
    hits: list[Hit] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # path -> status
    unparsed: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)


def analyse_commit(repo: Path, sha: str, roots: list[str]) -> CommitAnalysis:
    parent = _git(repo, "rev-parse", f"{sha}^1").strip()
    res = CommitAnalysis(sha, parent)
    diff = _git(repo, "diff", "-M", "-U0", "--no-color", "--no-ext-diff", parent, sha)
    for fc in parse_diff(diff):
        path = fc.old_path or fc.new_path or ""
        status = file_status(path, roots)
        res.files[path] = status
        if status != "python":
            continue
        if fc.old_path is None:
            res.new_files.append(path)
            continue
        source = _git(repo, "show", f"{parent}:{fc.old_path}")
        root = under(fc.old_path, roots)
        try:
            res.hits += map_changes(fc, source, module_name(fc.old_path, root), sha)
        except SyntaxError:
            res.unparsed.append(fc.old_path)
    return res


def tree_paths(repo: Path, rev: str) -> list[str]:
    return _git(repo, "ls-tree", "-r", "--name-only", rev).splitlines()


def combine(hits: Iterable[Hit]) -> dict[tuple[str, str], list[Hit]]:
    """Union of symbols over several commits, keeping every provenance."""
    out: dict[tuple[str, str], list[Hit]] = {}
    for h in hits:
        out.setdefault((h.symbol, h.kind), []).append(h)
    return dict(sorted(out.items()))
