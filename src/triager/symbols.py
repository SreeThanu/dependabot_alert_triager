"""AST symbol tables of an affected package at its vulnerable version (task T5).

A symbol table lists every fully qualified symbol defined in the package's Python
files under its import root(s), with the same conventions as the diff baseline
(``triager.baselines.diff``): ``pkg.mod.Class.method``, nested functions as
``pkg.mod.outer.<locals>.inner``, and module-level code as ``pkg.mod.<module>``.

The vulnerable version is the first parent of the (first) verified fix commit, or
otherwise the last affected release tag (see ``vulnerable_ref``).

Blobs are read from blobless clones: missing ``.py`` blobs are prefetched explicitly in
batches (the same ``fetch --stdin`` a lazy fetch performs; long single batches were
observed to fail), then read with ``cat-file --batch`` with lazy fetching disabled.
"""

from __future__ import annotations

import gzip
import json
import os
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from triager.advisories import Advisory
from triager.baselines.diff import (
    MODULE,
    file_status,
    import_roots,
    module_name,
    scopes,
    tree_paths,
    under,
)
from triager.fixcommit import (
    Version,
    fixed_and_last_affected_tags,
    index_tags,
    list_tags,
    parse_version,
)
from triager.fsutil import atomic_write_bytes

_NO_LAZY = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}


# --- vulnerable ref ----------------------------------------------------------------


def vulnerable_ref(
    adv: Advisory, tags: list[str], fix_commit: str | None, parent_of: Any = None
) -> tuple[str, str, str] | None:
    """Return (ref_kind, ref, note) or None.

    ref_kind: ``fix_parent`` (first parent of the verified fix commit),
    ``last_affected_tag`` (highest last-affected tag over ranges that list a fix or a
    last-affected bound) or ``latest_tag_unfixed`` (no fix listed: the highest stable tag
    at or above ``introduced``, i.e. the newest release still affected).
    """
    if fix_commit:
        return "fix_parent", parent_of(fix_commit), ""
    index = index_tags(tags, adv.packages)
    found: list[tuple[Version, str, str]] = []
    notes = []
    for rng in adv.ranges:
        if rng.fixed or rng.last_affected:
            _, last, note = fixed_and_last_affected_tags(rng, index)
            if last:
                ver = next(v for v, t in index.items() if t == last)
                found.append((ver, last, "last_affected_tag"))
            elif note:
                notes.append(note)
        else:
            intro = parse_version(rng.introduced) if rng.introduced != "0" else None
            stable = [v for v in index if v.stable and (intro is None or v >= intro)]
            if stable:
                v = max(stable)
                found.append((v, index[v], "latest_tag_unfixed"))
            else:
                notes.append(f"no stable tag at or above {rng.introduced}")
    if not found:
        return None
    ver, tag, kind = max(found)
    return kind, tag, "; ".join(notes)


# --- blobs -------------------------------------------------------------------------


def _git(repo: Path, *args: str, stdin: bytes | None = None, env=None) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], input=stdin, capture_output=True, timeout=1800, env=env
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])}: {proc.stderr.decode()[:300]}")
    return proc.stdout


def python_blobs(repo: Path, ref: str, roots: list[str]) -> list[tuple[str, str]]:
    """(blob oid, path) for in-scope Python files under ``roots`` at ``ref``."""
    out = _git(repo, "ls-tree", "-r", "--full-tree", ref, "--", *roots).decode()
    blobs = []
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        _, kind, oid = meta.split()
        if kind == "blob" and file_status(path, roots) == "python":
            blobs.append((oid, path))
    return blobs


def missing_objects(repo: Path, oids: Iterable[str]) -> list[str]:
    data = "\n".join(oids).encode() + b"\n"
    out = _git(repo, "cat-file", "--batch-check", stdin=data, env=_NO_LAZY).decode()
    return [ln.split()[0] for ln in out.splitlines() if ln.endswith(" missing")]


def prefetch(repo: Path, oids: list[str], batch: int = 200, retries: int = 3) -> None:
    for i in range(0, len(oids), batch):
        chunk = "\n".join(oids[i : i + batch]).encode() + b"\n"
        for attempt in range(retries + 1):
            try:
                _git(
                    repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "origin",
                    "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                    "--filter=blob:none", "--stdin", stdin=chunk,
                )  # fmt: skip
                break
            except RuntimeError:
                if attempt == retries:
                    raise


def read_blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    if not oids:
        return {}
    data = "\n".join(oids).encode() + b"\n"
    out = _git(repo, "cat-file", "--batch", stdin=data, env=_NO_LAZY)
    blobs, pos = {}, 0
    for _ in oids:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode().split()
        if header[-1] == "missing":
            raise RuntimeError(f"blob {header[0]} missing after prefetch")
        size = int(header[2])
        blobs[header[0]] = out[nl + 1 : nl + 1 + size]
        pos = nl + 1 + size + 1
    return blobs


# --- symbols -----------------------------------------------------------------------


def file_symbols(source: bytes | str, module: str, path: str) -> list[dict[str, Any]]:
    """Symbols in one file (raises SyntaxError / ValueError if it does not parse)."""
    syms = [{"symbol": f"{module}.{MODULE}", "kind": "module", "file": path, "lines": None}]
    for s in scopes(source):
        syms.append(
            {"symbol": f"{module}.{s.qualname}", "kind": s.kind, "file": path,
             "lines": [s.start, s.end]}
        )  # fmt: skip
    return syms


def build_table(
    repo: Path, ref: str, packages: list[str], overrides: dict[str, list[str]] | None = None
) -> dict[str, Any]:
    commit = _git(repo, "rev-parse", f"{ref}^{{commit}}").decode().strip()
    roots, method = import_roots(tree_paths(repo, commit), packages, overrides)
    table: dict[str, Any] = {
        "commit": commit,
        "import_roots": roots,
        "import_root_method": method,
        "files_parsed": 0,
        "files_unparsed": [],
        "symbols": [],
    }
    if not roots:
        return table
    blobs = python_blobs(repo, commit, roots)
    oids = sorted({oid for oid, _ in blobs})
    prefetch(repo, missing_objects(repo, oids))
    contents = read_blobs(repo, oids)
    for oid, path in sorted(blobs, key=lambda b: b[1]):
        module = module_name(path, under(path, roots))
        try:
            table["symbols"] += file_symbols(contents[oid], module, path)
            table["files_parsed"] += 1
        except (SyntaxError, ValueError):
            table["files_unparsed"].append(path)
    return table


def save(path: Path, table: dict[str, Any]) -> None:
    raw = json.dumps(table, sort_keys=True).encode()
    atomic_write_bytes(path, gzip.compress(raw, mtime=0))


def load(path: Path) -> dict[str, Any]:
    return json.loads(gzip.decompress(path.read_bytes()))


def tags_of(repo: Path) -> list[str]:
    return list_tags(repo)
