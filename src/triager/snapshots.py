"""Pinned advisory-database snapshots (config/snapshots.yaml).

A snapshot is fetched at exactly its pinned commit with a shallow, blobless fetch and
an optional sparse checkout. ``verify_head`` fails loudly if the working tree is at
any other commit; every reader of snapshot data must call it first.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "snapshots.yaml"


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class Snapshot:
    name: str
    repo_url: str
    commit: str
    date: str
    licence: str


def load(name: str, config: Path = CONFIG) -> Snapshot:
    data = yaml.safe_load(config.read_text())["snapshots"]
    if name not in data:
        raise SnapshotError(f"no snapshot {name!r} in {config}")
    s = data[name]
    return Snapshot(name, s["repo_url"], s["commit"], str(s["date"]), s["licence"])


def _git(dest: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(dest), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SnapshotError(f"git {' '.join(args)} failed in {dest}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def head(dest: Path) -> str:
    return _git(dest, "rev-parse", "HEAD")


def verify_head(dest: Path, snap: Snapshot) -> None:
    if not (dest / ".git").exists():
        raise SnapshotError(f"{dest} is not a git checkout; fetch snapshot {snap.name} first")
    actual = head(dest)
    if actual != snap.commit:
        raise SnapshotError(
            f"snapshot {snap.name} at {dest} is at {actual}, but config pins {snap.commit}"
        )


def fetch(snap: Snapshot, dest: Path, sparse_paths: list[str] | None = None) -> None:
    """Fetch ``snap`` at its pinned commit into ``dest`` and verify HEAD."""
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        _git(dest, "init", "-q")
        _git(dest, "remote", "add", "origin", snap.repo_url)
    if sparse_paths:
        _git(dest, "sparse-checkout", "set", "--no-cone", *sparse_paths)
    _git(dest, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", snap.commit)
    _git(dest, "checkout", "-q", "--detach", snap.commit)
    verify_head(dest, snap)
