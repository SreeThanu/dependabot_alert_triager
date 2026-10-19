import subprocess

import pytest

from triager.snapshots import Snapshot, SnapshotError, verify_head


def _git(cwd, *args):
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "f.txt").write_text("x")
    _git(tmp_path, "add", "f.txt")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c")
    return tmp_path


def snap(commit):
    return Snapshot("test_db", "https://example.invalid/repo", commit, "2026-10-19", "CC-BY-4.0")


def test_verify_head_passes_at_pinned_sha(repo):
    verify_head(repo, snap(_git(repo, "rev-parse", "HEAD")))


def test_verify_head_fails_loudly_on_other_sha(repo):
    pinned = "b16e369438ef2ab329b4c224cae8224f144bf5d5"
    with pytest.raises(SnapshotError, match=f"config pins {pinned}"):
        verify_head(repo, snap(pinned))


def test_verify_head_fails_when_not_a_checkout(tmp_path):
    with pytest.raises(SnapshotError, match="not a git checkout"):
        verify_head(tmp_path, snap("0" * 40))
