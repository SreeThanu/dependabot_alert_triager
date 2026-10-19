import os

import pytest

from triager import fsutil


def test_writes_and_replaces_without_debris(tmp_path):
    target = tmp_path / "out.txt"
    fsutil.atomic_write_text(target, "first")
    fsutil.atomic_write_text(target, "second")
    assert target.read_text() == "second"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.txt"]


def test_new_file_uses_umask_and_existing_mode_is_kept(tmp_path):
    new = tmp_path / "new.txt"
    fsutil.atomic_write_text(new, "x")
    umask = os.umask(0)
    os.umask(umask)
    assert new.stat().st_mode & 0o777 == 0o666 & ~umask

    existing = tmp_path / "existing.txt"
    existing.write_text("old")
    existing.chmod(0o640)
    fsutil.atomic_write_text(existing, "new")
    assert existing.stat().st_mode & 0o777 == 0o640


def test_failure_before_replace_leaves_original_intact(tmp_path, monkeypatch):
    target = tmp_path / "labels.csv"
    target.write_text("original")

    def boom(src, dst):
        raise OSError("simulated disk disconnect")

    monkeypatch.setattr(fsutil.os, "replace", boom)
    with pytest.raises(OSError, match="simulated"):
        fsutil.atomic_write_text(target, "half-written")
    assert target.read_text() == "original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["labels.csv"]
