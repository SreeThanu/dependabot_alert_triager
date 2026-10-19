"""Crash-safe file writes.

Data is written to a temporary file in the destination directory, flushed and
fsynced, then moved into place with ``os.replace`` (atomic on the same file
system), and the directory is fsynced. A crash or disk disconnect leaves either
the old file or the new one, never a truncated mix. A leftover ``.*.tmp`` file
is the only possible debris.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def _target_mode(path: Path) -> int:
    """Keep an existing file's mode; otherwise the usual 0o666 minus umask."""
    try:
        return path.stat().st_mode & 0o777
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        return 0o666 & ~umask


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = _target_mode(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)  # mkstemp creates 0o600
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))
