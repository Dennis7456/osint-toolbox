from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:  # pragma: no cover - selected by operating system.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows.
    _fcntl = None

try:  # pragma: no cover - selected by operating system.
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX.
    _msvcrt = None


LOCK_BACKEND = "fcntl" if _fcntl is not None else "msvcrt" if _msvcrt is not None else "unavailable"


def _lock_windows(handle: Any, module: Any) -> None:
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    handle.seek(0)
    module.locking(handle.fileno(), module.LK_LOCK, 1)


def _unlock_windows(handle: Any, module: Any) -> None:
    handle.seek(0)
    module.locking(handle.fileno(), module.LK_UNLCK, 1)


@contextmanager
def case_lock(case_dir: Path) -> Iterator[None]:
    if LOCK_BACKEND == "unavailable":
        raise RuntimeError("No supported inter-process file-locking backend is available")
    lock_path = case_dir / ".case.lock"
    with lock_path.open("a+b") as handle:
        if _fcntl is not None:
            _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        else:
            _lock_windows(handle, _msvcrt)
        try:
            yield
        finally:
            if _fcntl is not None:
                _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
            else:
                _unlock_windows(handle, _msvcrt)

