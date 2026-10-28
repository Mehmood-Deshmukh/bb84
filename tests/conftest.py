"""Shared fixtures: keys, test files, and a helper to run both ends of a connection."""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Any, Callable

import pytest

from qkd.core.crypto_utils import derive_aes_key


@pytest.fixture
def aes_key() -> bytes:
    return derive_aes_key(os.urandom(32))


@pytest.fixture
def make_file(tmp_path: Path) -> Callable[[str, int], Path]:
    """Create a file of random bytes, written in 1 MB pieces to keep memory flat."""

    def _make(name: str, size: int) -> Path:
        path = tmp_path / name
        with open(path, "wb") as f:
            remaining = size
            while remaining > 0:
                n = min(remaining, 1 << 20)
                f.write(os.urandom(n))
                remaining -= n
        return path

    return _make


def run_parallel(*fns: Callable[[], Any], timeout: float = 120) -> list[Any]:
    """Run each callable in its own thread. Returns results in order; re-raises the first exception."""
    results: list[Any] = [None] * len(fns)
    errors: list[BaseException] = []

    def run(i: int, fn: Callable[[], Any]) -> None:
        try:
            results[i] = fn()
        except BaseException as exc:  # noqa: BLE001 - surfaced to the caller below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
    if errors:
        raise errors[0]
    return results


def run_both(left: Callable[[socket.socket], Any], right: Callable[[socket.socket], Any]) -> tuple[Any, Any]:
    """Connect two sockets and run `left(sock_a)` and `right(sock_b)` in parallel."""
    a, b = socket.socketpair()
    with a, b:
        return tuple(run_parallel(lambda: left(a), lambda: right(b)))


@pytest.fixture
def connected() -> Callable[..., tuple[Any, Any]]:
    return run_both


@pytest.fixture
def parallel() -> Callable[..., list[Any]]:
    return run_parallel


def files_equal(path_a: Path, path_b: Path) -> bool:
    """Compare two files in 1 MB pieces."""
    if os.path.getsize(path_a) != os.path.getsize(path_b):
        return False
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            ca, cb = fa.read(1 << 20), fb.read(1 << 20)
            if ca != cb:
                return False
            if not ca:
                return True


@pytest.fixture
def same_file() -> Callable[[Path, Path], bool]:
    return files_equal
