"""
scripts/latency_proxy.py: a request/response through it costs one round trip of
2 x one-way delay, and data passes through unchanged and in order.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _echo_server() -> tuple[socket.socket, int]:
    """Accept one connection and echo everything back until the client closes."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def run() -> None:
        conn, _ = server.accept()
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)

    threading.Thread(target=run, daemon=True).start()
    return server, server.getsockname()[1]


def _start_proxy(target_port: int, one_way_ms: float) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "latency_proxy.py"),
         "--target-port", str(target_port), "--one-way-ms", str(one_way_ms)],
        stdout=subprocess.PIPE, text=True,
    )
    line = proc.stdout.readline()
    assert line.startswith("listening "), line
    return proc, int(line.split()[1])


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        assert chunk, "connection closed early"
        out += chunk
    return out


def test_ping_costs_one_round_trip() -> None:
    server, port = _echo_server()
    proxy, proxy_port = _start_proxy(port, one_way_ms=40)
    try:
        with socket.create_connection(("127.0.0.1", proxy_port)) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            times = []
            for _ in range(3):
                t0 = time.perf_counter()
                sock.sendall(b"ping")
                assert _recv_exact(sock, 4) == b"ping"
                times.append(time.perf_counter() - t0)
        # One round trip is 2 x 40 ms; allow scheduling slack above, never below
        assert all(0.080 <= t < 0.120 for t in times), times
    finally:
        proxy.wait(timeout=10)
        server.close()


def test_data_passes_unchanged_and_the_proxy_exits() -> None:
    server, port = _echo_server()
    proxy, proxy_port = _start_proxy(port, one_way_ms=1)
    payload = os.urandom(1 << 20)
    try:
        with socket.create_connection(("127.0.0.1", proxy_port)) as sock:
            sender = threading.Thread(target=sock.sendall, args=(payload,))
            sender.start()
            echoed = _recv_exact(sock, len(payload))
            sender.join()
        assert echoed == payload
        assert proxy.wait(timeout=10) == 0  # exits once both directions close
    finally:
        if proxy.poll() is None:
            proxy.kill()
        server.close()
