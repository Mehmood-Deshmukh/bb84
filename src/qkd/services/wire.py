"""
Length-prefixed message framing shared by Alice, Bob, and Eve.

Every message is a 4-byte big-endian length followed by the payload, which is
either UTF-8 JSON or raw bytes. This module must stay free of qiskit imports so
tests and the backend can use it without the quantum stack.
"""

from __future__ import annotations

import json
import socket
import struct
import time
from typing import Any

from qkd.core.config import BUFFER_SIZE

_LENGTH = struct.Struct(">I")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes, or raise ConnectionError if the peer closes first."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed during receive")
        buf += chunk
    return bytes(buf)


def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Send raw bytes with a 4-byte length prefix."""
    sock.sendall(_LENGTH.pack(len(data)) + data)


def recv_bytes(sock: socket.socket) -> bytes:
    """Receive one length-prefixed message as raw bytes."""
    (length,) = _LENGTH.unpack(recv_exact(sock, _LENGTH.size))
    return recv_exact(sock, length)


def encode_json(data: Any) -> bytes:
    """The payload bytes send_json puts on the wire for data."""
    return json.dumps(data).encode()


def decode_json(payload: bytes) -> Any:
    """Parse a payload produced by encode_json."""
    return json.loads(payload.decode())


def send_json(sock: socket.socket, data: Any) -> None:
    """Send a JSON-serialisable value with a 4-byte length prefix."""
    send_bytes(sock, encode_json(data))


def recv_json(sock: socket.socket) -> Any:
    """Receive one length-prefixed JSON message."""
    return decode_json(recv_bytes(sock))


def forward_message(src: socket.socket, dst: socket.socket) -> bytes:
    """Forward one length-prefixed message from src to dst unchanged and return its payload."""
    data = recv_bytes(src)
    send_bytes(dst, data)
    return data


def relay_until_closed(a: socket.socket, b: socket.socket) -> None:
    """
    Copy bytes both ways between a and b until both directions are closed.

    For in-path proxies (Eve) once they stop parsing: it does not need to know how many
    messages follow or in which direction, which varies with reconciliation rounds. When
    one side closes, its peer's sending direction is shut down too, as a direct
    connection would see.
    """
    import selectors

    open_from = {a: b, b: a}
    with selectors.DefaultSelector() as sel:
        for sock in open_from:
            sel.register(sock, selectors.EVENT_READ)
        while open_from:
            for key, _ in sel.select():
                src = key.fileobj
                dst = open_from.get(src)
                if dst is None:
                    continue
                try:
                    data = src.recv(65536)
                except (ConnectionError, OSError):
                    data = b""
                if data:
                    try:
                        dst.sendall(data)
                        continue
                    except (ConnectionError, OSError):
                        pass
                # src closed (or dst is gone): stop this direction
                sel.unregister(src)
                del open_from[src]
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass


def no_delay(sock: socket.socket) -> socket.socket:
    """
    Turn off Nagle's algorithm on a protocol socket and return it.

    Every message already goes out in one write, so Nagle only adds delay: when one
    side sends two messages in a row (Alice's qber, then her salt), the second waits
    for the ACK of the first, which the peer delays by up to about 40 ms because it
    has nothing to send back. Measured before this: about 40 ms per run, all of it
    charged to the key confirmation stage.
    """
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def accept(server: socket.socket) -> tuple[socket.socket, Any]:
    """server.accept() with TCP_NODELAY set on the new connection."""
    conn, addr = server.accept()
    return no_delay(conn), addr


def connect_with_retry(host: str, port: int, attempts: int = 15, delay: float = 1.0) -> socket.socket:
    """Connect to host:port, retrying while the listener is not up yet. TCP_NODELAY is set."""
    for attempt in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            return no_delay(sock)
        except ConnectionRefusedError:
            sock.close()
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise ConnectionRefusedError(f"Could not connect to {host}:{port}")


def listen(port: int, host: str = "0.0.0.0") -> socket.socket:
    """Open a listening TCP socket. Port 0 picks a free port (see sock.getsockname())."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    return server
