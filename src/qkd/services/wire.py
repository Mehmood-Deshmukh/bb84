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


def connect_with_retry(host: str, port: int, attempts: int = 15, delay: float = 1.0) -> socket.socket:
    """Connect to host:port, retrying while the listener is not up yet."""
    for attempt in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            return sock
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
