"""
Transcript tracking channel wrapper over wire framing.

Feeds a running SHA-256 hash of all classical protocol messages exchanged over the
wire, establishing an identical transcript digest on both peers for ML-DSA signing
and hybrid session key derivation.
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
from typing import Any

from qkd.services import wire

_LENGTH = struct.Struct(">I")
_DIR_ALICE = b"\x00"
_DIR_BOB = b"\x01"


def _canonical_json(data: Any) -> bytes:
    """Format data as canonical UTF-8 JSON (sorted keys, compact separators)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class TranscriptChannel:
    """
    Wraps wire.send_json / wire.recv_json to maintain a running transcript hash.

    Every tracked message updates the running SHA-256 with:
        direction byte (1B) || big-endian length (4B) || canonical JSON payload
    where direction byte is 0x00 for messages sent by Alice and 0x01 for messages
    sent by Bob.

    bytes_sent and bytes_received count framed bytes (length prefix + payload) of
    every message, tracked or not.
    """

    def __init__(self, sock: socket.socket, role: str) -> None:
        role_normalized = role.lower()
        if role_normalized not in {"alice", "bob"}:
            raise ValueError(f"Invalid role: {role!r}. Allowed roles: 'alice', 'bob'")
        self.sock = sock
        self.role = role_normalized
        self._hasher = hashlib.sha256()
        self.bytes_sent = 0
        self.bytes_received = 0

    def send_json(self, data: Any) -> None:
        """Send a JSON message and record it in the transcript hash."""
        payload = _canonical_json(data)
        dir_byte = _DIR_ALICE if self.role == "alice" else _DIR_BOB
        self._hasher.update(dir_byte + _LENGTH.pack(len(payload)) + payload)
        self._send(data)

    def recv_json(self) -> Any:
        """Receive a JSON message and record it in the transcript hash."""
        data = self._recv()
        payload = _canonical_json(data)
        # Sender was the peer
        dir_byte = _DIR_BOB if self.role == "alice" else _DIR_ALICE
        self._hasher.update(dir_byte + _LENGTH.pack(len(payload)) + payload)
        return data

    def send_untracked(self, data: Any) -> None:
        """Send a message without recording it in the transcript (e.g., qubits or finished)."""
        self._send(data)

    def recv_untracked(self) -> Any:
        """Receive an untracked message without recording it in the transcript."""
        return self._recv()

    def _send(self, data: Any) -> None:
        payload = wire.encode_json(data)
        wire.send_bytes(self.sock, payload)
        self.bytes_sent += _LENGTH.size + len(payload)

    def _recv(self) -> Any:
        payload = wire.recv_bytes(self.sock)
        self.bytes_received += _LENGTH.size + len(payload)
        return wire.decode_json(payload)

    def digest(self) -> bytes:
        """
        Return the current 32-byte transcript digest.

        Uses a copy of the running hash so subsequent messages can continue being tracked.
        """
        return self._hasher.copy().digest()
