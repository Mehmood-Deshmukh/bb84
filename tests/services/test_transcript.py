"""Tests for TranscriptChannel running SHA-256 transcript hashing and wire framing."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import json
import socket
import struct

import pytest

from qkd.services.transcript import TranscriptChannel


@pytest.fixture
def socket_pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    a, b = socket.socketpair()
    try:
        yield a, b
    finally:
        a.close()
        b.close()



def test_untracked_leaves_digest_unchanged(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    d_alice_start = alice.digest()
    d_bob_start = bob.digest()
    assert d_alice_start == d_bob_start

    # Qubit messages (e.g. list of QASM strings) sent untracked
    qubits = ["OPENQASM 2.0;", "qreg q[1];"]
    alice.send_untracked(qubits)
    received = bob.recv_untracked()
    assert received == qubits

    assert alice.digest() == d_alice_start
    assert bob.digest() == d_bob_start


def test_tracked_message_changes_digest_and_matches_across_peers(
    socket_pair: tuple[socket.socket, socket.socket],
) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    d_start = alice.digest()
    msg = {"hello": {"v": 1, "mode": "hybrid", "nonce": "abc"}}
    alice.send_json(msg)
    received = bob.recv_json()

    assert received == msg
    assert alice.digest() != d_start
    assert bob.digest() != d_start
    # Both ends hash identical bytes (direction byte || u32 length || canonical json)
    assert alice.digest() == bob.digest()


def test_direction_matters(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    msg = {"bases": ["+", "x", "+"]}

    # Alice -> Bob
    alice.send_json(msg)
    bob.recv_json()
    d_alice_to_bob = alice.digest()

    # Reset with fresh pair
    s1, s2 = socket.socketpair()
    try:
        alice2 = TranscriptChannel(s1, "alice")
        bob2 = TranscriptChannel(s2, "bob")

        # Bob -> Alice with identical message content
        bob2.send_json(msg)
        alice2.recv_json()
        d_bob_to_alice = bob2.digest()

        # Direction byte (0x00 for alice, 0x01 for bob) ensures different digests
        assert d_alice_to_bob != d_bob_to_alice
    finally:
        s1.close()
        s2.close()


def test_message_order_changes_digest() -> None:
    m1 = {"step": 1}
    m2 = {"step": 2}

    # Order 1: m1 then m2
    s1, s2 = socket.socketpair()
    try:
        a = TranscriptChannel(s1, "alice")
        b = TranscriptChannel(s2, "bob")
        a.send_json(m1)
        b.recv_json()
        a.send_json(m2)
        b.recv_json()
        d_order_1 = a.digest()
    finally:
        s1.close()
        s2.close()

    # Order 2: m2 then m1
    s3, s4 = socket.socketpair()
    try:
        a2 = TranscriptChannel(s3, "alice")
        b2 = TranscriptChannel(s4, "bob")
        a2.send_json(m2)
        b2.recv_json()
        a2.send_json(m1)
        b2.recv_json()
        d_order_2 = a2.digest()
    finally:
        s3.close()
        s4.close()

    assert d_order_1 != d_order_2


def test_digest_can_be_called_repeatedly_without_finalizing_running_hash(
    socket_pair: tuple[socket.socket, socket.socket],
) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    alice.send_json({"a": 1})
    bob.recv_json()

    d1 = alice.digest()
    d2 = alice.digest()
    assert d1 == d2
    assert len(d1) == 32

    # Channel keeps working and further messages update the running digest
    alice.send_json({"b": 2})
    bob.recv_json()

    d3 = alice.digest()
    assert d3 != d1
    assert alice.digest() == bob.digest()


def test_invalid_role_raises(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    sock_a, _ = socket_pair
    with pytest.raises(ValueError, match="role"):
        TranscriptChannel(sock_a, "eve")


def test_known_answer_digest(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    msg = {"hello": "world", "v": 1}
    # Canonical JSON bytes built by hand: sorted keys, compact separators, UTF-8
    p = b'{"hello":"world","v":1}'

    alice.send_json(msg)
    received = bob.recv_json()
    assert received == msg

    expected = hashlib.sha256(b"\x00" + struct.pack(">I", len(p)) + p).digest()
    assert alice.digest() == bob.digest() == expected


def test_byte_counters_count_framed_bytes(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    sock_a, sock_b = socket_pair
    alice = TranscriptChannel(sock_a, "alice")
    bob = TranscriptChannel(sock_b, "bob")

    tracked = {"hello": {"v": 1, "mode": "none"}}
    untracked = ["OPENQASM 2.0;"]
    reply = {"finished": "c2ln"}
    alice.send_json(tracked)
    bob.recv_json()
    alice.send_untracked(untracked)
    bob.recv_untracked()
    bob.send_untracked(reply)
    alice.recv_untracked()

    # Each frame is a 4-byte length prefix plus the JSON payload exactly as sent
    framed = lambda m: 4 + len(json.dumps(m).encode())  # noqa: E731
    sent_by_alice = framed(tracked) + framed(untracked)
    assert alice.bytes_sent == bob.bytes_received == sent_by_alice
    assert bob.bytes_sent == alice.bytes_received == framed(reply)
