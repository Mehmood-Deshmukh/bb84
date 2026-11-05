"""Length-prefixed framing shared by Alice, Bob, and Eve."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from qkd.services.wire import forward_message, listen, connect_with_retry, recv_bytes, recv_json, send_bytes, send_json


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


@pytest.mark.parametrize("value", [[], {"qber": 0.0}, ["+", "x"] * 64, {"sample_indices": [1, 5, 9]}, "text", 3])
def test_json_roundtrip(pair, value) -> None:
    a, b = pair
    send_json(a, value)
    assert recv_json(b) == value


def test_frame_layout(pair) -> None:
    a, b = pair
    send_bytes(a, b"abc")
    assert b.recv(7) == struct.pack(">I", 3) + b"abc"


def test_large_message_arrives_whole(pair) -> None:
    a, b = pair
    payload = bytes(range(256)) * 20_000  # ~5 MB, larger than one recv
    t = threading.Thread(target=send_bytes, args=(a, payload))
    t.start()
    assert recv_bytes(b) == payload
    t.join()


def test_messages_keep_order(pair) -> None:
    a, b = pair
    send_json(a, {"n": 1})
    send_bytes(a, b"\x00\x01")
    send_json(a, {"n": 2})
    assert recv_json(b) == {"n": 1}
    assert recv_bytes(b) == b"\x00\x01"
    assert recv_json(b) == {"n": 2}


def test_closed_connection_raises(pair) -> None:
    a, b = pair
    a.sendall(struct.pack(">I", 10) + b"short")
    a.close()
    with pytest.raises(ConnectionError):
        recv_bytes(b)


def test_forward_message_is_byte_identical() -> None:
    src_a, src_b = socket.socketpair()
    dst_a, dst_b = socket.socketpair()
    with src_a, src_b, dst_a, dst_b:
        send_json(src_a, {"salt": "00ff"})
        payload = forward_message(src_b, dst_a)
        assert payload == b'{"salt": "00ff"}'
        assert recv_json(dst_b) == {"salt": "00ff"}


def test_listen_on_free_port_and_connect() -> None:
    with listen(0, host="127.0.0.1") as server:
        port = server.getsockname()[1]
        with connect_with_retry("127.0.0.1", port, attempts=1) as client:
            conn, _ = server.accept()
            with conn:
                send_json(client, "hi")
                assert recv_json(conn) == "hi"


def test_connect_with_retry_gives_up() -> None:
    with listen(0, host="127.0.0.1") as server:
        port = server.getsockname()[1]
    with pytest.raises(ConnectionRefusedError):
        connect_with_retry("127.0.0.1", port, attempts=2, delay=0.01)


def test_protocol_sockets_disable_nagle() -> None:
    """Both ends of a protocol connection have TCP_NODELAY set (see wire.no_delay)."""
    import socket as _socket

    from qkd.services.wire import accept, connect_with_retry, listen

    with listen(0, "127.0.0.1") as server:
        port = server.getsockname()[1]
        client = connect_with_retry("127.0.0.1", port, attempts=1)
        conn, _ = accept(server)
        with client, conn:
            for sock in (client, conn):
                assert sock.getsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY) != 0
