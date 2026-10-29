"""
End-to-end chunked file transfer over a localhost TCP socket.

Runs the final phase of the protocol (metadata + encrypted chunks) with a
pre-shared AES key, using the same file_stream module as Alice and Bob.
No qiskit is imported here.
"""

from __future__ import annotations

import os
import socket
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.config import CHUNK_SIZE
from qkd.core.crypto_utils import derive_aes_key
from qkd.services.file_stream import (
    describe_file,
    receive_encrypted_file,
    receive_file_meta,
    received_path,
    send_encrypted_file,
)
from qkd.services.wire import forward_message, recv_json, send_json

MB = 1024 * 1024


def transfer_over_tcp(src: Path, out_dir: Path, send_key: bytes, recv_key: bytes) -> Path:
    """Send src over a real TCP connection and return the received file's path."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    errors: list[BaseException] = []

    def send() -> None:
        try:
            with socket.create_connection(("127.0.0.1", port)) as sock:
                send_encrypted_file(sock, str(src), send_key, describe_file(str(src)))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    sender = threading.Thread(target=send)
    sender.start()
    conn, _ = server.accept()
    try:
        with conn:
            meta = receive_file_meta(conn)
            out = Path(received_path(str(out_dir), meta.filename))
            written = receive_encrypted_file(conn, meta, str(out), recv_key)
            assert written == meta.total_size
    finally:
        sender.join(120)
        server.close()
    if errors:
        raise errors[0]
    return out


@pytest.mark.parametrize(
    "size",
    [0, 1, 100, CHUNK_SIZE, CHUNK_SIZE + 1, 123_457, 1 * MB, 10 * MB, 100 * MB],
    ids=["empty", "1B", "100B", "chunk", "chunk+1", "odd", "1MB", "10MB", "100MB"],
)
def test_transfer_preserves_content(size: int, make_file, same_file, tmp_path: Path, aes_key: bytes) -> None:
    src = make_file(f"payload_{size}.bin", size)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    received = transfer_over_tcp(src, out_dir, aes_key, aes_key)
    assert received.name == f"received_{src.name}"
    assert same_file(src, received)


def test_text_file_integrity(tmp_path: Path, aes_key: bytes) -> None:
    src = tmp_path / "message.txt"
    content = "Top secret quantum message! 🔐\n" * 1000
    src.write_text(content, encoding="utf-8")
    received = transfer_over_tcp(src, tmp_path, aes_key, aes_key)
    assert received.read_text(encoding="utf-8") == content


def test_wrong_key_fails_and_leaves_no_partial_file(make_file, tmp_path: Path, aes_key: bytes) -> None:
    src = make_file("secret.bin", 3 * CHUNK_SIZE)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(InvalidTag):
        transfer_over_tcp(src, out_dir, aes_key, derive_aes_key(os.urandom(32)))
    assert list(out_dir.iterdir()) == []


def test_received_path_strips_directories(tmp_path: Path) -> None:
    assert received_path(str(tmp_path), "../../etc/passwd") == str(tmp_path / "received_passwd")


def test_metadata_counts_chunks(make_file) -> None:
    meta = describe_file(str(make_file("x.bin", 2 * CHUNK_SIZE + 5)))
    assert (meta.total_size, meta.num_chunks, meta.chunk_size, len(meta.base_nonce)) == (2 * CHUNK_SIZE + 5, 3, CHUNK_SIZE, 8)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda msg: {**msg, "filename": "other.bin"},
        # Same bytes after FileMeta parsing, so only an AAD over the raw message catches it
        lambda msg: {**msg, "base_nonce": msg["base_nonce"].upper()},
    ],
    ids=["filename", "base_nonce_uppercase"],
)
def test_changed_metadata_fails_on_chunk_zero(tamper, make_file, tmp_path: Path, aes_key: bytes) -> None:
    src = make_file("secret.bin", 300)
    meta = replace(describe_file(str(src), chunk_size=100), base_nonce=bytes.fromhex("abababababababab"))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sender, relay_in = socket.socketpair()
    relay_out, receiver = socket.socketpair()
    with sender, relay_in, relay_out, receiver:
        # The file is small enough to sit in the socket buffers, so no threads are needed
        send_encrypted_file(sender, str(src), aes_key, meta)
        send_json(relay_out, tamper(recv_json(relay_in)))
        for _ in range(meta.num_chunks):
            forward_message(relay_in, relay_out)

        got = receive_file_meta(receiver)
        out = Path(received_path(str(out_dir), got.filename))
        progress: list[int] = []
        with pytest.raises(InvalidTag):
            receive_encrypted_file(receiver, got, str(out), aes_key, lambda done, *_: progress.append(done))
    assert progress == []
    assert list(out_dir.iterdir()) == []
