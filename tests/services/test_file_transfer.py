"""
End-to-end chunked file transfer over a localhost TCP socket.

Runs the final phase of the protocol (encrypted metadata + encrypted chunks)
with a pre-shared session key, using the same file_stream module as Alice and Bob.
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
from qkd.core.crypto_utils import derive_aes_key, key_schedule
from qkd.services.file_stream import (
    FileMeta,
    MetadataError,
    describe_file,
    encrypt_metadata,
    receive_encrypted_file,
    receive_file_meta,
    received_path,
    send_encrypted_file,
)
from qkd.services.wire import forward_message, recv_bytes, send_bytes

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
            meta = receive_file_meta(conn, recv_key)
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


def test_empty_file_is_sent_as_one_authenticated_chunk(make_file) -> None:
    assert describe_file(str(make_file("empty.bin", 0))).num_chunks == 1


def _relay(src: Path, out_dir: Path, aes_key: bytes, rewrite) -> list[int]:
    """
    Send src through an in-process relay that rewrites the raw metadata message, then receive it.

    Returns the chunks Bob reported. Raises whatever receive_file_meta or
    receive_encrypted_file raises.
    """
    meta = replace(describe_file(str(src), chunk_size=100), base_nonce=bytes.fromhex("abababababababab"))
    sender, relay_in = socket.socketpair()
    relay_out, receiver = socket.socketpair()
    progress: list[int] = []
    with sender, relay_in, relay_out, receiver:
        # The file is small enough to sit in the socket buffers, so no threads are needed
        send_encrypted_file(sender, str(src), aes_key, meta)
        send_bytes(relay_out, rewrite(recv_bytes(relay_in)))
        for _ in range(meta.num_chunks):
            forward_message(relay_in, relay_out)

        got = receive_file_meta(receiver, aes_key)
        out = Path(received_path(str(out_dir), got.filename))
        receive_encrypted_file(receiver, got, str(out), aes_key, lambda done, *_: progress.append(done))
    return progress


def _flip_last_byte(raw: bytes) -> bytes:
    return raw[:-1] + bytes([raw[-1] ^ 1])


def _other_key(raw: bytes) -> bytes:
    msg = {"filename": "evil.bin", "total_size": 300, "chunk_size": 100, "num_chunks": 3, "base_nonce": "ab" * 8}
    return encrypt_metadata(msg, os.urandom(32))


def _plaintext_v1(raw: bytes) -> bytes:
    # What a protocol v1 sender put on the wire: the metadata as plain JSON
    return b'{"base_nonce":"abababababababab","chunk_size":100,"filename":"evil.bin","num_chunks":3,"total_size":300}'


@pytest.mark.parametrize("rewrite", [_flip_last_byte, _other_key, _plaintext_v1],
                         ids=["bit_flip", "other_key", "plaintext_v1"])
def test_changed_metadata_fails_before_any_file_is_created(rewrite, make_file, tmp_path: Path, aes_key: bytes) -> None:
    src = make_file("secret.bin", 300)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(InvalidTag):
        _relay(src, out_dir, aes_key, rewrite)
    assert list(out_dir.iterdir()) == []


def test_metadata_is_not_sent_in_clear(make_file, aes_key: bytes) -> None:
    src = make_file("quarterly_secret_report.pdf", 300)
    sender, receiver = socket.socketpair()
    with sender, receiver:
        send_encrypted_file(sender, str(src), aes_key, describe_file(str(src), chunk_size=100))
        raw = recv_bytes(receiver)
    assert b"quarterly_secret_report" not in raw
    assert b"total_size" not in raw and b"num_chunks" not in raw


@pytest.mark.parametrize("size", [0, 300], ids=["empty", "300B"])
def test_zero_chunk_metadata_is_rejected(size: int, make_file, tmp_path: Path, aes_key: bytes) -> None:
    """
    Regression: metadata claiming zero chunks used to skip every tag check, so a
    relay could make Bob write an empty file under any name it chose. Metadata is
    now encrypted, so a relay cannot forge it; this encrypts the bad metadata with
    the right key to check the count rule still holds on its own.
    """
    src = make_file("secret.bin", size)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    bad = {"filename": "invoice_PAID.pdf", "total_size": 0, "chunk_size": 100, "num_chunks": 0, "base_nonce": "ab" * 8}
    with pytest.raises(MetadataError, match="num_chunks"):
        _relay(src, out_dir, aes_key, lambda raw: encrypt_metadata(bad, key_schedule(aes_key).metadata))
    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize(
    "msg",
    [
        "not an object",
        {"total_size": 0, "chunk_size": 100, "num_chunks": 1, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": "0", "chunk_size": 100, "num_chunks": 1, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": 0, "chunk_size": 0, "num_chunks": 1, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": -1, "chunk_size": 100, "num_chunks": 1, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": 300, "chunk_size": 100, "num_chunks": 2, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": 300, "chunk_size": 100, "num_chunks": True, "base_nonce": "ab" * 8},
        {"filename": "f", "total_size": 0, "chunk_size": 100, "num_chunks": 1, "base_nonce": "zz"},
        {"filename": "f", "total_size": 0, "chunk_size": 100, "num_chunks": 1, "base_nonce": "ab" * 4},
    ],
    ids=["not_dict", "no_filename", "str_size", "zero_chunk_size", "negative_size",
         "count_mismatch", "bool_count", "bad_hex", "short_nonce"],
)
def test_malformed_metadata_is_rejected(msg) -> None:
    with pytest.raises(MetadataError):
        FileMeta.from_message(msg)
