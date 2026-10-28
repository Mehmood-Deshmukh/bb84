"""
Chunked AES-256-GCM file streaming (the final phase of the wire protocol).

Sender: one JSON metadata message, then one length-prefixed `tag(16B) + ciphertext`
message per chunk. Chunk i is encrypted with nonce = base_nonce(8B) || i(4B).
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from qkd.core.config import CHUNK_SIZE
from qkd.core.crypto_utils import decrypt_chunk, derive_chunk_nonce, encrypt_chunk
from qkd.services.wire import recv_bytes, recv_json, send_bytes, send_json

TAG_SIZE = 16

# Called after each chunk with (chunks_done, num_chunks, bytes_done)
ProgressCallback = Callable[[int, int, int], None]


@dataclass(frozen=True)
class FileMeta:
    filename: str
    total_size: int
    chunk_size: int
    num_chunks: int
    base_nonce: bytes

    def to_message(self) -> dict:
        return {
            "filename": self.filename,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "num_chunks": self.num_chunks,
            "base_nonce": self.base_nonce.hex(),
        }

    @classmethod
    def from_message(cls, msg: dict) -> "FileMeta":
        return cls(
            filename=msg["filename"],
            total_size=msg["total_size"],
            chunk_size=msg["chunk_size"],
            num_chunks=msg["num_chunks"],
            base_nonce=bytes.fromhex(msg["base_nonce"]),
        )


def describe_file(filepath: str, chunk_size: int = CHUNK_SIZE) -> FileMeta:
    """Build the metadata message for a file, with a fresh random base nonce."""
    size = os.path.getsize(filepath)
    return FileMeta(
        filename=os.path.basename(filepath),
        total_size=size,
        chunk_size=chunk_size,
        num_chunks=(size + chunk_size - 1) // chunk_size,
        base_nonce=os.urandom(8),
    )


def send_encrypted_file(
    sock: socket.socket,
    filepath: str,
    aes_key: bytes,
    meta: FileMeta,
    on_progress: Optional[ProgressCallback] = None,
) -> None:
    """Send the metadata message followed by every encrypted chunk."""
    send_json(sock, meta.to_message())
    sent = 0
    with open(filepath, "rb") as f:
        for i in range(meta.num_chunks):
            plaintext = f.read(meta.chunk_size)
            ciphertext, tag = encrypt_chunk(plaintext, aes_key, derive_chunk_nonce(meta.base_nonce, i))
            send_bytes(sock, tag + ciphertext)
            sent += len(plaintext)
            if on_progress:
                on_progress(i + 1, meta.num_chunks, sent)


def receive_file_meta(sock: socket.socket) -> FileMeta:
    return FileMeta.from_message(recv_json(sock))


def receive_encrypted_file(
    sock: socket.socket,
    meta: FileMeta,
    output_path: str,
    aes_key: bytes,
    on_progress: Optional[ProgressCallback] = None,
) -> int:
    """
    Receive and decrypt every chunk into output_path. Returns bytes written.

    Raises cryptography.exceptions.InvalidTag if any chunk fails authentication.
    The partial output file is removed in that case.
    """
    written = 0
    try:
        with open(output_path, "wb") as f:
            for i in range(meta.num_chunks):
                data = recv_bytes(sock)
                tag, ciphertext = data[:TAG_SIZE], data[TAG_SIZE:]
                plaintext = decrypt_chunk(ciphertext, aes_key, derive_chunk_nonce(meta.base_nonce, i), tag)
                f.write(plaintext)
                written += len(plaintext)
                if on_progress:
                    on_progress(i + 1, meta.num_chunks, written)
    except Exception:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise
    return written


def received_path(output_dir: str, filename: str) -> str:
    """Where Bob stores a received file. Only the basename of the sender's name is used."""
    return os.path.join(output_dir, f"received_{os.path.basename(filename)}")
