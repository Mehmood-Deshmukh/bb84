"""
Chunked AES-256-GCM file streaming (the final phase of the wire protocol).

Sender: one JSON metadata message, then one length-prefixed `tag(16B) + ciphertext`
message per chunk. Chunk i is encrypted with nonce = base_nonce(8B) || i(4B).
Every chunk carries SHA-256 of the canonical metadata JSON as GCM AAD, so a changed
metadata message fails authentication on chunk 0.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from qkd.core.config import CHUNK_SIZE
from qkd.core.crypto_utils import decrypt_chunk, derive_chunk_nonce, encrypt_chunk
from qkd.services.wire import recv_bytes, recv_json, send_bytes, send_json

TAG_SIZE = 16
MAX_CHUNKS = 2**32  # the chunk counter in the nonce is 4 bytes

# Called after each chunk with (chunks_done, num_chunks, bytes_done)
ProgressCallback = Callable[[int, int, int], None]


@dataclass(frozen=True)
class FileMeta:
    filename: str
    total_size: int
    chunk_size: int
    num_chunks: int
    base_nonce: bytes
    # metadata_aad() of the message this was parsed from (set by from_message)
    aad: bytes = field(default=b"", compare=False, repr=False)
    # Resume mode only. Both are left out of the message when None, so a transfer without
    # resume sends exactly the metadata (and therefore the AAD) it always did.
    sha256: Optional[str] = None  # hex SHA-256 of the whole file
    resume_offset: Optional[int] = None  # first chunk index sent in this session

    def to_message(self) -> dict:
        msg = {
            "filename": self.filename,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "num_chunks": self.num_chunks,
            "base_nonce": self.base_nonce.hex(),
        }
        if self.sha256 is not None:
            msg["sha256"] = self.sha256
        if self.resume_offset is not None:
            msg["resume_offset"] = self.resume_offset
        return msg

    @classmethod
    def from_message(cls, msg: dict) -> "FileMeta":
        return cls(
            filename=msg["filename"],
            total_size=msg["total_size"],
            chunk_size=msg["chunk_size"],
            num_chunks=msg["num_chunks"],
            base_nonce=bytes.fromhex(msg["base_nonce"]),
            aad=metadata_aad(msg),
            sha256=msg.get("sha256"),
            resume_offset=msg.get("resume_offset"),
        )


def metadata_aad(msg: dict) -> bytes:
    """SHA-256 of the canonical JSON (sorted keys, compact, UTF-8) of a metadata message."""
    return hashlib.sha256(json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()


def describe_file(
    filepath: str,
    chunk_size: int = CHUNK_SIZE,
    *,
    with_sha256: bool = False,
    resume_offset: Optional[int] = None,
) -> FileMeta:
    """
    Build the metadata message for a file, with a fresh random base nonce.

    Every call draws a new base nonce, so a resumed session never repeats the nonces of the
    session it continues. with_sha256 and resume_offset are for resume mode (see FileMeta).
    """
    size = os.path.getsize(filepath)
    num_chunks = (size + chunk_size - 1) // chunk_size
    if num_chunks > MAX_CHUNKS:
        raise ValueError(f"{num_chunks} chunks exceed the {MAX_CHUNKS} the 4-byte nonce counter allows")
    return FileMeta(
        filename=os.path.basename(filepath),
        total_size=size,
        chunk_size=chunk_size,
        num_chunks=num_chunks,
        base_nonce=os.urandom(8),
        sha256=file_sha256(filepath) if with_sha256 else None,
        resume_offset=resume_offset,
    )


def file_sha256(filepath: str, limit: Optional[int] = None) -> str:
    """Hex SHA-256 of a file, or of its first `limit` bytes."""
    digest = hashlib.sha256()
    remaining = limit
    with open(filepath, "rb") as f:
        while remaining is None or remaining > 0:
            block = f.read(1 << 20 if remaining is None else min(1 << 20, remaining))
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    return digest.hexdigest()


def send_encrypted_file(
    sock: socket.socket,
    filepath: str,
    aes_key: bytes,
    meta: FileMeta,
    on_progress: Optional[ProgressCallback] = None,
    start_chunk: int = 0,
) -> None:
    """
    Send the metadata message followed by the encrypted chunks start_chunk..num_chunks-1.

    Chunk i always uses nonce base_nonce || i, whatever start_chunk is. progress counts from
    the offset: the first callback reports start_chunk + 1 chunks done.
    """
    if not 0 <= start_chunk <= meta.num_chunks:
        raise ValueError(f"start_chunk {start_chunk} is outside 0..{meta.num_chunks}")
    if meta.resume_offset is not None and meta.resume_offset != start_chunk:
        raise ValueError("metadata resume_offset does not match start_chunk")
    msg = meta.to_message()
    send_json(sock, msg)
    aad = metadata_aad(msg)
    sent = min(start_chunk * meta.chunk_size, meta.total_size)
    with open(filepath, "rb") as f:
        f.seek(start_chunk * meta.chunk_size)
        for i in range(start_chunk, meta.num_chunks):
            plaintext = f.read(meta.chunk_size)
            ciphertext, tag = encrypt_chunk(plaintext, aes_key, derive_chunk_nonce(meta.base_nonce, i), aad)
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

    Raises cryptography.exceptions.InvalidTag if any chunk fails authentication,
    including when meta.aad does not match the sender's metadata. The partial
    output file is removed in that case.
    """
    written = 0
    try:
        with open(output_path, "wb") as f:
            for i in range(meta.num_chunks):
                data = recv_bytes(sock)
                tag, ciphertext = data[:TAG_SIZE], data[TAG_SIZE:]
                plaintext = decrypt_chunk(ciphertext, aes_key, derive_chunk_nonce(meta.base_nonce, i), tag, meta.aad)
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
