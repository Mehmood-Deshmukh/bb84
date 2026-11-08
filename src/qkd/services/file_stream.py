"""
Chunked AES-256-GCM file streaming (the final phase of the wire protocol).

Both functions take the session key and split it with crypto_utils.key_schedule.

Sender: one encrypted metadata message, `tag(16B) + ciphertext` of the canonical
metadata JSON under the metadata subkey (fixed all-zero nonce, which is safe
because that subkey encrypts exactly one message), then one `tag(16B) + ciphertext`
message per chunk under the file subkey. Chunk i is encrypted with
nonce = base_nonce(8B) || i(4B). Every chunk also carries SHA-256 of the canonical
metadata JSON as GCM AAD, which ties the chunk stream to that metadata.

The metadata is encrypted so that a passive observer does not learn the filename
or the exact file size (only the total ciphertext length, about the same thing
rounded to the chunk framing).

There is always at least one chunk (an empty file is sent as one chunk of empty
plaintext), and the receiver rejects metadata whose num_chunks does not match
total_size and chunk_size. Without both rules a metadata message claiming zero
chunks would be accepted without any tag ever being checked.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag

from qkd.core.config import CHUNK_SIZE
from qkd.core.crypto_utils import decrypt_chunk, derive_chunk_nonce, encrypt_chunk, key_schedule
from qkd.services.wire import recv_bytes, send_bytes

TAG_SIZE = 16
METADATA_NONCE = bytes(12)
METADATA_AAD = b"qkd-file-meta-v1"
WIRE_PREFIX = 4  # length prefix in front of every wire message
BASE_NONCE_SIZE = 8
MAX_CHUNKS = 1 << 32  # the chunk counter in the nonce is 4 bytes


class MetadataError(ValueError):
    """The file metadata message is malformed or does not describe the data that followed."""


def expected_chunks(total_size: int, chunk_size: int) -> int:
    """
    Number of chunks used for a file of total_size bytes.

    Always at least 1, so every transfer, even of an empty file, is checked by
    at least one GCM tag.
    """
    return max(1, -(-total_size // chunk_size))


def _int_field(msg: dict, name: str) -> int:
    value = msg.get(name)
    # bool is a subclass of int, so rule it out explicitly
    if not isinstance(value, int) or isinstance(value, bool):
        raise MetadataError(f"metadata field {name!r} must be an integer")
    return value

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
        """
        Parse and check a metadata message.

        Raises MetadataError if a field is missing or has the wrong type, or if
        num_chunks is not expected_chunks(total_size, chunk_size).
        """
        if not isinstance(msg, dict):
            raise MetadataError("metadata must be a JSON object")
        filename = msg.get("filename")
        if not isinstance(filename, str):
            raise MetadataError("metadata field 'filename' must be a string")
        total_size = _int_field(msg, "total_size")
        chunk_size = _int_field(msg, "chunk_size")
        num_chunks = _int_field(msg, "num_chunks")
        if total_size < 0 or chunk_size <= 0:
            raise MetadataError("metadata sizes out of range")
        if num_chunks != expected_chunks(total_size, chunk_size) or num_chunks > MAX_CHUNKS:
            raise MetadataError(
                f"metadata num_chunks={num_chunks} does not match total_size={total_size}, chunk_size={chunk_size}"
            )
        try:
            base_nonce = bytes.fromhex(msg.get("base_nonce"))
        except (TypeError, ValueError):
            raise MetadataError("metadata field 'base_nonce' must be hex") from None
        if len(base_nonce) != BASE_NONCE_SIZE:
            raise MetadataError(f"metadata base_nonce must be {BASE_NONCE_SIZE} bytes")
        return cls(
            filename=filename,
            total_size=total_size,
            chunk_size=chunk_size,
            num_chunks=num_chunks,
            base_nonce=base_nonce,
            aad=metadata_aad(msg),
            sha256=msg.get("sha256"),
            resume_offset=msg.get("resume_offset"),
        )


def _canonical(msg: dict) -> bytes:
    return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")


def metadata_aad(msg: dict) -> bytes:
    """SHA-256 of the canonical JSON (sorted keys, compact, UTF-8) of a metadata message."""
    return hashlib.sha256(_canonical(msg)).digest()


def encrypt_metadata(msg: dict, metadata_key: bytes) -> bytes:
    """`tag + ciphertext` of the canonical metadata JSON. The key must encrypt nothing else."""
    ciphertext, tag = encrypt_chunk(_canonical(msg), metadata_key, METADATA_NONCE, METADATA_AAD)
    return tag + ciphertext


def decrypt_metadata(data: bytes, metadata_key: bytes) -> dict:
    """
    Inverse of encrypt_metadata.

    Raises InvalidTag if the message was changed or encrypted under another key,
    and MetadataError if it decrypts to something that is not JSON.
    """
    if len(data) < TAG_SIZE:
        raise InvalidTag()
    plaintext = decrypt_chunk(data[TAG_SIZE:], metadata_key, METADATA_NONCE, data[:TAG_SIZE], METADATA_AAD)
    try:
        return json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MetadataError("metadata is not valid JSON") from None


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
    num_chunks = expected_chunks(size, chunk_size)
    if num_chunks > MAX_CHUNKS:
        raise ValueError(f"{num_chunks} chunks exceed the {MAX_CHUNKS} the 4-byte nonce counter allows")
    return FileMeta(
        filename=os.path.basename(filepath),
        total_size=size,
        chunk_size=chunk_size,
        num_chunks=num_chunks,
        base_nonce=os.urandom(BASE_NONCE_SIZE),
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
    session_key: bytes,
    meta: FileMeta,
    on_progress: Optional[ProgressCallback] = None,
    start_chunk: int = 0,
) -> int:
    """
    Send the encrypted metadata message followed by the encrypted chunks start_chunk..num_chunks-1.

    Chunk i always uses nonce base_nonce || i, whatever start_chunk is. progress counts from
    the offset: the first callback reports start_chunk + 1 chunks done.
    Returns the bytes put on the wire, including each 4-byte length prefix.
    """
    if not 0 <= start_chunk <= meta.num_chunks:
        raise ValueError(f"start_chunk {start_chunk} is outside 0..{meta.num_chunks}")
    if meta.resume_offset is not None and meta.resume_offset != start_chunk:
        raise ValueError("metadata resume_offset does not match start_chunk")
    keys = key_schedule(session_key)
    msg = meta.to_message()
    encrypted_meta = encrypt_metadata(msg, keys.metadata)
    send_bytes(sock, encrypted_meta)
    wire_bytes = WIRE_PREFIX + len(encrypted_meta)
    aad = metadata_aad(msg)
    sent = min(start_chunk * meta.chunk_size, meta.total_size)
    with open(filepath, "rb") as f:
        f.seek(start_chunk * meta.chunk_size)
        for i in range(start_chunk, meta.num_chunks):
            plaintext = f.read(meta.chunk_size)
            ciphertext, tag = encrypt_chunk(plaintext, keys.file, derive_chunk_nonce(meta.base_nonce, i), aad)
            send_bytes(sock, tag + ciphertext)
            wire_bytes += WIRE_PREFIX + len(tag) + len(ciphertext)
            sent += len(plaintext)
            if on_progress:
                on_progress(i + 1, meta.num_chunks, sent)
    return wire_bytes


def receive_file_meta(sock: socket.socket, session_key: bytes) -> FileMeta:
    """
    Receive, decrypt, and check the metadata message.

    Raises InvalidTag if it was changed in transit and MetadataError if it is malformed.
    """
    return FileMeta.from_message(decrypt_metadata(recv_bytes(sock), key_schedule(session_key).metadata))


def receive_encrypted_file(
    sock: socket.socket,
    meta: FileMeta,
    output_path: str,
    session_key: bytes,
    on_progress: Optional[ProgressCallback] = None,
) -> int:
    """
    Receive and decrypt every chunk into output_path. Returns bytes written.

    Raises cryptography.exceptions.InvalidTag if any chunk fails authentication,
    including when meta.aad does not match the sender's metadata, and
    MetadataError if the decrypted size differs from meta.total_size. The
    partial output file is removed in both cases.
    """
    file_key = key_schedule(session_key).file
    written = 0
    try:
        with open(output_path, "wb") as f:
            for i in range(meta.num_chunks):
                data = recv_bytes(sock)
                tag, ciphertext = data[:TAG_SIZE], data[TAG_SIZE:]
                plaintext = decrypt_chunk(ciphertext, file_key, derive_chunk_nonce(meta.base_nonce, i), tag, meta.aad)
                f.write(plaintext)
                written += len(plaintext)
                if on_progress:
                    on_progress(i + 1, meta.num_chunks, written)
        if written != meta.total_size:
            raise MetadataError(f"received {written} bytes, metadata promised {meta.total_size}")
    except Exception:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise
    return written


def received_path(output_dir: str, filename: str) -> str:
    """Where Bob stores a received file. Only the basename of the sender's name is used."""
    return os.path.join(output_dir, f"received_{os.path.basename(filename)}")
