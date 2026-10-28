"""
Chunked AES-256-GCM encryption/decryption.

Encrypt -> decrypt round trips at sizes around the chunk boundary and up to
100 MB, plus tamper detection through the GCM authentication tag.
"""

from __future__ import annotations

import math
import os

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.config import CHUNK_SIZE
from qkd.core.crypto_utils import decrypt_chunk, derive_aes_key, derive_chunk_nonce, encrypt_chunk

MB = 1024 * 1024


@pytest.fixture
def base_nonce() -> bytes:
    return os.urandom(8)


def roundtrip(data: bytes, key: bytes, base_nonce: bytes) -> bytes:
    """Encrypt data in CHUNK_SIZE pieces, then decrypt and reassemble."""
    num_chunks = math.ceil(len(data) / CHUNK_SIZE)
    encrypted = [
        encrypt_chunk(data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE], key, derive_chunk_nonce(base_nonce, i))
        for i in range(num_chunks)
    ]
    return b"".join(
        decrypt_chunk(ct, key, derive_chunk_nonce(base_nonce, i), tag) for i, (ct, tag) in enumerate(encrypted)
    )


@pytest.mark.parametrize(
    "size",
    [0, 1, 100, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 1 * MB, 10 * MB, 100 * MB],
    ids=["empty", "1B", "100B", "chunk", "chunk+1", "2chunks", "1MB", "10MB", "100MB"],
)
def test_roundtrip(size: int, aes_key: bytes, base_nonce: bytes) -> None:
    data = os.urandom(size)
    assert roundtrip(data, aes_key, base_nonce) == data


@pytest.fixture
def sealed(aes_key: bytes, base_nonce: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = derive_chunk_nonce(base_nonce, 0)
    ct, tag = encrypt_chunk(os.urandom(1000), aes_key, nonce)
    return nonce, ct, tag


def test_tampered_ciphertext_detected(sealed, aes_key: bytes) -> None:
    nonce, ct, tag = sealed
    with pytest.raises(InvalidTag):
        decrypt_chunk(bytes([ct[0] ^ 0xFF]) + ct[1:], aes_key, nonce, tag)


def test_tampered_tag_detected(sealed, aes_key: bytes) -> None:
    nonce, ct, tag = sealed
    with pytest.raises(InvalidTag):
        decrypt_chunk(ct, aes_key, nonce, bytes([tag[0] ^ 0xFF]) + tag[1:])


def test_wrong_nonce_detected(sealed, aes_key: bytes, base_nonce: bytes) -> None:
    _, ct, tag = sealed
    with pytest.raises(InvalidTag):
        decrypt_chunk(ct, aes_key, derive_chunk_nonce(base_nonce, 1), tag)


def test_wrong_key_detected(sealed) -> None:
    nonce, ct, tag = sealed
    with pytest.raises(InvalidTag):
        decrypt_chunk(ct, derive_aes_key(os.urandom(32)), nonce, tag)


def test_ciphertext_length_matches_plaintext(aes_key: bytes, base_nonce: bytes) -> None:
    ct, tag = encrypt_chunk(b"x" * 123, aes_key, derive_chunk_nonce(base_nonce, 0))
    assert len(ct) == 123
    assert len(tag) == 16
