"""Per-chunk nonce construction: base_nonce (8 bytes) || chunk index (4 bytes, big-endian)."""

from __future__ import annotations

import os
import struct

import pytest

from qkd.core.crypto_utils import derive_chunk_nonce


@pytest.fixture
def base_nonce() -> bytes:
    return os.urandom(8)


def test_nonce_is_96_bits(base_nonce: bytes) -> None:
    assert all(len(derive_chunk_nonce(base_nonce, i)) == 12 for i in range(100))


def test_nonce_layout(base_nonce: bytes) -> None:
    nonce = derive_chunk_nonce(base_nonce, 0x01020304)
    assert nonce[:8] == base_nonce
    assert nonce[8:] == bytes([1, 2, 3, 4])


def test_nonces_unique_within_transfer(base_nonce: bytes) -> None:
    nonces = {derive_chunk_nonce(base_nonce, i) for i in range(10_000)}
    assert len(nonces) == 10_000


def test_different_base_nonces_differ() -> None:
    a, b = os.urandom(8), os.urandom(8)
    assert all(derive_chunk_nonce(a, i) != derive_chunk_nonce(b, i) for i in range(10))


def test_counter_limit(base_nonce: bytes) -> None:
    derive_chunk_nonce(base_nonce, 2**32 - 1)
    with pytest.raises(struct.error):
        derive_chunk_nonce(base_nonce, 2**32)
