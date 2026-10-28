"""Key derivation: SHA-256 privacy amplification, then HKDF to the AES-256 key."""

from __future__ import annotations

import hashlib
import os

from qkd.core.bb84_protocol import bits_to_bytes, privacy_amplification
from qkd.core.crypto_utils import derive_aes_key


def test_hkdf_is_deterministic_and_256_bit() -> None:
    raw = os.urandom(32)
    key = derive_aes_key(raw)
    assert len(key) == 32
    assert derive_aes_key(raw) == key


def test_hkdf_info_separates_domains() -> None:
    raw = os.urandom(32)
    assert derive_aes_key(raw, info=b"a") != derive_aes_key(raw, info=b"b")


def test_hkdf_different_inputs_differ() -> None:
    assert derive_aes_key(os.urandom(32)) != derive_aes_key(os.urandom(32))


def test_privacy_amplification_matches_sha256_of_salt_and_bits() -> None:
    bits = [1, 0, 1, 1, 0, 0, 1, 0, 1]
    salt = bytes(range(8))
    out_salt, key = privacy_amplification(bits, salt=salt)
    assert out_salt == salt
    assert key == hashlib.sha256(salt + bits_to_bytes(bits)).digest()


def test_privacy_amplification_same_bits_and_salt_give_same_key() -> None:
    bits = [1, 0] * 30
    salt, key_a = privacy_amplification(bits)
    _, key_b = privacy_amplification(bits, salt=salt)
    assert key_a == key_b
    assert len(salt) == 8


def test_privacy_amplification_one_bit_difference_changes_key() -> None:
    bits = [1, 0] * 30
    salt, key_a = privacy_amplification(bits)
    _, key_b = privacy_amplification([bits[0] ^ 1] + bits[1:], salt=salt)
    assert key_a != key_b


def test_bits_to_bytes_pads_on_the_right() -> None:
    assert bits_to_bytes([1]) == b"\x80"
    assert bits_to_bytes([1, 0, 1, 0, 1, 0, 1, 0, 1]) == b"\xaa\x80"
    assert bits_to_bytes([]) == b""
