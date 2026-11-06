"""Key derivation: Toeplitz privacy amplification, HKDF to the session key, and the key schedule."""

from __future__ import annotations

import os
import secrets

import pytest

from qkd.core.bb84_protocol import bits_to_bytes, privacy_amplification, toeplitz_hash, toeplitz_seed_bytes
from qkd.core.crypto_utils import derive_aes_key, key_schedule


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


def _toeplitz_reference(bits: list[int], seed: bytes, m: int) -> bytes:
    """Straight from the definition: y[i] = sum_j T[i][j] x[j] mod 2, with T[i][j] = s[i - j + n - 1]."""
    n = len(bits)
    s = [(seed[b // 8] >> (7 - b % 8)) & 1 for b in range(n + m - 1)]
    y = [sum(s[i - j + n - 1] & bits[j] for j in range(n)) % 2 for i in range(m)]
    return bits_to_bytes(y)


@pytest.mark.parametrize("n", [1, 7, 64, 300, 1001])
def test_toeplitz_hash_matches_matrix_definition(n: int) -> None:
    bits = [secrets.randbelow(2) for _ in range(n)]
    seed = os.urandom(toeplitz_seed_bytes(n, 256))
    assert toeplitz_hash(bits, seed, 256) == _toeplitz_reference(bits, seed, 256)


def test_toeplitz_hash_is_linear_over_gf2() -> None:
    # Linearity is what makes a random Toeplitz matrix two-universal
    n = 500
    a = [secrets.randbelow(2) for _ in range(n)]
    b = [secrets.randbelow(2) for _ in range(n)]
    seed = os.urandom(toeplitz_seed_bytes(n, 256))
    ha, hb = toeplitz_hash(a, seed, 256), toeplitz_hash(b, seed, 256)
    hab = toeplitz_hash([x ^ y for x, y in zip(a, b)], seed, 256)
    assert hab == bytes(x ^ y for x, y in zip(ha, hb))


def test_toeplitz_seed_length_is_checked() -> None:
    with pytest.raises(ValueError, match="seed must be"):
        toeplitz_hash([1, 0, 1], b"\x00" * 3, 256)
    with pytest.raises(ValueError, match="multiple of 8"):
        toeplitz_hash([1, 0, 1], b"\x00", 7)


def test_privacy_amplification_uses_a_full_fresh_seed() -> None:
    bits = [1, 0] * 1000
    salt, key = privacy_amplification(bits)
    assert len(salt) == toeplitz_seed_bytes(len(bits), 256)
    assert len(key) == 32
    assert key == toeplitz_hash(bits, salt, 256)
    assert privacy_amplification(bits)[0] != salt


def test_privacy_amplification_same_bits_and_salt_give_same_key() -> None:
    bits = [1, 0] * 300
    salt, key_a = privacy_amplification(bits)
    _, key_b = privacy_amplification(bits, salt=salt)
    assert key_a == key_b


def test_privacy_amplification_one_bit_difference_changes_key() -> None:
    bits = [1, 0] * 300
    salt, key_a = privacy_amplification(bits)
    _, key_b = privacy_amplification([bits[0] ^ 1] + bits[1:], salt=salt)
    assert key_a != key_b


def test_privacy_amplification_respects_target_length() -> None:
    _, key = privacy_amplification([1, 0] * 300, target_bits=128)
    assert len(key) == 16


def test_key_schedule_subkeys_are_distinct_and_deterministic() -> None:
    k = os.urandom(32)
    a, b = key_schedule(k), key_schedule(k)
    assert a == b
    assert len({a.file, a.metadata, a.confirm, k}) == 4
    assert key_schedule(os.urandom(32)).file != a.file


def test_bits_to_bytes_pads_on_the_right() -> None:
    assert bits_to_bytes([1]) == b"\x80"
    assert bits_to_bytes([1, 0, 1, 0, 1, 0, 1, 0, 1]) == b"\xaa\x80"
    assert bits_to_bytes([]) == b""
