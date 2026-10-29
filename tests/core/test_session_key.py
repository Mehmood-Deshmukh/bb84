"""Tests for derive_session_key hybrid HKDF key derivation."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qkd.core.crypto_utils import derive_aes_key, derive_session_key


def test_derive_session_key_deterministic() -> None:
    qkd_key = os.urandom(32)
    kem_ss = os.urandom(32)
    t_hash = os.urandom(32)

    k1 = derive_session_key(qkd_key, kem_ss, t_hash, mode="hybrid")
    k2 = derive_session_key(qkd_key, kem_ss, t_hash, mode="hybrid")
    assert len(k1) == 32
    assert k1 == k2

    k_sign1 = derive_session_key(qkd_key, None, t_hash, mode="sign")
    k_sign2 = derive_session_key(qkd_key, None, t_hash, mode="sign")
    assert len(k_sign1) == 32
    assert k_sign1 == k_sign2

    k_none1 = derive_session_key(qkd_key, None, t_hash, mode="none")
    k_none2 = derive_session_key(qkd_key, None, t_hash, mode="none")
    assert len(k_none1) == 32
    assert k_none1 == k_none2


def test_hybrid_changes_when_any_input_changes() -> None:
    qkd_key = os.urandom(32)
    kem_ss = os.urandom(32)
    t_hash = os.urandom(32)

    base = derive_session_key(qkd_key, kem_ss, t_hash, mode="hybrid")

    # Change qkd_key
    assert derive_session_key(os.urandom(32), kem_ss, t_hash, mode="hybrid") != base

    # Change kem_ss
    assert derive_session_key(qkd_key, os.urandom(32), t_hash, mode="hybrid") != base

    # Change transcript_hash
    assert derive_session_key(qkd_key, kem_ss, os.urandom(32), mode="hybrid") != base


def test_sign_mode_ignores_kem_ss() -> None:
    qkd_key = os.urandom(32)
    t_hash = os.urandom(32)

    k_none_ss = derive_session_key(qkd_key, None, t_hash, mode="sign")
    k_with_ss = derive_session_key(qkd_key, os.urandom(32), t_hash, mode="sign")

    assert k_none_ss == k_with_ss


def test_sign_and_hybrid_keys_differ() -> None:
    qkd_key = os.urandom(32)
    kem_ss = os.urandom(32)
    t_hash = os.urandom(32)

    k_sign = derive_session_key(qkd_key, kem_ss, t_hash, mode="sign")
    k_hybrid = derive_session_key(qkd_key, kem_ss, t_hash, mode="hybrid")

    assert k_sign != k_hybrid


def test_none_mode_equals_derive_aes_key() -> None:
    qkd_key = os.urandom(32)
    t_hash = os.urandom(32)

    k_none = derive_session_key(qkd_key, None, t_hash, mode="none")
    assert k_none == derive_aes_key(qkd_key)


def test_invalid_mode_raises() -> None:
    qkd_key = os.urandom(32)
    kem_ss = os.urandom(32)
    t_hash = os.urandom(32)

    with pytest.raises(ValueError, match="Invalid mode"):
        derive_session_key(qkd_key, kem_ss, t_hash, mode="unsupported")


def test_hybrid_mode_missing_kem_ss_raises() -> None:
    qkd_key = os.urandom(32)
    t_hash = os.urandom(32)

    with pytest.raises(ValueError, match="kem_ss"):
        derive_session_key(qkd_key, None, t_hash, mode="hybrid")


def test_known_answer_hkdf() -> None:
    qkd_key = os.urandom(32)
    kem_ss = os.urandom(32)
    t_hash = os.urandom(32)

    # Independent HKDF computation for hybrid mode
    expected_hybrid = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=t_hash,
        info=b"bb84-mlkem768-hybrid-v1",
    ).derive(qkd_key + kem_ss)
    assert derive_session_key(qkd_key, kem_ss, t_hash, mode="hybrid") == expected_hybrid


def test_known_answer_hkdf_sign() -> None:
    qkd_key = os.urandom(32)
    t_hash = os.urandom(32)

    # Sign mode has its own info label, separate from hybrid's, for domain separation.
    expected_sign = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=t_hash,
        info=b"bb84-sign-v1",
    ).derive(qkd_key)
    assert derive_session_key(qkd_key, None, t_hash, mode="sign") == expected_sign
