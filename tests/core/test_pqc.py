"""Tests for ML-DSA-65 and ML-KEM-768 post-quantum cryptographic primitives."""

from __future__ import annotations

import hashlib

import pytest

from qkd.core.pqc import (
    fingerprint,
    kem_decaps,
    kem_encaps,
    kem_keygen,
    sig_keygen,
    sign,
    verify,
)


def test_kem_roundtrip() -> None:
    pk, sk = kem_keygen()
    ss, ct = kem_encaps(pk)
    decapped_ss = kem_decaps(sk, ct)
    assert decapped_ss == ss
    assert len(ss) == 32


def test_kem_wrong_private_key() -> None:
    pk1, sk1 = kem_keygen()
    _, sk2 = kem_keygen()
    ss, ct = kem_encaps(pk1)

    # ML-KEM uses implicit rejection (FIPS 203): decapsulation with a different
    # private key yields a deterministic 32-byte secret that does not match ss.
    wrong_ss = kem_decaps(sk2, ct)
    assert isinstance(wrong_ss, bytes)
    assert len(wrong_ss) == 32
    assert wrong_ss != ss

    # Corrupted ciphertext also yields a different secret
    corrupted_ct = bytearray(ct)
    corrupted_ct[0] ^= 1
    corrupted_ss = kem_decaps(sk1, bytes(corrupted_ct))
    assert isinstance(corrupted_ss, bytes)
    assert len(corrupted_ss) == 32
    assert corrupted_ss != ss

    # Invalid lengths raise ValueError
    with pytest.raises(ValueError):
        kem_decaps(b"short_sk", ct)
    with pytest.raises(ValueError):
        kem_decaps(sk1, b"short_ct")
    with pytest.raises(ValueError):
        kem_encaps(b"short_pk")


def test_signature_roundtrip() -> None:
    pk, seed = sig_keygen()
    msg = b"BB84 classical channel transcript payload"
    signature = sign(seed, msg)
    assert verify(pk, msg, signature) is True


def test_verify_returns_false_on_tampered_inputs() -> None:
    pk, seed = sig_keygen()
    msg = b"Authentic message"
    signature = sign(seed, msg)

    # Flip one bit in the message
    bad_msg = bytearray(msg)
    bad_msg[0] ^= 1
    assert verify(pk, bytes(bad_msg), signature) is False

    # Flip one bit in the signature
    bad_sig = bytearray(signature)
    bad_sig[0] ^= 1
    assert verify(pk, msg, bytes(bad_sig)) is False

    # Flip one bit in the public key
    bad_pk = bytearray(pk)
    bad_pk[0] ^= 1
    assert verify(bytes(bad_pk), msg, signature) is False

    # Wrong-length inputs must return False and never raise
    assert verify(pk, msg, b"") is False
    assert verify(pk, msg, b"short_sig") is False
    assert verify(pk, msg, signature + b"extra") is False
    assert verify(b"", msg, signature) is False
    assert verify(b"short_pk", msg, signature) is False
    assert verify(pk + b"extra", msg, signature) is False


def test_sign_twice_verifies_both_times() -> None:
    pk, seed = sig_keygen()
    msg = b"Consistent verification test"
    sig1 = sign(seed, msg)
    sig2 = sign(seed, msg)

    assert verify(pk, msg, sig1) is True
    assert verify(pk, msg, sig2) is True


def test_fingerprint() -> None:
    pk1, _ = sig_keygen()
    pk2, _ = sig_keygen()

    fp1 = fingerprint(pk1)
    fp2 = fingerprint(pk2)

    # 8 groups of 4 lowercase hex digits joined by '-'
    parts = fp1.split("-")
    assert len(parts) == 8
    for part in parts:
        assert len(part) == 4
        assert all(c in "0123456789abcdef" for c in part)

    # Deterministic
    assert fingerprint(pk1) == fp1

    # Different keys yield different fingerprints
    assert fp1 != fp2

    # Matches first 16 bytes of SHA-256(pk)
    expected_hex = hashlib.sha256(pk1).digest()[:16].hex()
    expected_fp = "-".join(expected_hex[i : i + 4] for i in range(0, 32, 4))
    assert fp1 == expected_fp


def test_sizes() -> None:
    sig_pk, sig_seed = sig_keygen()
    sig = sign(sig_seed, b"payload")
    assert len(sig) == 3309  # ML-DSA-65 signature length
    assert len(sig_seed) == 32  # ML-DSA-65 private seed length
    assert len(sig_pk) == 1952  # ML-DSA-65 public key length

    kem_pk, kem_sk = kem_keygen()
    assert len(kem_pk) == 1184  # ML-KEM-768 public key length
    assert len(kem_sk) == 64  # ML-KEM-768 seed / private key length

    ss, ct = kem_encaps(kem_pk)
    assert len(ct) == 1088  # ML-KEM-768 ciphertext length
    assert len(ss) == 32  # Shared secret length
