"""Keys and sealing for resume negotiation messages."""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.crypto_utils import derive_resume_key, derive_session_key, open_resume_message, seal_resume_message


@pytest.fixture
def session_key() -> bytes:
    return derive_session_key(os.urandom(32), None, os.urandom(32), "sign")


def test_resume_keys_differ_per_role_and_from_the_file_key(session_key: bytes) -> None:
    alice, bob = derive_resume_key(session_key, "alice"), derive_resume_key(session_key, "bob")
    assert len({alice, bob, session_key}) == 3
    assert len(alice) == len(bob) == 32


def test_resume_key_is_deterministic_per_session(session_key: bytes) -> None:
    assert derive_resume_key(session_key, "bob") == derive_resume_key(session_key, "bob")
    assert derive_resume_key(session_key, "bob") != derive_resume_key(os.urandom(32), "bob")


def test_unknown_role_rejected(session_key: bytes) -> None:
    with pytest.raises(ValueError):
        derive_resume_key(session_key, "mallory")


def test_seal_open_roundtrip(session_key: bytes) -> None:
    blob = seal_resume_message(session_key, "bob", b'{"next_chunk": 4}', b"T|request")
    assert open_resume_message(session_key, "bob", blob, b"T|request") == b'{"next_chunk": 4}'


def test_sealing_is_randomised(session_key: bytes) -> None:
    assert seal_resume_message(session_key, "bob", b"x", b"a") != seal_resume_message(session_key, "bob", b"x", b"a")


@pytest.mark.parametrize("case", ["aad", "role", "key", "bitflip", "truncated", "empty"])
def test_open_rejects_anything_but_the_exact_inputs(session_key: bytes, case: str) -> None:
    blob = seal_resume_message(session_key, "bob", b"secret", b"aad")
    args = {
        "aad": (session_key, "bob", blob, b"other"),
        "role": (session_key, "alice", blob, b"aad"),
        "key": (os.urandom(32), "bob", blob, b"aad"),
        "bitflip": (session_key, "bob", blob[:-1] + bytes([blob[-1] ^ 1]), b"aad"),
        "truncated": (session_key, "bob", blob[:20], b"aad"),
        "empty": (session_key, "bob", b"", b"aad"),
    }[case]
    with pytest.raises(InvalidTag):
        open_resume_message(*args)
