"""
Tamper-acceptance tests (Gate 3): honest Alice and Bob (hybrid, pinned to each
other) with the generic proxy rewriting exactly one classical message.

For the six classical tampers the QBER threshold is set above 1.0 on both sides, so
the QBER check can never abort — the only thing that can catch the change is the
transcript divergence surfacing in the 4b signature. (A tampered classical message
is hashed by one side as sent and the other as received, so their transcripts T
differ, and Bob's signature over his T fails to verify against Alice's T.)

The metadata tamper uses the normal threshold: the handshake succeeds and the change
to the (encrypted) file metadata is caught by its own GCM tag instead.

Each tamper asserts it actually changed the message, so a no-op tamper fails loudly
rather than passing silently. Runs use the Qiskit Aer simulator with 64 qubits.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.config import ProtocolParams
from qkd.usecases.common import PeerAuthError
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys, proxy

# Threshold above 1.0 disables the QBER abort; fraction 0.5 keeps the sample large
# enough that the index-swap tampers always have two elements to swap.
# These runs test authentication and tamper mechanics, not key length, so they use a
# small N with the finite-key gate off. tests/invariants/test_finite_key_gate.py and the
# honest-transfer tests exercise the gate at the default N.
TAMPER_PARAMS = ProtocolParams(num_qubits=64, qber_sample_fraction=0.5, qber_threshold=1.01, enforce_finite_key=False)
META_PARAMS = ProtocolParams(num_qubits=64, enforce_finite_key=False)  # metadata decryption is the detector


def _changed(new: Any, old: Any) -> Any:
    assert new != old, "tamper did not change the message"
    return new


def t_bases(bases: list) -> list:
    out = list(bases)
    out[0] = "x" if out[0] == "+" else "+"
    return _changed(out, bases)


def t_matching(m: list) -> list:
    out = list(m)
    out[0], out[1] = out[1], out[0]  # distinct sorted indices, so this reorders
    return _changed(out, m)


def t_sample_indices(msg: dict) -> dict:
    idx = list(msg["sample_indices"])
    idx[0], idx[1] = idx[1], idx[0]
    return _changed({**msg, "sample_indices": idx}, msg)


def t_sample_bits(msg: dict) -> dict:
    bits = list(msg["sample_bits"])
    bits[0] ^= 1
    return _changed({**msg, "sample_bits": bits}, msg)


def t_qber(msg: dict) -> dict:
    return _changed({**msg, "qber": 0.05}, msg)  # honest qber is exactly 0.0


def t_salt(msg: dict) -> dict:
    salt = msg["salt"]
    first = "1" if salt[0] == "0" else "0"  # stays valid hex
    return _changed({**msg, "salt": first + salt[1:]}, msg)


def _run(parallel, src: Path, out_dir: Path, keys, params, **proxy_kwargs):
    """Honest Alice/Bob (hybrid, pinned) with the proxy between them."""
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    with alice_end, proxy_a, proxy_b, bob_end:
        alice_res, bob_res, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, params, context(keys, "alice", "hybrid")))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), bob_rep, params, context(keys, "bob", "hybrid")))(bob_end),
            lambda: proxy(proxy_a, proxy_b, **proxy_kwargs),
        )
    return alice_res, bob_res, alice_rep, bob_rep


@pytest.mark.parametrize(
    "step, tamper",
    [
        ("2-bases", t_bases),
        ("2-matching", t_matching),
        ("3-sample_indices", t_sample_indices),
        ("3-sample_bits", t_sample_bits),
        ("3-qber", t_qber),
        ("4-salt", t_salt),
    ],
)
def test_classical_tamper_caught_by_signature(step, tamper, keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_res, _, alice_rep, bob_rep = _run(
        parallel, src, out_dir, keys, TAMPER_PARAMS, tamper_step=step, tamper=tamper, stop_after="4b-bob"
    )
    assert isinstance(alice_res, PeerAuthError)
    assert "signature" in alice_res.reason
    assert alice_rep.stages[-1] == "key_confirmation"
    assert "file_transfer" not in alice_rep.stages
    assert "file_transfer" not in bob_rep.stages
    assert not out_dir.exists()


def test_metadata_tamper_caught_by_aad(keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)  # one chunk
    out_dir = tmp_path / "received"
    # The metadata is ciphertext now; flip one bit of it
    tamper = lambda raw: _changed(raw[:-1] + bytes([raw[-1] ^ 1]), raw)  # noqa: E731
    _, bob_res, _, bob_rep = _run(
        parallel, src, out_dir, keys, META_PARAMS, tamper_step="5-meta", tamper=tamper, stop_after=None
    )
    assert isinstance(bob_res, InvalidTag)
    assert bob_rep.chunks_reported() == 0  # failed on the metadata, before any chunk was written
    assert not out_dir.exists()  # rejected before the output directory was even created


def test_untampered_proxy_run_succeeds(keys, parallel, make_file, same_file, tmp_path: Path) -> None:
    # No tamper, threshold still above 1.0: proves the proxy and the disabled QBER
    # check do not themselves break a clean transfer, so the failures above are the tampers.
    src = make_file("payload.bin", 100_000)
    out_dir = tmp_path / "received"
    alice_res, bob_res, _, _ = _run(parallel, src, out_dir, keys, TAMPER_PARAMS, stop_after=None)
    assert not isinstance(alice_res, Exception) and not isinstance(bob_res, Exception)
    assert same_file(src, Path(bob_res.output_path))
