"""
The finite-key gate and key confirmation, end to end on the Aer simulator.

  - Too few qubits: both peers compute the same finite-key bound from public
    values, find it below the key length, and abort before the salt.
  - Default qubits on a clean channel: the bound passes and both keys match.
  - Keys that differ despite a passing QBER check (simulated here by flipping
    every qubit with the QBER and finite-key checks turned off) are caught by
    the key confirmation tag in step 4b, before any file data moves.
"""

from __future__ import annotations

import socket
from pathlib import Path

from qkd.core.config import ProtocolParams
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases import receive_file as bob
from qkd.usecases import send_file as alice
from qkd.usecases.common import KeyConfirmationError
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys, proxy  # noqa: F401


def _key_exchange(connected, params: ProtocolParams):
    return connected(
        lambda s: alice.run_key_exchange(TranscriptChannel(s, "alice"), params, NullReporter()),
        lambda s: bob.run_key_exchange(TranscriptChannel(s, "bob"), params, NullReporter()),
    )


def test_too_few_qubits_abort_on_both_sides(connected) -> None:
    a, b = _key_exchange(connected, ProtocolParams(num_qubits=128))
    assert a.aborted and b.aborted
    assert a.qber == b.qber == 0.0  # the channel is clean; the sample is just too small
    assert a.secure_bits == b.secure_bits == 0
    assert "finite-key bound" in a.abort_reason and "finite-key bound" in b.abort_reason


def test_default_qubits_pass_the_bound_with_matching_keys(connected) -> None:
    params = ProtocolParams()
    a, b = _key_exchange(connected, params)
    assert not a.aborted and not b.aborted
    assert a.secure_bits == b.secure_bits >= params.final_key_bits
    assert a.key == b.key and len(a.key) == params.final_key_bits // 8


def _flip_every_qubit(qasm_strings: list[str]) -> list[str]:
    # An X before the basis change flips the encoded bit in either basis
    # Match the declaration alone: a bit-0 '+' qubit has no gates and no trailing newline
    return [q.replace("qreg q[1];", "qreg q[1];\nx q[0];", 1) for q in qasm_strings]


def test_key_mismatch_is_caught_by_key_confirmation(keys, parallel, make_file, tmp_path: Path) -> None:
    params = ProtocolParams(num_qubits=64, qber_threshold=1.01, enforce_finite_key=False)
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    with alice_end, proxy_a, proxy_b, bob_end:
        alice_res, bob_res, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, params, context(keys, "alice", "hybrid")))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), bob_rep, params, context(keys, "bob", "hybrid")))(bob_end),
            lambda: proxy(proxy_a, proxy_b, tamper_step="1", tamper=_flip_every_qubit),
        )
    # Bob's signature verifies (same transcript), but his key tag does not
    assert isinstance(alice_res, KeyConfirmationError)
    assert alice_rep.stages[-1] == "key_confirmation"
    assert "file_transfer" not in alice_rep.stages
    assert "file_transfer" not in bob_rep.stages
    assert not out_dir.exists()
