"""
Protocol-level properties, exercised with the real Alice/Bob workflows over a socket pair.

- Without Eve, both sides derive the same key and the file arrives intact.
- When QBER >= threshold, both sides abort and Bob writes nothing.
- A channel that flips every qubit is always detected.
- Chunked encryption round trips for arbitrary sizes.

These use the Qiskit Aer simulator, with a small qubit count to keep them fast.
"""

from __future__ import annotations

import os
import random
import socket
from dataclasses import replace
from pathlib import Path

import pytest
from qiskit import QuantumCircuit
from qiskit.qasm2 import dumps

from qkd.core.config import ProtocolParams
from qkd.core.crypto_utils import decrypt_chunk, derive_chunk_nonce, encrypt_chunk
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.services.wire import forward_message, recv_json, send_json
from qkd.usecases import receive_file as bob
from qkd.usecases import send_file as alice
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file

PARAMS = ProtocolParams(num_qubits=48)


def test_same_key_on_both_sides_without_eve(connected) -> None:
    a, b = connected(
        lambda s: alice.run_key_exchange(TranscriptChannel(s, "alice"), PARAMS, NullReporter()),
        lambda s: bob.run_key_exchange(TranscriptChannel(s, "bob"), PARAMS, NullReporter()),
    )
    assert not a.aborted and not b.aborted
    assert a.qber == b.qber == 0.0
    assert a.key == b.key
    assert len(a.key) == 32
    assert a.sifted_length == b.sifted_length
    assert a.sample_size == b.sample_size >= 1


def test_file_arrives_intact_without_eve(connected, make_file, same_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 200_000)
    out_dir = tmp_path / "received"
    sent, got = connected(
        lambda s: send_file(s, str(src), NullReporter(), PARAMS),
        lambda s: receive_file(s, str(out_dir), NullReporter(), PARAMS),
    )
    assert not sent.aborted
    assert got.bytes_written == 200_000
    assert same_file(src, Path(got.output_path))


def test_abort_when_qber_equals_threshold(connected, make_file, tmp_path: Path) -> None:
    # A clean channel has QBER 0, so a threshold of 0 sits exactly on the boundary.
    params = replace(PARAMS, qber_threshold=0.0)
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    sent, got = connected(
        lambda s: send_file(s, str(src), NullReporter(), params),
        lambda s: receive_file(s, str(out_dir), NullReporter(), params),
    )
    assert sent.aborted and got.key_exchange.aborted
    assert sent.key is None and got.output_path is None
    assert not out_dir.exists()


def _flip_every_qubit(qasm: str) -> str:
    """Apply Y (bit and phase flip), so a measurement in either basis returns the wrong bit."""
    qc = QuantumCircuit.from_qasm_str(qasm)
    qc.y(0)
    return dumps(qc)


def _flipping_proxy(from_alice: socket.socket, to_bob: socket.socket) -> None:
    """Relay the hellos, flip every qubit, then relay the classical messages up to the QBER verdict."""
    forward_message(from_alice, to_bob)    # Alice's hello
    forward_message(to_bob, from_alice)    # Bob's hello
    send_json(to_bob, [_flip_every_qubit(q) for q in recv_json(from_alice)])
    forward_message(to_bob, from_alice)    # Bob's bases
    forward_message(from_alice, to_bob)    # matching indices
    forward_message(from_alice, to_bob)    # sample indices
    forward_message(to_bob, from_alice)    # sample bits
    forward_message(from_alice, to_bob)    # QBER verdict


def test_tampered_channel_is_always_detected(parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    with alice_end, proxy_a, proxy_b, bob_end:
        sent, got, _ = parallel(
            lambda: send_file(alice_end, str(src), NullReporter(), PARAMS),
            lambda: receive_file(bob_end, str(out_dir), NullReporter(), PARAMS),
            lambda: _flipping_proxy(proxy_a, proxy_b),
        )
    assert sent.qber == 1.0
    assert sent.aborted and got.key_exchange.aborted
    assert not out_dir.exists()


@pytest.mark.parametrize("seed", range(10))
def test_chunk_roundtrip_random_sizes(seed: int, aes_key: bytes) -> None:
    rng = random.Random(seed)
    chunk_size = rng.choice([1, 7, 1024, 65536])
    data = os.urandom(rng.randint(0, 300_000))
    base = os.urandom(8)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    sealed = [encrypt_chunk(c, aes_key, derive_chunk_nonce(base, i)) for i, c in enumerate(chunks)]
    assert b"".join(decrypt_chunk(ct, aes_key, derive_chunk_nonce(base, i), tag) for i, (ct, tag) in enumerate(sealed)) == data
