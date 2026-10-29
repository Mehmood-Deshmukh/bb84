"""
Man-in-the-middle demo (Gate 3), exercised with the real Alice/Bob/Mallory workflows.

Topology: Alice <-> Mallory <-> Bob over two socket pairs. Alice runs send_file,
Bob runs receive_file, and Mallory runs run_mitm between them.

- auth off: Mallory relays the file and recovers the plaintext, undetected (the gap).
- auth on, own key: Alice rejects Mallory at the hello; no qubits leave Alice.
- auth on, relay hello: Mallory's relayed transcript matches Alice's, but she cannot
  sign as Bob, so Alice rejects her at key confirmation.
- control: given Bob's real key, the relay passes key confirmation, proving the only
  thing missing in the real relay test is Bob's signing key.

Runs that reach the quantum phase use the Qiskit Aer simulator with 64 qubits.
"""

from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.services.reporting import NullReporter
from qkd.usecases.common import PeerAuthError
from qkd.usecases.mitm_demo import MitmResult, run_mitm
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys

PARAMS = ProtocolParams(num_qubits=64)


def _run_triangle(
    parallel: Callable[..., list],
    src: Path,
    bob_out: Path,
    keys: dict[str, tuple[bytes, bytes]],
    mode: str,
    strategy: str,
    mallory_identity: Optional[tuple[bytes, bytes]],
) -> tuple[Any, Any, MitmResult, RecordingReporter, RecordingReporter]:
    """Run Alice (send), Bob (receive), and Mallory (run_mitm) concurrently."""
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, mallory_a = socket.socketpair()
    mallory_b, bob_end = socket.socketpair()
    with alice_end, mallory_a, mallory_b, bob_end:
        alice_res, bob_res, mitm = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, PARAMS, context(keys, "alice", mode)))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(bob_out), bob_rep, PARAMS, context(keys, "bob", mode)))(bob_end),
            lambda: run_mitm(mallory_a, mallory_b, NullReporter(), PARAMS, mode, strategy, mallory_identity),
        )
    return alice_res, bob_res, mitm, alice_rep, bob_rep


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_mitm_auth_off(parallel, make_file, same_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 100_000)
    bob_out = tmp_path / "received"
    alice_res, bob_res, mitm, _, _ = _run_triangle(parallel, src, bob_out, {}, "none", "own_key", None)

    assert not isinstance(alice_res, Exception) and not isinstance(bob_res, Exception)
    assert alice_res.qber == 0.0 and bob_res.key_exchange.qber == 0.0
    assert mitm.relayed is True
    assert mitm.plaintext_sha256 == _sha256(src)
    assert mitm.plaintext_bytes == 100_000
    # Bob's copy is byte-identical; its name is re-prefixed because the file passes
    # through a receive then a send, so compare at the path Bob actually wrote.
    assert same_file(src, Path(bob_res.output_path))


@pytest.mark.parametrize("mode", ["sign", "hybrid"])
def test_mitm_auth_on_own_key(mode: str, keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    bob_out = tmp_path / "received"
    mallory = pqc.sig_keygen()
    alice_res, _, mitm, alice_rep, _ = _run_triangle(parallel, src, bob_out, keys, mode, "own_key", mallory)

    assert isinstance(alice_res, PeerAuthError)
    assert alice_rep.stages[-1] == "authentication"
    assert "quantum_transmission" not in alice_rep.stages
    assert alice_rep.merged()["peer_fingerprint"] == pqc.fingerprint(mallory[0])
    assert mitm.plaintext_sha256 is None
    assert not bob_out.exists()


@pytest.mark.parametrize("mode", ["sign", "hybrid"])
def test_mitm_auth_on_relay_hello(mode: str, keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    bob_out = tmp_path / "received"
    alice_res, _, mitm, alice_rep, _ = _run_triangle(parallel, src, bob_out, keys, mode, "relay_hello", None)

    assert isinstance(alice_res, PeerAuthError)
    assert "signature" in alice_res.reason
    assert alice_rep.stages[-1] == "key_confirmation"
    assert "file_transfer" not in alice_rep.stages
    assert alice_rep.merged()["peer_fingerprint"] == pqc.fingerprint(keys["bob"][0])
    assert mitm.plaintext_sha256 is None
    assert not bob_out.exists()


def test_relay_control_with_bobs_key_passes_key_confirmation(keys, parallel, make_file, tmp_path: Path) -> None:
    # Mallory is handed Bob's real identity, so her relayed transcript plus a valid
    # Bob signature carry Alice past key confirmation and into file transfer. This
    # isolates the one thing the real relay test lacks: Bob's signing key.
    src = make_file("payload.bin", 1000)
    bob_out = tmp_path / "received"
    alice_res, _, mitm, alice_rep, _ = _run_triangle(parallel, src, bob_out, keys, "hybrid", "relay_hello", keys["bob"])

    assert not isinstance(alice_res, PeerAuthError)
    assert "key_confirmation" in alice_rep.stages
    assert "file_transfer" in alice_rep.stages
    assert "signature" not in (mitm.alice_error or "")
