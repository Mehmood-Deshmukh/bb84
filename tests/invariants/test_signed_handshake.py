"""
Signed handshake properties, exercised with the real Alice/Bob (and Eve) workflows.

- An honest sign or hybrid transfer arrives intact, with both peers pinned.
- A key that fails the trust check stops Alice before any qubit is sent.
- Mismatched modes (downgrade attempts) abort on both sides before any decryption.
- Eve forwarding the hellos unchanged still ends in a QBER abort in hybrid mode.

Runs that reach the quantum phase use the Qiskit Aer simulator with 64 qubits.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.services.reporting import NullReporter
from qkd.usecases.common import PeerAuthError
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import (
    AUTH_METRICS,
    BB84_METRICS,
    SIGNED_STAGES,
    RecordingReporter,
    context,
    guarded,
    keys,
)

PARAMS = ProtocolParams()  # default N with the finite-key gate on
# Sample every sifted bit and abort on any error, so Eve's ~25% disturbance is caught
# with overwhelming probability at 64 qubits (an honest channel has QBER exactly 0).
EVE_PARAMS = ProtocolParams(num_qubits=64, qber_sample_fraction=1.0, qber_threshold=0.01)


@pytest.mark.parametrize("mode", ["sign", "hybrid"])
def test_honest_transfer(mode: str, keys, connected, make_file, same_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 200_000)
    out_dir = tmp_path / "received"
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    sent, got = connected(
        lambda s: send_file(s, str(src), alice_rep, PARAMS, context(keys, "alice", mode)),
        lambda s: receive_file(s, str(out_dir), bob_rep, PARAMS, context(keys, "bob", mode)),
    )
    assert not sent.aborted
    assert same_file(src, Path(got.output_path))
    for rep, peer in ((alice_rep, "bob"), (bob_rep, "alice")):
        assert rep.stages == SIGNED_STAGES
        assert {k for e in rep.metric_events for k in e} - BB84_METRICS == AUTH_METRICS
        assert rep.auth_metric_counts() == dict.fromkeys(AUTH_METRICS, 1)
        m = rep.merged()
        assert m["auth_mode"] == mode
        assert m["peer_fingerprint"] == pqc.fingerprint(keys[peer][0])
        assert m["peer_trust"] == "pinned"
        assert m["handshake_ms"] > 0
        assert m["auth_overhead_bytes"] > 0


def test_wrong_pin_rejected_before_qubits(keys, connected, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    stranger_pk, _ = pqc.sig_keygen()
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    err, bob_err = connected(
        guarded(lambda s: send_file(s, str(src), alice_rep, PARAMS, context(keys, "alice", "hybrid", pin=stranger_pk))),
        guarded(lambda s: receive_file(s, str(out_dir), bob_rep, PARAMS, context(keys, "bob", "hybrid"))),
    )
    assert isinstance(err, PeerAuthError)
    assert alice_rep.merged()["peer_fingerprint"] == pqc.fingerprint(keys["bob"][0])
    assert "peer_trust" not in alice_rep.merged()
    # Bob was waiting for qubits when Alice's side closed
    assert isinstance(bob_err, ConnectionError)
    assert "raw_qubits" not in bob_rep.merged()
    assert not out_dir.exists()


@pytest.mark.parametrize(
    "alice_mode, bob_mode",
    [("hybrid", "none"), ("none", "hybrid")],
    ids=["alice_hybrid_bob_none", "alice_none_bob_hybrid"],
)
def test_downgrade_rejected(alice_mode: str, bob_mode: str, keys, connected, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    bob_rep = RecordingReporter()
    alice_err, bob_err = connected(
        guarded(lambda s: send_file(s, str(src), NullReporter(), PARAMS, context(keys, "alice", alice_mode))),
        guarded(lambda s: receive_file(s, str(out_dir), bob_rep, PARAMS, context(keys, "bob", bob_mode))),
    )
    for err in (alice_err, bob_err):
        assert isinstance(err, PeerAuthError)
        assert "mode mismatch" in err.reason
    assert bob_rep.stages == ["authentication"]
    assert not out_dir.exists()


def test_eve_with_hybrid_aborts_on_qber(keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, eve_a = socket.socketpair()
    eve_b, bob_end = socket.socketpair()
    with alice_end, eve_a, eve_b, bob_end:
        sent, got, eve = parallel(
            lambda: send_file(alice_end, str(src), alice_rep, EVE_PARAMS, context(keys, "alice", "hybrid")),
            lambda: receive_file(bob_end, str(out_dir), bob_rep, EVE_PARAMS, context(keys, "bob", "hybrid")),
            lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=EVE_PARAMS.qber_threshold),
        )
    assert sent.aborted and got.key_exchange.aborted and eve.aborted
    assert sent.qber > 0
    for rep in (alice_rep, bob_rep):
        # Authentication went through Eve untouched; the QBER check is what stopped the run
        assert rep.merged()["peer_trust"] == "pinned"
        assert "key_confirmation" not in rep.stages
    assert not out_dir.exists()
