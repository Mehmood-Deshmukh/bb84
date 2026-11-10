"""
Photon-number-splitting (PNS) attack, end to end on the Aer simulator: Alice (eve-mode, a
weak-coherent source) hands her pre-loss pulses to the PNS Eve proxy, which splits photons off
the multi-photon pulses and forwards the rest to Bob. This is the textbook demonstration that
decoy states defend against PNS (Brassard et al. 2000; Lutkenhaus; Ma et al. 2005):

  * Against SOURCE=wcp (the single-photon Tomamichel gate, which ignores the gains) the run
    COMPLETES, Bob's QBER stays at the honest level, and Eve learns the bit of every multi-photon
    pulse Bob detected -- a large share of the key.
  * Against SOURCE=decoy the decoy estimate sees the signal/decoy gains pulled apart by the
    multi-photon content, drives the single-photon-yield bound Y1_L to 0, and the decoy gate
    ABORTS before any file data.

A control with the attack off (Eve just applies the honest loss) reproduces the honest gains, so
the proxy path itself adds no artefact.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from qkd.core import decoy
from qkd.core.channel_model import preset
from qkd.core.config import ProtocolParams
from qkd.usecases.pns_demo import run_pns
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys

GYS_25 = preset("GYS", 25)
GYS_0 = preset("GYS", 0)


def _run_attack(parallel, src, out_dir, keys, params, *, attack=True, forward_fraction=None,
                multi_fraction=None, strength=1.0, mode="hybrid"):
    """Alice (eve-mode) <-> PNS Eve proxy <-> Bob, over two socket pairs. Returns the three results."""
    alice_rep, bob_rep, eve_rep = RecordingReporter(), RecordingReporter(), RecordingReporter()
    alice_end, eve_a = socket.socketpair()
    eve_b, bob_end = socket.socketpair()
    with alice_end, eve_a, eve_b, bob_end:
        alice_res, bob_res, eve_res = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, params,
                                                context(keys, "alice", mode), eve_mode=True))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), bob_rep, params,
                                                   context(keys, "bob", mode)))(bob_end),
            lambda: guarded(lambda s: run_pns(s, eve_b, eve_rep, params, attack=attack, seed=7,
                                              forward_fraction=forward_fraction,
                                              multi_fraction=multi_fraction, strength=strength))(eve_a),
        )
    return (alice_res, alice_rep), (bob_res, bob_rep), (eve_res, eve_rep)


def test_wcp_pns_completes_and_leaks_key(keys, parallel, make_file, same_file, tmp_path: Path) -> None:
    # wcp: the single-photon gate ignores the gains, so the attack goes through. Forward every
    # multi-photon pulse (multi_fraction=1) so there are plenty of clicks and Eve knows them all.
    params = ProtocolParams(num_qubits=2 ** 18, channel=GYS_0, source="wcp", reconciliation="cascade")
    src = make_file("payload.bin", 20_000)
    out_dir = tmp_path / "received"
    (a_res, a_rep), (b_res, b_rep), (e_res, _) = _run_attack(
        parallel, src, out_dir, keys, params, multi_fraction=1.0)

    assert not isinstance(a_res, Exception), a_res
    assert not isinstance(b_res, Exception), b_res
    # The run completed and the file arrived: the single-photon gate did not catch the attack.
    assert a_res.key is not None
    assert same_file(src, Path(b_res.output_path))
    a = a_rep.merged()
    assert a["secure_key_bits"] >= 256                      # Tomamichel gate "passed"
    assert a["qber"] == pytest.approx(0.033, abs=0.02)      # Bob's QBER stayed at the honest level
    # Eve learned (nearly) the whole sifted key: with no single-photon forwarding, every click Bob
    # saw came from a multi-photon pulse Eve stored.
    assert e_res.known_fraction > 0.9


def test_decoy_pns_aborts_at_decoy_gate(keys, parallel, make_file, tmp_path: Path) -> None:
    params = ProtocolParams(num_qubits=2 ** 17, channel=GYS_25, source="decoy", reconciliation="cascade")
    src = make_file("payload.bin", 5_000)
    out_dir = tmp_path / "received"
    (a_res, a_rep), (b_res, b_rep), (e_res, _) = _run_attack(
        parallel, src, out_dir, keys, params, multi_fraction=1.0)

    assert not isinstance(a_res, Exception), a_res
    assert not isinstance(b_res, Exception), b_res
    # The decoy gate stopped the run before any file data.
    assert a_res.aborted and b_res.key_exchange.aborted
    assert not out_dir.exists()
    a, b = a_rep.merged(), b_rep.merged()
    # The single-photon yield bound collapses: Y1_L is at (or essentially at) zero, far below the
    # honest single-photon yield.
    true_y1 = decoy.single_photon_yield(GYS_25)
    assert a["decoy_Y1_lower"] <= 0.1 * true_y1
    # Ground truth from Bob (requirement 1): both sides compute the gains from Bob's detected set,
    # and the signal gain reflects the multi-photon rate, not the honest single-photon gain.
    assert a["decoy_gains"] == b["decoy_gains"]
    honest_signal = decoy.gain(GYS_25, 0.48)
    assert a["decoy_gains"][0] > 3 * honest_signal          # gains pulled far from honest
    assert e_res.source == "decoy"


def test_partial_pns_degrades_smoothly(keys, parallel, make_file, tmp_path: Path) -> None:
    # The partial attack (strength g): Eve PNS-attacks a fraction g of the pulses and passes the
    # rest through honestly. As g rises Eve learns more of the sifted key and the signal gain is
    # pulled further from honest (so Y1_L falls), while she introduces no error -- QBER stays flat.
    # enforce_finite_key is off so every g completes and we can read the measured quantities.
    params = ProtocolParams(num_qubits=2 ** 21, channel=GYS_25, source="decoy", reconciliation="cascade",
                            enforce_finite_key=False, measurement="analytic")
    src = make_file("payload.bin", 2_000)
    known, qbers, y1 = {}, {}, {}
    for g in (0.0, 0.5, 1.0):
        (a_res, a_rep), (b_res, _), (e_res, _) = _run_attack(
            parallel, src, tmp_path / f"r{g}", keys, params, strength=g, multi_fraction=1.0)
        assert not isinstance(a_res, Exception), a_res
        assert not isinstance(b_res, Exception), b_res
        known[g] = e_res.known_fraction
        qbers[g] = a_rep.merged()["qber"]
        y1[g] = a_rep.merged()["decoy_Y1_lower"]

    # g=0 is the honest control (Eve stores nothing); g=1 is the maximal attack (she knows ~all).
    assert known[0.0] == 0.0
    assert known[1.0] > 0.9
    # Known fraction rises monotonically and Y1_L falls monotonically with g.
    assert known[0.0] < known[0.5] < known[1.0]
    assert y1[0.0] > y1[0.5] > y1[1.0]
    # QBER stays at the honest floor for every g (Eve forwards states unchanged).
    assert all(q == pytest.approx(0.033, abs=0.02) for q in qbers.values())


def test_honest_control_through_proxy_reproduces_gains(keys, parallel, make_file, same_file, tmp_path: Path) -> None:
    # Attack off: Eve applies the honest loss and forwards survivors, with no splitting. The
    # measured gains match the channel model, so the proxy path adds no artefact of its own.
    # enforce_finite_key is off so a small, fast N still completes.
    params = ProtocolParams(num_qubits=2 ** 17, channel=GYS_25, source="decoy",
                            reconciliation="cascade", enforce_finite_key=False)
    src = make_file("payload.bin", 5_000)
    out_dir = tmp_path / "received"
    (a_res, a_rep), (b_res, b_rep), (e_res, _) = _run_attack(
        parallel, src, out_dir, keys, params, attack=False)

    assert not isinstance(a_res, Exception), a_res
    assert not isinstance(b_res, Exception), b_res
    assert a_res.key is not None
    assert same_file(src, Path(b_res.output_path))
    a = a_rep.merged()
    assert a["decoy_gains"][0] == pytest.approx(decoy.gain(GYS_25, 0.48), rel=0.15)
    assert a["decoy_gains"][1] == pytest.approx(decoy.gain(GYS_25, 0.1), rel=0.3)
    assert e_res.known_fraction == 0.0  # the control stores nothing
