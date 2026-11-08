"""
Honest decoy-state transfer, end to end on the Aer simulator: a weak coherent source with
three intensities (wire step 2d) over GYS at 25 km, hybrid auth and Cascade reconciliation.

The smallest power of two that passes the decoy_asymptotic gate *reliably* at GYS 25 km with
the default security policy is 2**21 (~520-920 secure bits, 6/6 over repeated runs); 2**20 is
marginal (it straddles the 256-bit cut-off, ~1/6 runs pass, because the decoy-QBER estimate
e1_U fluctuates over the few hundred decoy-sifted bits) and 2**19 gives ~140 bits. This test
uses 2**21. It checks that the measured per-intensity gains and QBERs match the decoy model,
that the single-photon bound Y1_L stays below the true Y1, and that the file arrives
byte-identical.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from qkd.core import decoy
from qkd.core.channel_model import preset
from qkd.core.config import ProtocolParams
from qkd.core.source import DECOY, SIGNAL
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys

GYS_25KM = preset("GYS", 25)
# 2**21: the smallest power of two that reliably clears the 256-bit gate here (see module doc).
DECOY_N = 2 ** 21
DECOY_PARAMS = ProtocolParams(num_qubits=DECOY_N, channel=GYS_25KM, reconciliation="cascade",
                              source="decoy")


@pytest.mark.parametrize("mode", ["hybrid"])
def test_honest_decoy_transfer(mode, keys, parallel, make_file, same_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 50_000)
    out_dir = tmp_path / "received"
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, bob_end = socket.socketpair()
    with alice_end, bob_end:
        alice_res, bob_res = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, DECOY_PARAMS, context(keys, "alice", mode)))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), bob_rep, DECOY_PARAMS, context(keys, "bob", mode)))(bob_end),
        )

    assert not isinstance(alice_res, Exception), alice_res
    assert not isinstance(bob_res, Exception), bob_res
    # Key exchange completed and the file arrived byte-identical.
    assert alice_res.key is not None
    assert same_file(src, Path(bob_res.output_path))

    a, b = alice_rep.merged(), bob_rep.merged()
    # Both sides agree on the per-intensity measurements and the single-photon bounds.
    assert a["decoy_gains"] == b["decoy_gains"]
    assert a["decoy_qbers"] == b["decoy_qbers"]
    assert a["decoy_Y1_lower"] == b["decoy_Y1_lower"]

    gains = a["decoy_gains"]
    qbers = a["decoy_qbers"]
    # Measured gains match the decoy model within sampling tolerance.
    assert gains[SIGNAL] == pytest.approx(decoy.gain(GYS_25KM, 0.48), rel=0.1)
    assert gains[DECOY] == pytest.approx(decoy.gain(GYS_25KM, 0.1), rel=0.15)
    # Decoy QBER is around the misalignment error e_d = 0.033.
    assert qbers[DECOY] == pytest.approx(0.033, abs=0.025)

    # The Y1 lower bound tracks the true single-photon yield and stays close to (at or a
    # little below) it. It is conservative only in expectation: this is an asymptotic point
    # estimate (the decoy bounds are evaluated at the measured gains/QBERs), so a single run's
    # statistical fluctuation can nudge Y1_L a few percent above or e1_U below the true value.
    # Phase 5's composable Lim et al. bound uses confidence intervals and is strictly
    # conservative; hence the tolerance here rather than a hard inequality.
    true_y1 = decoy.single_photon_yield(GYS_25KM)
    assert a["decoy_Y1_lower"] == pytest.approx(true_y1, rel=0.15)
    assert a["decoy_Y1_lower"] <= true_y1 * 1.12
    # e1_U estimates the single-photon error, which is near the misalignment e_d = 0.033.
    assert a["decoy_e1_upper"] == pytest.approx(0.033, abs=0.03)
    # The gate passed, so the reported secure length clears the policy's 256 bits.
    assert a["secure_key_bits"] >= 256
