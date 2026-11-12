"""
The composable decoy_finite_key gate (usecases/common.decoy_finite_key_verdict), which maps the
symmetric-basis protocol's measured per-intensity statistics onto the Lim et al. (2014) bound and
must agree with the Phase 5a required_N calculator. Honest expected counts at the required N clear
256 bits; a photon-number-splitting signature (signal/decoy gains pulled apart) drives the
single-photon yield to 0 and aborts.
"""

from __future__ import annotations

import pytest

from qkd.core import decoy, decoy_finitekey as dfk
from qkd.core.channel_model import preset
from qkd.core.config import ProtocolParams
from qkd.usecases.common import DecoyEstimate, decoy_finite_key_verdict, estimate_decoy

INTENS = (0.45, 0.12, 0.0)
PROBS = (0.3, 0.5, 0.2)
Q_X = 0.5


class _Rep:
    def __init__(self) -> None:
        self.m: dict = {}

    def metrics(self, **k):
        self.m.update(k)

    def success(self, *a):
        pass

    def warning(self, *a):
        pass

    def error(self, *a):
        pass


def _honest_estimate(link, n_pulses):
    """Expected honest per-intensity gains/QBERs/sent/clicks at these counts."""
    gains = [decoy.gain(link, mu) for mu in INTENS]
    qbers = [None, decoy.qber(link, INTENS[1]), decoy.qber(link, INTENS[2])]
    sent = [int(n_pulses * p) for p in PROBS]
    clicks = [int(s * g) for s, g in zip(sent, gains)]
    return DecoyEstimate(tuple(gains), tuple(qbers), tuple(sent), tuple(clicks),
                         0.0, 0.0, 0.0, INTENS[0], INTENS[1], gains[2])


def _params(link, n_pulses):
    return ProtocolParams(num_qubits=n_pulses, channel=link, source="decoy",
                          intensities=INTENS, probs=PROBS, decoy_gate="composable")


def test_gate_matches_calculator_at_expected_counts() -> None:
    link = preset("GYS", 25)
    req = dfk.required_N(link, [25], INTENS, PROBS, q_x=Q_X)[0]
    n = req.n_pulses
    est = _honest_estimate(link, n)
    signal_qber = decoy.qber(link, INTENS[0])
    rep = _Rep()
    secure, reason = decoy_finite_key_verdict(est, signal_qber, _params(link, n), rep)
    # The gate's ell equals the calculator's ell at the same expected counts (up to count rounding).
    calc = dfk.secure_key_length(dfk.expected_counts(link, n, INTENS, PROBS, Q_X), 1e-10, 1e-15, 1.16)
    assert abs(secure - calc.ell) <= max(5, 0.05 * calc.ell)
    assert reason is None and secure >= 256


def test_gate_aborts_below_required_n() -> None:
    link = preset("GYS", 25)
    req = dfk.required_N(link, [25], INTENS, PROBS, q_x=Q_X)[0]
    n = req.n_pulses // 4          # a quarter of the required block: well below threshold
    est = _honest_estimate(link, n)
    rep = _Rep()
    secure, reason = decoy_finite_key_verdict(est, decoy.qber(link, INTENS[0]), _params(link, n), rep)
    assert reason is not None and secure < 256


def test_pns_signature_drives_y1_to_zero() -> None:
    # A PNS attack forwards multi-photon pulses on a lossless line, so the signal gain is pulled up
    # relative to the decoy gain (quadratic ~ mu^2 instead of linear ~ mu). Feed such a gain
    # structure and the single-photon bound collapses: Y1_L -> 0 and the gate aborts.
    link = preset("GYS", 25)
    n = 100_000_000
    sent = [int(n * p) for p in PROBS]
    honest = [decoy.gain(link, mu) for mu in INTENS]
    # Inflate the signal gain so Q_signal/Q_decoy is far above the honest (near-linear) ratio.
    gains = [honest[0] * 3.0, honest[1], honest[2]]
    clicks = [int(s * g) for s, g in zip(sent, gains)]
    qbers = (None, decoy.qber(link, INTENS[1]), decoy.qber(link, INTENS[2]))
    est = DecoyEstimate(tuple(gains), qbers, tuple(sent), tuple(clicks),
                        0.0, 0.0, 0.0, INTENS[0], INTENS[1], gains[2])
    rep = _Rep()
    secure, reason = decoy_finite_key_verdict(est, decoy.qber(link, INTENS[0]), _params(link, n), rep)
    assert secure == 0 and reason is not None
    assert rep.m["decoy_comp_Y1_lower"] == pytest.approx(0.0, abs=1e-6)


def test_both_peers_reach_the_same_verdict() -> None:
    # Alice and Bob build the estimate from the same agreed public values, so the gate is identical.
    link = preset("KTH", 0)
    req = dfk.required_N(link, [0], INTENS, PROBS, q_x=Q_X)[0]
    est = _honest_estimate(link, req.n_pulses)
    sq = decoy.qber(link, INTENS[0])
    a = decoy_finite_key_verdict(est, sq, _params(link, req.n_pulses), _Rep())
    b = decoy_finite_key_verdict(est, sq, _params(link, req.n_pulses), _Rep())
    assert a == b
