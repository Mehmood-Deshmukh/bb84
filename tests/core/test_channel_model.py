"""
Lossy channel and detector model (core/channel_model.py): formulas against Ma et al.
(PRA 72, 012326, 2005) and sampled statistics against those formulas.
"""

from __future__ import annotations

import math
import subprocess
import sys

import numpy as np
import pytest

from qkd.core.channel_model import (
    PRESETS,
    ChannelParams,
    expected_secure_rate,
    misalignment_flips,
    preset,
    sample_clicks,
)


def within_sigmas(observed: float, n: int, p: float, k: float = 5.0) -> bool:
    """Is a binomial count observed/n within k standard deviations of p?"""
    sd = math.sqrt(n * p * (1 - p))
    return abs(observed - n * p) <= k * sd + 1


def test_ideal_channel_is_perfect() -> None:
    p = PRESETS["ideal"]
    assert (p.transmittance, p.eta, p.click_prob, p.error_rate, p.is_ideal) == (1.0, 1.0, 1.0, 0.0, True)


def test_gys_at_50_km_matches_ma_et_al() -> None:
    p = preset("GYS", 50)
    assert p.transmittance == pytest.approx(10 ** (-0.21 * 50 / 10))
    assert p.eta == pytest.approx(0.045 * 10 ** -1.05)
    # Ma et al.'s first-order forms, Y1 ~ Y0 + eta and e1 ~ (Y0/2 + e_d eta) / Y1, agree to
    # far better than a part in a thousand at these values
    y1_first_order = 1.7e-6 + p.eta
    e1_first_order = (0.5 * 1.7e-6 + 0.033 * p.eta) / y1_first_order
    assert p.click_prob == pytest.approx(y1_first_order, rel=1e-3)
    assert p.error_rate == pytest.approx(e1_first_order, rel=1e-3)
    assert 0.033 < p.error_rate < 0.034  # misalignment dominates, dark counts add a little


def test_error_rate_rises_towards_half_as_background_dominates() -> None:
    rates = [preset("KTH", L).error_rate for L in (0, 50, 100, 150, 200, 300)]
    assert rates == sorted(rates)
    assert rates[-1] > 0.4


def test_parameters_are_validated() -> None:
    for bad in ({"detector_efficiency": 1.5}, {"dark_count_prob": -0.1}, {"misalignment": 0.6},
                {"length_km": -1}):
        with pytest.raises(ValueError):
            ChannelParams(**bad)
    with pytest.raises(ValueError, match="Unknown channel preset"):
        preset("nope")


def test_ideal_channel_clicks_on_every_pulse() -> None:
    clicks = sample_clicks(1000, PRESETS["ideal"], np.random.default_rng(1))
    assert len(clicks) == 1000
    assert clicks.index.tolist() == list(range(1000)) and clicks.signal.all()


@pytest.mark.parametrize("name, length", [("KTH", 25), ("GYS", 10), ("KTH", 150)])
def test_sampled_clicks_match_the_model(name: str, length: float) -> None:
    p = preset(name, length)
    n = 2_000_000
    clicks = sample_clicks(n, p, np.random.default_rng(7))
    assert within_sigmas(len(clicks), n, p.click_prob)
    # Share of clicks that are real photons (the rest are background)
    assert within_sigmas(int(clicks.signal.sum()), len(clicks), p.eta / p.click_prob)
    idx = clicks.index
    assert (np.diff(idx) > 0).all() and idx[0] >= 0 and idx[-1] < n  # sorted, distinct, in range


def test_simulated_error_rate_matches_e1() -> None:
    # Errors among clicks: misalignment on photons, a fair coin on background clicks
    p = preset("KTH", 120)
    rng = np.random.default_rng(3)
    clicks = sample_clicks(5_000_000, p, rng)
    photon_errors = misalignment_flips(int(clicks.signal.sum()), p, rng).sum()
    dark_errors = (rng.random(int((~clicks.signal).sum())) < 0.5).sum()
    assert within_sigmas(int(photon_errors + dark_errors), len(clicks), p.error_rate)


def test_misalignment_flip_rate() -> None:
    flips = misalignment_flips(1_000_000, ChannelParams(misalignment=0.033), np.random.default_rng(2))
    assert within_sigmas(int(flips.sum()), 1_000_000, 0.033)


def test_expected_secure_rate_falls_with_distance_and_reaches_zero() -> None:
    rates = [expected_secure_rate(preset("GYS", L)) for L in (0, 25, 50, 100, 150, 400)]
    assert rates[0] > 0
    assert rates == sorted(rates, reverse=True)
    assert rates[-1] == 0.0


def test_channel_model_does_not_import_qiskit() -> None:
    code = "import sys, qkd.core.channel_model; print(any(m.startswith('qiskit') for m in sys.modules))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "False"


def test_pulse_message_round_trip_and_ideal_form() -> None:
    from qkd.core.channel_model import decode_pulses, encode_pulses

    full = encode_pulses(3, [0, 1, 2], ["a", "b", None])
    assert full["index"] is None  # every pulse clicked in order: no index needed
    assert decode_pulses(full) == (3, [0, 1, 2], ["a", "b", None])
    lossy = encode_pulses(100, [4, 17], ["q", None])
    assert decode_pulses(lossy) == (100, [4, 17], ["q", None])


@pytest.mark.parametrize(
    "msg",
    [
        ["a", "b"],  # the version-2 format
        {"n": -1, "index": None, "qubits": []},
        {"n": 2, "index": None, "qubits": ["a"]},  # no index but a pulse missing
        {"n": 2, "index": [1, 0], "qubits": ["a", "b"]},  # not increasing
        {"n": 2, "index": [0, 2], "qubits": ["a", "b"]},  # out of range
        {"n": 2, "index": [0], "qubits": ["a", "b"]},  # lengths differ
        {"n": 2, "index": None, "qubits": ["a", 3]},
        {"n": 1, "index": None, "qubits": ["a", "b"]},  # more qubits than pulses
    ],
    ids=["v2_list", "negative_n", "missing_pulse", "unsorted", "out_of_range", "length_mismatch",
         "bad_qubit", "too_many"],
)
def test_malformed_pulse_messages_are_rejected(msg) -> None:
    from qkd.core.channel_model import decode_pulses

    with pytest.raises(ValueError):
        decode_pulses(msg)
