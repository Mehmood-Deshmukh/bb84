"""
Decoy weak-coherent source sampling (core/source.py): the per-intensity gains and the
photon-number statistics match the core/decoy.py expectations within statistical tolerance.
Fixed seeds, large N, NumPy only (no qiskit).
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from qkd.core import decoy
from qkd.core.channel_model import preset
from qkd.core.source import DECOY, SIGNAL, VACUUM, sample_clicks_decoy

INTENSITIES = (0.48, 0.1, 0.0)
PROBS = (0.7, 0.2, 0.1)


def within_sigmas(observed: int, n: int, p: float, k: float = 6.0) -> bool:
    """Is a binomial count `observed` out of `n` within k standard deviations of mean n p?"""
    sd = math.sqrt(max(n * p * (1 - p), 1e-9))
    return abs(observed - n * p) <= k * sd + 2


@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", [0.0, 25.0, 50.0])
def test_per_intensity_gain_matches_decoy_model(name: str, length: float) -> None:
    p = preset(name, length)
    n = 4_000_000
    rng = np.random.default_rng(20260211)
    clicks = sample_clicks_decoy(n, INTENSITIES, PROBS, p, rng)

    counts = np.bincount(clicks.label, minlength=3)
    assert clicks.sent.sum() == n
    for k, mu in enumerate(INTENSITIES):
        expected_gain = decoy.gain(p, mu)
        # clicks_k out of sent_k is Binomial(sent_k, gain_k)
        assert within_sigmas(int(counts[k]), int(clicks.sent[k]), expected_gain)
        if clicks.sent[k]:
            measured = counts[k] / clicks.sent[k]
            assert measured == pytest.approx(expected_gain, abs=5e-4 + 0.05 * expected_gain)


@pytest.mark.parametrize("name", ["GYS", "KTH"])
def test_sent_fractions_match_probs(name: str) -> None:
    p = preset(name, 25)
    n = 2_000_000
    rng = np.random.default_rng(7)
    clicks = sample_clicks_decoy(n, INTENSITIES, PROBS, p, rng)
    for k, prob in enumerate(PROBS):
        assert within_sigmas(int(clicks.sent[k]), n, prob)


def test_vacuum_clicks_are_dark_only() -> None:
    # Vacuum pulses emit no photons, so every vacuum click is a dark count: photon number 0
    # and the signal flag False. Needs a channel with a non-zero dark rate (KTH).
    p = preset("KTH", 25)
    rng = np.random.default_rng(99)
    clicks = sample_clicks_decoy(2_000_000, INTENSITIES, PROBS, p, rng)
    vac = clicks.label == VACUUM
    assert vac.sum() > 0  # KTH's Y0 = 4e-4 gives some vacuum clicks at this N
    assert np.all(clicks.photons[vac] == 0)
    assert not np.any(clicks.signal[vac])
    # Vacuum gain is just Y0.
    assert clicks.photons[vac].size / clicks.sent[VACUUM] == pytest.approx(p.dark_count_prob, abs=1e-4)


def test_signal_clicks_have_at_least_one_photon() -> None:
    # A photon-signalled click means at least one photon reached Bob, so n >= 1.
    p = preset("GYS", 25)
    rng = np.random.default_rng(3)
    clicks = sample_clicks_decoy(1_000_000, INTENSITIES, PROBS, p, rng)
    assert np.all(clicks.photons[clicks.signal] >= 1)


@pytest.mark.parametrize("mu_index", [SIGNAL, DECOY])
def test_photon_number_is_zero_truncated_poisson_on_ideal_channel(mu_index: int) -> None:
    # On an ideal channel (eta = 1, Y0 = 0) a pulse clicks iff it emitted >= 1 photon, so the
    # clicked photon counts follow a zero-truncated Poisson(mu) with mean mu / (1 - e^-mu).
    p = preset("ideal")
    mu = INTENSITIES[mu_index]
    rng = np.random.default_rng(1234)
    clicks = sample_clicks_decoy(5_000_000, INTENSITIES, PROBS, p, rng)
    photons = clicks.photons[clicks.label == mu_index]
    assert np.all(photons >= 1)  # ideal channel: no dark clicks, every click carries a photon
    expected_mean = mu / (1 - math.exp(-mu))
    assert photons.mean() == pytest.approx(expected_mean, rel=0.02)


def test_empty_block() -> None:
    clicks = sample_clicks_decoy(0, INTENSITIES, PROBS, preset("GYS", 25), np.random.default_rng(0))
    assert len(clicks) == 0
    assert clicks.sent.tolist() == [0, 0, 0]


def test_vacuum_never_clicks_on_ideal_channel() -> None:
    # eta = 1, Y0 = 0: vacuum pulses emit nothing and there are no dark counts, so Q_vacuum = 0.
    clicks = sample_clicks_decoy(500_000, INTENSITIES, PROBS, preset("ideal"), np.random.default_rng(5))
    assert np.sum(clicks.label == VACUUM) == 0
