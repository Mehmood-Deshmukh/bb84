"""
Composable finite-key decoy bounds (core/decoy_finitekey.py), checked against Lim et al.
(PRA 89, 022307, 2014) and cross-checked against the asymptotic numerics in core/decoy.py:

  * the finite key is never longer than the asymptotic key at the same counts, and converges
    to it as N -> infinity;
  * in that asymptotic limit the vacuum and single-photon event bounds reproduce decoy.py's
    Y0 and Y1 (the bound is exact for vacuum, ~3% loose for single photons);
  * required_N grows with distance for a fixed configuration;
  * a Lim-like fiber system reaches a positive composable key over ~100 km (their Fig 1 regime).

decoy_finitekey.py must not import qiskit (the layering test in tests/test_setup.py covers it).
"""

from __future__ import annotations

import math

import pytest

from qkd.core import decoy, decoy_finitekey as dfk
from qkd.core.channel_model import ChannelParams, preset

EPS_SEC, EPS_COR = 1e-10, 1e-15  # the single-photon path's values (config defaults)
INTENS = (0.5, 0.1, 0.0)         # signal, decoy, vacuum
PROBS = (0.6, 0.3, 0.1)
Q_X = 0.7


# ── building blocks ──────────────────────────────────────────────────────────

def test_tau_is_a_distribution() -> None:
    # tau_n is the probability Alice sends an n-photon state; summed over n it is 1.
    total = sum(dfk.tau(n, INTENS, PROBS) for n in range(0, 60))
    assert total == pytest.approx(1.0, abs=1e-12)
    # tau_0 = sum_k p_k e^{-mu_k}; with a true vacuum (mu3=0) its p3 term is exactly p3.
    assert dfk.tau(0, INTENS, PROBS) == pytest.approx(
        sum(p * math.exp(-mu) for mu, p in zip(INTENS, PROBS)))


def test_counts_validation() -> None:
    good = dict(intensities=(0.5, 0.1, 0.0), probs=(0.6, 0.3, 0.1),
                n_X=(1.0, 1.0, 1.0), m_X=(0.0, 0.0, 0.0),
                n_Z=(1.0, 1.0, 1.0), m_Z=(0.0, 0.0, 0.0))
    dfk.DecoyCounts(**good)
    with pytest.raises(ValueError):  # mu1 must exceed mu2 + mu3
        dfk.DecoyCounts(**{**good, "intensities": (0.12, 0.1, 0.05)})
    with pytest.raises(ValueError):  # probs must sum to 1
        dfk.DecoyCounts(**{**good, "probs": (0.6, 0.3, 0.2)})
    with pytest.raises(ValueError):  # no negative counts
        dfk.DecoyCounts(**{**good, "m_X": (-1.0, 0.0, 0.0)})


def test_gamma_and_phase_degenerate() -> None:
    # gamma falls back to 0 on degenerate arguments, and the phase bound to 1/2 with no Z data.
    assert dfk.gamma(EPS_SEC, 0.0, 10.0, 10.0) == 0.0
    assert dfk.gamma(EPS_SEC, 0.1, 0.0, 10.0) == 0.0
    assert dfk.phase_error_upper(1.0, 0.0, 10.0, EPS_SEC) == 0.5
    assert dfk.phase_error_upper(0.0, 10.0, 10.0, EPS_SEC, finite=False) == 0.0


# ── finite vs asymptotic ─────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", [0.0, 25.0, 50.0])
@pytest.mark.parametrize("n_pulses", [1e8, 1e10, 1e12])
def test_finite_never_exceeds_asymptotic(name: str, length: float, n_pulses: float) -> None:
    counts = dfk.expected_counts(preset(name, length), n_pulses, INTENS, PROBS, Q_X)
    fin = dfk.secure_key_length(counts, EPS_SEC, EPS_COR)
    asy = dfk.asymptotic_key_length(counts)
    assert fin.raw <= asy.raw + 1e-6
    assert fin.ell <= max(0, math.floor(asy.raw))


def test_converges_to_asymptotic() -> None:
    # finite / N -> asymptotic / pulse as N grows (the sqrt(N) penalties wash out).
    p = preset("GYS", 25)
    per_pulse = dfk.asymptotic_key_length(dfk.expected_counts(p, 1.0, INTENS, PROBS, Q_X)).raw
    assert per_pulse > 0.0
    ratios = []
    for n_pulses in (1e11, 1e13, 1e15):
        fin = dfk.secure_key_length(dfk.expected_counts(p, n_pulses, INTENS, PROBS, Q_X), EPS_SEC, EPS_COR)
        ratios.append(fin.raw / n_pulses / per_pulse)
    assert ratios[0] < ratios[1] < ratios[2]        # monotone approach
    assert ratios[-1] == pytest.approx(1.0, abs=5e-3)


@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", [0.0, 25.0, 50.0])
def test_asymptotic_bounds_match_decoy_module(name: str, length: float) -> None:
    # As N -> infinity the vacuum/single-photon event bounds recover decoy.py's Y0 and Y1.
    p = preset(name, length)
    n_pulses = 1e13
    asy = dfk.asymptotic_key_length(dfk.expected_counts(p, n_pulses, INTENS, PROBS, Q_X))
    norm = n_pulses * Q_X * Q_X
    y0_est = asy.s_x0 / (norm * dfk.tau(0, INTENS, PROBS))
    y1_est = asy.s_x1 / (norm * dfk.tau(1, INTENS, PROBS))
    assert y0_est == pytest.approx(p.dark_count_prob, rel=1e-6)   # vacuum bound is exact at mu3=0
    assert y1_est == pytest.approx(decoy.single_photon_yield(p), rel=0.05)  # s1 bound ~3% loose
    assert y1_est <= decoy.single_photon_yield(p)                 # and it is a lower bound


# ── required block size ──────────────────────────────────────────────────────

def test_required_N_grows_with_distance() -> None:
    # For a fixed configuration, more pulses are needed at longer distance.
    rows = dfk.required_N(preset("GYS"), [0, 10, 25, 40, 50], INTENS, PROBS,
                          EPS_SEC, EPS_COR, ell_min=256, q_x=Q_X)
    assert all(r.feasible and r.n_pulses for r in rows)
    sizes = [r.n_pulses for r in rows]
    assert sizes == sorted(sizes)
    assert sizes[0] < sizes[-1]


def test_required_N_reaches_target_and_defaults_match_single_photon_path() -> None:
    # The defaults are the single-photon path's eps values; the key at the returned N clears 256.
    (row,) = dfk.required_N(preset("GYS"), [25], INTENS, PROBS, q_x=Q_X)
    assert row.feasible and row.ell_at_n >= 256
    one_less = dfk.secure_key_length(
        dfk.expected_counts(preset("GYS", 25), row.n_pulses - 1, INTENS, PROBS, Q_X),
        EPS_SEC, EPS_COR).ell
    assert one_less < 256                     # N is the smallest that works (tight)


def test_required_N_infeasible_beyond_reach() -> None:
    # Far past the asymptotic limit no N gives a positive key, so feasible is False.
    rows = dfk.required_N(preset("GYS"), [400.0], INTENS, PROBS, q_x=Q_X)
    assert rows[0].feasible is False and rows[0].n_pulses is None


# ── a worked point in the paper's regime (Lim et al. Fig 1) ──────────────────

def test_lim_fiber_system_reaches_hundred_km() -> None:
    # Lim et al.'s dedicated-fiber system: eta_Bob = 0.1, 0.2 dB/km, p_dc = 6e-7, e_mis = 5e-3
    # (we omit their after-pulsing, which only helps). With a ~1.5e8 block their Fig 1 shows a
    # positive key past 100 km; a fixed near-optimal setting reproduces that order of magnitude.
    base = ChannelParams(loss_db_per_km=0.2, detector_efficiency=0.1,
                         dark_count_prob=6e-7, misalignment=5e-3)
    cfg = dict(intensities=(0.5, 0.1, 0.0), probs=(0.4, 0.4, 0.2))
    near = dfk.secure_key_length(
        dfk.expected_counts(base.at_length(50), 1.5e8, q_x=0.8, **cfg), EPS_SEC, EPS_COR)
    assert near.ell > 1000                                  # comfortably positive at 50 km
    far = dfk.secure_key_length(
        dfk.expected_counts(base.at_length(120), 1.5e8, q_x=0.8, **cfg), EPS_SEC, EPS_COR)
    assert near.ell > far.ell                               # and shrinks with distance
