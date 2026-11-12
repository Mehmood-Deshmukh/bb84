"""
Decoy-state numerics (core/decoy.py), checked against Ma, Qi, Zhao, Lo (PRA 72, 012326,
2005): the expected source/channel quantities, the vacuum+weak decoy bounds, the ordering
of the four key-rate variants, and the reported GYS numbers (optimal mu, maximum secure
distance). decoy.py must not import qiskit; the layering test (tests/test_setup.py) covers
that core does not import services/usecases/runner.
"""

from __future__ import annotations

import math
import subprocess
import sys
from dataclasses import replace

import numpy as np
import pytest

from qkd.core import decoy
from qkd.core.channel_model import ChannelParams, preset

F_EC = decoy.F_EC_DEFAULT  # 1.22, the value Ma et al. use for GYS


def max_secure_distance(preset_name: str, method: str, *, nu: float | None = None,
                        f: float = F_EC, step: float = 0.25, limit: float = 220.0) -> float:
    """Largest fibre length (km) at which the method's optimised key rate is still positive."""
    base = preset(preset_name)
    last = 0.0
    for length in np.arange(0.0, limit, step):
        p = base.at_length(float(length))
        if method == "vacuum_weak":
            mu = decoy.optimal_mu(p, "vacuum_weak", nu=nu, f=f)
            rate = decoy.rate_vacuum_weak(p, mu, nu, f=f)
        elif method == "single_photon":
            rate = decoy.rate_single_photon(p, f=f)
        else:
            mu = decoy.optimal_mu(p, method, f=f)
            rate = decoy.RATE_METHODS[method](p, mu, f=f)
        if rate > 0.0:
            last = float(length)
    return last


# ── expected quantities vs the single-photon model (channel_model) ───────────

@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", [0.0, 25.0, 50.0])
def test_single_photon_yield_matches_click_prob(name: str, length: float) -> None:
    # Y1 = 1 - (1 - Y0)(1 - eta) is exactly ChannelParams.click_prob, by construction.
    p = preset(name, length)
    assert decoy.single_photon_yield(p) == pytest.approx(p.click_prob, rel=1e-15)
    assert decoy.yield_n(p, 1) == pytest.approx(p.click_prob, rel=1e-15)


def test_yield_zero_photons_is_background() -> None:
    p = preset("GYS", 25)
    assert decoy.yield_n(p, 0) == pytest.approx(p.dark_count_prob)


@pytest.mark.parametrize("name", ["GYS", "KTH"])
def test_single_photon_error_matches_channel_model_when_no_dark_counts(name: str) -> None:
    # With Y0 = 0 the paper's e1 = (e0 Y0 + e_d eta)/Y1 and channel_model's
    # (e_d eta + e0 (1 - eta) Y0)/Y1 both collapse to e_d, so they agree exactly. With dark
    # counts they differ only by the negligible e0 eta Y0 / Y1 term (the precedence convention).
    p = replace(preset(name, 25), dark_count_prob=0.0)
    assert decoy.single_photon_error(p) == pytest.approx(p.error_rate, rel=1e-12)
    with_dark = preset(name, 25)
    assert decoy.single_photon_error(with_dark) == pytest.approx(with_dark.error_rate, rel=2e-2)


@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("mu", [0.1, 0.3, 0.5, 1.0])
def test_gain_exact_vs_first_order_approximation(name: str, mu: float) -> None:
    # Exact Q_mu = 1 - (1 - Y0) e^(-eta mu); Ma et al. Eq 10 uses Y0 + 1 - e^(-eta mu). The
    # two differ by exactly Y0 e^(-eta mu) (negligible in absolute terms; not in relative
    # terms for KTH, whose Y0 is close to the tiny gain Q_mu at small mu).
    p = preset(name, 25)
    exact = decoy.gain(p, mu)
    ma_eq10 = p.dark_count_prob + 1.0 - math.exp(-p.eta * mu)
    assert exact < ma_eq10
    # Difference = Q_eq10 - Q_exact = Y0 (1 - e^(-eta mu)).
    assert ma_eq10 - exact == pytest.approx(p.dark_count_prob * (1.0 - math.exp(-p.eta * mu)), rel=1e-9)


def test_gain_at_zero_is_vacuum_yield() -> None:
    # Q_vacuum = Y0 (Ma et al. Eq 33).
    p = preset("KTH", 10)
    assert decoy.gain(p, 0.0) == pytest.approx(p.dark_count_prob)


@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("mu", [0.2, 0.5, 1.0])
def test_error_gain_product_matches_eq11(name: str, mu: float) -> None:
    # E_mu Q_mu = e0 Y0 + e_d (1 - e^(-eta mu)) is exact (Eq 11); E_mu is that over Q_mu.
    p = preset(name, 25)
    assert decoy.qber(p, mu) == pytest.approx(decoy.error_gain_product(p, mu) / decoy.gain(p, mu))


# ── vacuum + weak decoy bounds ───────────────────────────────────────────────

@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", [0.0, 25.0, 50.0, 100.0])
def test_bounds_are_conservative(name: str, length: float) -> None:
    # Y1_L <= true Y1 and e1_U >= true e1 for honest parameters at every distance.
    p = preset(name, length)
    mu, nu = 0.5, 0.05
    gain_mu, gain_nu, qber_nu = decoy.gain(p, mu), decoy.gain(p, nu), decoy.qber(p, nu)
    y1_l = decoy.y1_lower(mu, nu, gain_mu, gain_nu, p.dark_count_prob)
    e1_u = decoy.e1_upper(nu, gain_nu, qber_nu, y1_l, p.dark_count_prob)
    assert y1_l <= decoy.single_photon_yield(p) + 1e-12
    assert e1_u >= decoy.single_photon_error(p) - 1e-12


@pytest.mark.parametrize("name", ["GYS", "KTH"])
def test_bounds_are_tight_as_nu_goes_to_zero(name: str) -> None:
    # On the honest channel the bounds approach the true single-photon values as nu -> 0.
    p = preset(name, 25)
    mu = 0.5
    true_y1, true_e1 = decoy.single_photon_yield(p), decoy.single_photon_error(p)
    prev_y1_gap = prev_e1_gap = math.inf
    for nu in (0.1, 0.01, 0.001):
        gain_mu, gain_nu, qber_nu = decoy.gain(p, mu), decoy.gain(p, nu), decoy.qber(p, nu)
        y1_l = decoy.y1_lower(mu, nu, gain_mu, gain_nu, p.dark_count_prob)
        e1_u = decoy.e1_upper(nu, gain_nu, qber_nu, y1_l, p.dark_count_prob)
        y1_gap, e1_gap = true_y1 - y1_l, e1_u - true_e1
        assert y1_gap < prev_y1_gap and e1_gap < prev_e1_gap  # monotonically tighter
        prev_y1_gap, prev_e1_gap = y1_gap, e1_gap
    # Y1_L converges faster than e1_U (the e1 bound carries the Y1_L slack in its denominator).
    assert y1_l == pytest.approx(true_y1, rel=1e-3)
    assert e1_u == pytest.approx(true_e1, rel=5e-3)


def test_y1_lower_requires_nu_below_mu() -> None:
    with pytest.raises(ValueError):
        decoy.y1_lower(0.4, 0.4, 0.01, 0.005, 1e-6)
    with pytest.raises(ValueError):
        decoy.y1_lower(0.4, 0.5, 0.01, 0.005, 1e-6)


def test_bounds_clamp_to_physical_range() -> None:
    # A degenerate measurement can drive the raw bounds out of range; they must clamp.
    assert decoy.y1_lower(0.5, 0.05, 0.9, 0.0, 0.0) == 0.0            # Y1_L >= 0
    assert decoy.e1_upper(0.05, 0.0, 0.0, 0.0, 0.0) == decoy.E0        # Y1_L = 0 -> e0
    assert 0.0 <= decoy.e1_upper(0.05, 0.5, 0.9, 1e-6, 0.0) <= decoy.E0


# ── key-rate variants ────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["GYS", "KTH"])
@pytest.mark.parametrize("length", list(range(0, 150, 10)))
def test_rate_ordering(name: str, length: float) -> None:
    # no decoy <= vacuum+weak <= infinite decoy, at every distance, each mu-optimised.
    p = preset(name, length)
    r_no = decoy.rate_no_decoy(p, decoy.optimal_mu(p, "no_decoy"))
    r_vw = decoy.rate_vacuum_weak(p, decoy.optimal_mu(p, "vacuum_weak", nu=0.05), 0.05)
    r_inf = decoy.rate_infinite_decoy(p, decoy.optimal_mu(p, "infinite_decoy"))
    assert r_no <= r_vw + 1e-12
    assert r_vw <= r_inf + 1e-12


def test_rates_never_negative() -> None:
    # Far beyond the secure distance every variant floors at 0, not a negative rate.
    p = preset("GYS", 200)
    assert decoy.rate_no_decoy(p, 0.5) == 0.0
    assert decoy.rate_vacuum_weak(p, 0.5, 0.05) == 0.0
    assert decoy.rate_infinite_decoy(p, 0.5) == 0.0
    assert decoy.rate_single_photon(p) >= 0.0


def test_single_photon_rate_reduces_to_closed_form() -> None:
    p = preset("GYS", 25)
    y1, e1 = decoy.single_photon_yield(p), decoy.single_photon_error(p)
    h = decoy.binary_entropy(e1)
    expected = 0.5 * y1 * (1.0 - (1.0 + F_EC) * h)
    assert decoy.rate_single_photon(p) == pytest.approx(expected)


# ── validation against Ma et al.'s reported numbers ──────────────────────────
#
# Targets read from the paper (GYS parameters, Table 1; error correction f = 1.22):
#   - Optimal signal intensity mu_optimal^GYS ~ 0.48 for f = 1.22 and ~ 0.54 for f = 1
#     (Section 3.1, just below Eq 12, page 7).
#   - Maximum secure distance (Figure 2 caption, page 16): infinite decoy 142.05 km;
#     Vacuum+Weak (mu = 0.48, nu = 0.05) 140.55 km.
# The paper reports no pure "no decoy" maximum distance and no KTH distances, so those are
# only sanity-checked (ordering + positivity), not asserted against paper numbers.

def test_optimal_mu_matches_ma_et_al_gys() -> None:
    gys = preset("GYS", 0)
    assert decoy.optimal_mu(gys, "infinite_decoy", f=1.22) == pytest.approx(0.48, abs=0.03)
    assert decoy.optimal_mu(gys, "infinite_decoy", f=1.0) == pytest.approx(0.54, abs=0.03)
    assert 0.0 < decoy.optimal_mu(gys, "no_decoy", f=1.22) <= 1.0


def test_max_distance_infinite_decoy_gys_matches_figure2() -> None:
    # Paper: 142.05 km.
    assert max_secure_distance("GYS", "infinite_decoy") == pytest.approx(142.05, abs=3.0)


def test_max_distance_vacuum_weak_gys_matches_figure2() -> None:
    # Paper: 140.55 km with nu = 0.05 (we optimise mu rather than fixing it at 0.48, which
    # is why ours runs a touch further).
    assert max_secure_distance("GYS", "vacuum_weak", nu=0.05) == pytest.approx(140.55, abs=3.0)
    # A larger weak decoy loosens the bounds, so its reach is shorter.
    assert max_secure_distance("GYS", "vacuum_weak", nu=0.10) < \
        max_secure_distance("GYS", "vacuum_weak", nu=0.05)


def test_no_decoy_reaches_far_less_than_decoy() -> None:
    # Sanity only (no paper target): the GLLP worst case dies early because GYS's low
    # efficiency makes the multi-photon fraction dominate the gain.
    no_decoy = max_secure_distance("GYS", "no_decoy")
    assert 10.0 < no_decoy < 100.0
    assert no_decoy < max_secure_distance("GYS", "infinite_decoy")


# ── expected counts ──────────────────────────────────────────────────────────

def test_expected_counts() -> None:
    p = preset("GYS", 25)
    n = 1_000_000
    ec = decoy.expected_counts(n, [0.5, 0.1, 0.0], [0.7, 0.2, 0.1], p)
    assert ec.pulses == pytest.approx(np.array([0.7, 0.2, 0.1]) * n)
    assert ec.clicks[0] == pytest.approx(0.7 * n * decoy.gain(p, 0.5))
    # The vacuum intensity clicks only on the background rate Y0.
    assert ec.clicks[2] == pytest.approx(0.1 * n * p.dark_count_prob)


def test_expected_counts_validates_probs() -> None:
    p = preset("GYS", 25)
    with pytest.raises(ValueError):
        decoy.expected_counts(1000, [0.5, 0.1], [0.7, 0.2], p)  # probs do not sum to 1
    with pytest.raises(ValueError):
        decoy.expected_counts(1000, [0.5, 0.1, 0.0], [0.7, 0.2], p)  # length mismatch


# ── layering / dependency guards ─────────────────────────────────────────────

def test_decoy_does_not_import_qiskit() -> None:
    code = (
        "import sys; import qkd.core.decoy; "
        "assert 'qiskit' not in sys.modules, sorted(m for m in sys.modules if 'qiskit' in m)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
