"""
Decoy-state numerics for weak-coherent-pulse BB84 (Ma, Qi, Zhao, Lo, Phys. Rev. A 72,
012326, 2005; literature/2005_Ma-Qi-Zhao-Lo_practical-decoy-state_PRA72-012326.pdf).

This is Phase 1: numbers only. Nothing here touches the protocol, the wire, Eve, or the
simulator, and the module imports no qiskit. It reuses ``ChannelParams`` from
``channel_model`` (eta, dark_count_prob = Y0, misalignment = e_d) and ``binary_entropy``
from ``finite_key``. Pure Python + NumPy/SciPy.

What the paper gives us (equation numbers refer to the PDF):

  Source   a weak coherent pulse of intensity mu has a Poisson photon number (Eq 4).
  Detector threshold detector, i-photon transmittance eta_i = 1 - (1 - eta)^i (Eq 6).
  Yield    Y_i = Y0 + eta_i - Y0 eta_i = 1 - (1 - Y0)(1 - eta)^i (Eq 7, exact form).
  Gain     Q_i = Y_i mu^i e^-mu / i!  (Eq 8); overall Q_mu = 1 - (1 - Y0) e^(-eta mu).
  Error    e_i = (e0 Y0 + e_d eta_i) / Y_i  (Eq 9), e0 = 1/2; E_mu Q_mu = e0 Y0 +
           e_d (1 - e^(-eta mu))  (Eq 11).

Single-photon truth: Y1 = 1 - (1 - Y0)(1 - eta), e1 = (e0 Y0 + e_d eta) / Y1,
Q1 = Y1 mu e^-mu.

Vacuum+weak decoy estimates (signal mu, weak decoy nu < mu, vacuum gives Y0, Eqs 34/37/35):
lower bound Y1_L, upper bound e1_U, and Q1_L = Y1_L mu e^-mu.

Key rate (GLLP, Eq 1): R = q{ -Q_mu f h(E_mu) + Q1 [1 - h(e1)] }, q = 1/2 for BB84,
f the error-correction inefficiency. Four variants are provided (single-photon source,
no decoy / GLLP worst case, infinite decoy / true values, vacuum+weak).

NOTE on the exact vs approximate gain. The paper writes Q_mu ~ Y0 + 1 - e^(-eta mu)
(Eq 10, first order in the small quantity Y0). The exact value obtained by summing Eq 8
over the Poisson distribution is Q_mu = 1 - (1 - Y0) e^(-eta mu); this module uses the
exact form, which differs only by the negligible term Y0 (1 - e^(-eta mu)).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize_scalar

from qkd.core.channel_model import E0, ChannelParams
from qkd.core.finite_key import binary_entropy

__all__ = [
    "E0",
    "yield_n",
    "gain",
    "error_gain_product",
    "qber",
    "single_photon_yield",
    "single_photon_error",
    "single_photon_gain",
    "y1_lower",
    "e1_upper",
    "q1_lower",
    "rate_single_photon",
    "rate_no_decoy",
    "rate_infinite_decoy",
    "rate_vacuum_weak",
    "optimal_mu",
    "ExpectedCounts",
    "expected_counts",
    "RATE_METHODS",
]

# q = 1/2 for standard BB84 (half the time the bases disagree); f is the
# error-correction inefficiency, f = 1 at the Shannon limit. Ma et al. use f = 1.22.
Q_BB84 = 0.5
F_EC_DEFAULT = 1.22


# ── expected source / channel quantities (honest, no eavesdropper) ───────────

def yield_n(params: ChannelParams, n: int) -> float:
    """
    Y_n, the yield of an n-photon state: the probability of a click at Bob given Alice
    sent exactly n photons (Ma et al. Eq 7, exact form Y_n = 1 - (1 - Y0)(1 - eta)^n).
    """
    if n < 0:
        raise ValueError("n must not be negative")
    eta = params.eta
    return 1.0 - (1.0 - params.dark_count_prob) * (1.0 - eta) ** n


def gain(params: ChannelParams, mu: float) -> float:
    """
    Q_mu, the overall gain (probability a sent pulse of intensity mu clicks at Bob).

    Exact form Q_mu = 1 - (1 - Y0) e^(-eta mu), from summing Eq 8 over the Poisson photon
    number. The paper's Eq 10 uses the first-order approximation Y0 + 1 - e^(-eta mu);
    the two differ only by Y0 (1 - e^(-eta mu)). At mu = 0 this returns Q_vacuum = Y0 (Eq 33).
    """
    if mu < 0:
        raise ValueError("mu must not be negative")
    return 1.0 - (1.0 - params.dark_count_prob) * math.exp(-params.eta * mu)


def error_gain_product(params: ChannelParams, mu: float) -> float:
    """
    E_mu Q_mu, the product of QBER and gain (Ma et al. Eq 11, exact):
    e0 Y0 + e_d (1 - e^(-eta mu)). This is an exact identity, not an approximation.
    """
    if mu < 0:
        raise ValueError("mu must not be negative")
    return E0 * params.dark_count_prob + params.misalignment * (1.0 - math.exp(-params.eta * mu))


def qber(params: ChannelParams, mu: float) -> float:
    """E_mu, the overall QBER for intensity mu. Returns 0 when the gain is 0."""
    q_mu = gain(params, mu)
    if q_mu <= 0.0:
        return 0.0
    return error_gain_product(params, mu) / q_mu


def single_photon_yield(params: ChannelParams) -> float:
    """
    Y1 = 1 - (1 - Y0)(1 - eta). Equal to ``ChannelParams.click_prob`` by construction
    (both are eta + (1 - eta) Y0), so the single-photon yield agrees with channel_model.
    """
    return yield_n(params, 1)


def single_photon_error(params: ChannelParams) -> float:
    """
    e1 = (e0 Y0 + e_d eta) / Y1 (Ma et al. Eq 9 at i = 1).

    This is the paper's convention. channel_model.ChannelParams.error_rate uses a slightly
    different one, (e_d eta + e0 (1 - eta) Y0) / Y1, because that module assumes an
    arriving photon takes precedence over a simultaneous dark count. The two differ only by
    the O(Y0 eta) term e0 eta Y0 / Y1 and agree in the e_d-dominated regime.
    """
    y1 = single_photon_yield(params)
    if y1 <= 0.0:
        return 0.0
    return (E0 * params.dark_count_prob + params.misalignment * params.eta) / y1


def single_photon_gain(params: ChannelParams, mu: float) -> float:
    """Q1 = Y1 mu e^-mu (Ma et al. Eq 8 at i = 1): the true single-photon gain at intensity mu."""
    return single_photon_yield(params) * mu * math.exp(-mu)


# ── vacuum + weak decoy bounds (take MEASURED gains/QBERs, Ma et al. 3.4) ─────
#
# These take observed quantities (Q_mu, Q_nu, E_nu, Y0) rather than ChannelParams, so that
# a later phase can feed in values measured under attack. In this phase the honest rate
# functions below compute the expected measurements from ChannelParams and pass them in.

def y1_lower(mu: float, nu: float, gain_mu: float, gain_nu: float, y0: float) -> float:
    """
    Lower bound on the single-photon yield Y1 from a vacuum+weak decoy (Ma et al. Eq 34):

        Y1_L = mu / (mu nu - nu^2)
               * [ Q_nu e^nu - Q_mu e^mu nu^2/mu^2 - (mu^2 - nu^2)/mu^2 Y0 ]

    where Y0 is the background rate measured from the vacuum decoy. Requires 0 < nu < mu.
    Clamped to Y1_L >= 0: the raw bound can go slightly negative from statistical slack or
    a too-small nu, and a negative yield is unphysical (it then yields a zero key rate).
    """
    if not 0.0 < nu < mu:
        raise ValueError(f"need 0 < nu < mu, got nu={nu}, mu={mu}")
    coeff = mu / (mu * nu - nu * nu)
    bracket = gain_nu * math.exp(nu) - gain_mu * math.exp(mu) * nu * nu / (mu * mu) \
        - (mu * mu - nu * nu) / (mu * mu) * y0
    return max(0.0, coeff * bracket)


def e1_upper(nu: float, gain_nu: float, qber_nu: float, y1_l: float, y0: float) -> float:
    """
    Upper bound on the single-photon error rate e1 from a vacuum+weak decoy (Ma et al. Eq 37):

        e1_U = (E_nu Q_nu e^nu - e0 Y0) / (Y1_L nu)

    Clamped to [0, 1/2]: e0 = 1/2 is the worst case (a fully random error), so e1 above 1/2
    is meaningless, and the raw bound can dip below 0 from statistical slack. When Y1_L is 0
    the bound is undefined and we return 1/2 (no usable single-photon key).
    """
    if nu <= 0.0:
        raise ValueError(f"nu must be positive, got {nu}")
    if y1_l <= 0.0:
        return E0
    raw = (qber_nu * gain_nu * math.exp(nu) - E0 * y0) / (y1_l * nu)
    return min(E0, max(0.0, raw))


def q1_lower(mu: float, y1_l: float) -> float:
    """Q1_L = Y1_L mu e^-mu (Ma et al. Eq 35): the single-photon gain from the Y1 lower bound."""
    return y1_l * mu * math.exp(-mu)


# ── key rate variants (GLLP, Ma et al. Eq 1) ─────────────────────────────────

def _gllp_rate(gain_mu: float, qber_mu: float, q1: float, e1: float, q: float, f: float) -> float:
    """R = q{ -Q_mu f h(E_mu) + Q1 [1 - h(e1)] }, floored at 0 (Ma et al. Eq 1)."""
    rate = q * (-gain_mu * f * binary_entropy(qber_mu) + q1 * (1.0 - binary_entropy(e1)))
    return max(0.0, rate)


def rate_single_photon(params: ChannelParams, q: float = Q_BB84, f: float = F_EC_DEFAULT) -> float:
    """
    Key rate for an ideal single-photon source (every pulse is exactly one photon). This is
    what the current code assumes (channel_model.expected_secure_rate). With Q_mu = Q1 = Y1
    and E_mu = e1, Eq 1 reduces to R = q Y1 [1 - (1 + f) h(e1)].
    """
    y1 = single_photon_yield(params)
    e1 = single_photon_error(params)
    return _gllp_rate(y1, e1, y1, e1, q, f)


def rate_no_decoy(params: ChannelParams, mu: float, q: float = Q_BB84, f: float = F_EC_DEFAULT) -> float:
    """
    Key rate for a weak coherent source with no decoy states, GLLP worst case: every
    multi-photon pulse is assumed tagged (insecure). The tagged fraction of detected signals
    is Delta = (1 - e^-mu (1 + mu)) / Q_mu (multi-photon probability over the gain, assuming
    every multi-photon pulse clicks), giving Q1 = Q_mu (1 - Delta) and e1 = E_mu / (1 - Delta).

    Optimise mu per distance with optimal_mu(params, "no_decoy").
    """
    gain_mu = gain(params, mu)
    qber_mu = qber(params, mu)
    if gain_mu <= 0.0:
        return 0.0
    multi = 1.0 - math.exp(-mu) * (1.0 + mu)
    delta = multi / gain_mu
    untagged = 1.0 - delta
    if untagged <= 0.0:
        return 0.0
    q1 = gain_mu * untagged
    e1 = min(E0, qber_mu / untagged)
    return _gllp_rate(gain_mu, qber_mu, q1, e1, q, f)


def rate_infinite_decoy(params: ChannelParams, mu: float, q: float = Q_BB84, f: float = F_EC_DEFAULT) -> float:
    """
    Key rate with an infinite number of decoy states: Y1 and e1 are known exactly (the upper
    limit on what any decoy protocol can reach). Q1 = Y1 mu e^-mu. Optimise mu per distance.
    """
    gain_mu = gain(params, mu)
    qber_mu = qber(params, mu)
    q1 = single_photon_gain(params, mu)
    e1 = single_photon_error(params)
    return _gllp_rate(gain_mu, qber_mu, q1, e1, q, f)


def rate_vacuum_weak(params: ChannelParams, mu: float, nu: float,
                     q: float = Q_BB84, f: float = F_EC_DEFAULT) -> float:
    """
    Key rate for the vacuum+weak decoy protocol: Q1 and e1 come from the bounds Y1_L / e1_U
    estimated from the signal (mu), a weak decoy (nu) and a vacuum decoy (Y0). The expected
    gains and QBERs are computed from ``params`` here and passed to the bound functions.
    """
    gain_mu = gain(params, mu)
    qber_mu = qber(params, mu)
    gain_nu = gain(params, nu)
    qber_nu = qber(params, nu)
    y0 = params.dark_count_prob
    y1_l = y1_lower(mu, nu, gain_mu, gain_nu, y0)
    e1_u = e1_upper(nu, gain_nu, qber_nu, y1_l, y0)
    q1_l = q1_lower(mu, y1_l)
    return _gllp_rate(gain_mu, qber_mu, q1_l, e1_u, q, f)


RATE_METHODS = {
    "no_decoy": rate_no_decoy,
    "infinite_decoy": rate_infinite_decoy,
    "vacuum_weak": rate_vacuum_weak,
}


def optimal_mu(params: ChannelParams, method: str, nu: float = 0.05,
               q: float = Q_BB84, f: float = F_EC_DEFAULT) -> float:
    """
    Signal intensity mu in (0, 1] that maximises the key rate for the given method
    (Ma et al. restrict mu to (0, 1], 3.1). ``method`` is one of RATE_METHODS; ``nu`` is
    only used by "vacuum_weak". Returns the optimal mu (not the rate).
    """
    if method not in RATE_METHODS:
        raise ValueError(f"Unknown method {method!r}. Known: {', '.join(RATE_METHODS)}")
    rate_fn = RATE_METHODS[method]
    if method == "vacuum_weak":
        def rate_at(mu: float) -> float:
            return rate_fn(params, mu, nu, q, f)
    else:
        def rate_at(mu: float) -> float:
            return rate_fn(params, mu, q, f)

    # The no-decoy worst case peaks in a narrow spike at mu ~ 2 eta and is flat at zero
    # elsewhere, where a bare bounded-Brent search gets stuck. Pre-scan a dense grid to
    # bracket the maximum, then refine with bounded Brent inside that bracket.
    # vacuum_weak needs mu > nu (Eq 15), so start the grid just above nu there.
    lo = (nu + 1e-3) if method == "vacuum_weak" else 1e-4
    hi = 1.0
    if lo >= hi:
        raise ValueError(f"nu={nu} leaves no room for mu in (nu, 1]")
    grid = np.linspace(lo, hi, 400)
    rates = np.array([rate_at(float(mu)) for mu in grid])
    best = int(np.argmax(rates))
    if rates[best] <= 0.0:
        return float(grid[best])
    left = float(grid[max(best - 1, 0)])
    right = float(grid[min(best + 1, len(grid) - 1)])
    result = minimize_scalar(lambda mu: -rate_at(mu), bounds=(left, right),
                             method="bounded", options={"xatol": 1e-6})
    return float(result.x) if -result.fun >= rates[best] else float(grid[best])


# ── expected counts per intensity (for Phase 5 finite-key sizing) ────────────

@dataclass(frozen=True)
class ExpectedCounts:
    """
    Expected pulse and click counts per intensity for a block of N pulses.

    intensities[i] is sent with probability probs[i]; pulses[i] = N probs[i] is the expected
    number sent at that intensity and clicks[i] = pulses[i] Q(intensity[i]) the expected
    number that click at Bob. Phase 5 will use these for finite-key statistics.
    """

    n_pulses: int
    intensities: np.ndarray
    probs: np.ndarray
    pulses: np.ndarray
    clicks: np.ndarray


def expected_counts(n_pulses: int, intensities, probs, params: ChannelParams) -> ExpectedCounts:
    """
    Expected pulses and clicks per intensity for N pulses split by ``probs`` over ``intensities``.

    ``probs`` must be non-negative and sum to 1 (one entry per intensity). The expected click
    count at intensity x is N p_x Q_x, with Q_x the exact gain from ``gain``.
    """
    intensities = np.asarray(intensities, dtype=float)
    probs = np.asarray(probs, dtype=float)
    if intensities.shape != probs.shape or intensities.ndim != 1:
        raise ValueError("intensities and probs must be 1-D arrays of the same length")
    if n_pulses < 0:
        raise ValueError("n_pulses must not be negative")
    if np.any(intensities < 0) or np.any(probs < 0):
        raise ValueError("intensities and probs must be non-negative")
    if not math.isclose(float(probs.sum()), 1.0, rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError(f"probs must sum to 1, got {float(probs.sum())}")
    pulses = n_pulses * probs
    gains = np.array([gain(params, float(x)) for x in intensities])
    clicks = pulses * gains
    return ExpectedCounts(n_pulses, intensities, probs, pulses, clicks)
