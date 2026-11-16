"""
Composable finite-key decoy-state bounds (Lim, Curty, Walenta, Xu, Zbinden,
Phys. Rev. A 89, 022307, 2014).

Phase 5a: numbers only. Nothing here touches the protocol, the wire, Eve, or the simulator,
and the module imports no qiskit. It builds on ``decoy.py`` (Ma et al. asymptotic numerics)
and reuses ``ChannelParams`` and ``binary_entropy``. Pure Python + NumPy/SciPy.

Where decoy.py gives the *asymptotic* vacuum+weak bounds (Ma et al. 2005), this module gives
the *composable finite-key* bounds valid against general attacks: the secure length is bounded
by the smooth min-entropy of the raw key, with every statistical quantity (vacuum, single-photon
and phase-error counts) replaced by a finite-sample bound from Hoeffding's inequality and a
random-sampling-without-replacement tail. All bound functions take MEASURED counts, so Phase 5b
can feed attacked runs; the honest expected counts are produced here by ``expected_counts``.

Protocol (Lim et al., "Protocol Description"): asymmetric-basis BB84. Bases X, Z are chosen with
probabilities q_x, 1 - q_x; the key is extracted from the events where both pick X. Each pulse
has one of three intensities K = {mu1, mu2, mu3} (signal, decoy, vacuum) with mu1 > mu2 + mu3,
mu2 > mu3 >= 0, sent with probabilities p1, p2, p3.

Equation numbers below refer to the paper (main text Eqs 1-5, supplement Eqs 2-13):

  tau_n = sum_k e^{-mu_k} mu_k^n p_k / n!       probability Alice sends an n-photon state.

  Hoeffding deviation (supp Eq 1, with eps_1 = eps_sec/21 so that eps_sec = 21 eps):
      delta(M) = sqrt( (M / 2) ln(21 / eps_sec) ),   M = detections (or errors) in that basis.
  Tilted counts (main text, below Eq 3; supp Eqs 7-10):
      n_pm[k] = (e^{mu_k} / p_k) ( n_k +/- delta ).

  s0  >= tau0 ( mu2 n_minus[mu3] - mu3 n_plus[mu2] ) / (mu2 - mu3)                  (Eq 2)
  s1  >= tau1 mu1 [ n_minus[mu2] - n_plus[mu3]
                    - (mu2^2 - mu3^2)/mu1^2 ( n_plus[mu1] - s0/tau0 ) ]
          / ( mu1(mu2 - mu3) - mu2^2 + mu3^2 )                                      (Eq 3)
  v1  <= tau1 ( m_plus[mu2] - m_minus[mu3] ) / (mu2 - mu3)                          (Eq 4)
  phi_X <= v_{Z,1}/s_{Z,1} + gamma(eps_sec, v_{Z,1}/s_{Z,1}, s_{Z,1}, s_{X,1})      (Eq 5)
      gamma(a,b,c,d) = sqrt( (c+d)(1-b)b / (c d ln2) * log2( (c+d)/(c d (1-b) b) * 21^2/a^2 ) )

  ell = floor( s_{X,0} + s_{X,1}[1 - h(phi_X)]
               - leak_EC - 6 log2(21/eps_sec) - log2(2/eps_cor) )                   (Eq 1)
      leak_EC = f_EC n_X h(E_X),  E_X the observed X-basis error rate.

s_{X,0}, s_{X,1} use the X (key-basis) detection counts; s_{Z,1} and v_{Z,1} use the Z-basis
detection and error counts (the phase error of the X single-photons is estimated from Z, where
Alice and Bob would have obtained the complementary bits). Deviation from the paper, if any, is
flagged in a comment; none is intended.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from qkd.core import decoy
from qkd.core.channel_model import ChannelParams
from qkd.core.finite_key import binary_entropy

__all__ = [
    "DecoyCounts",
    "KeyLengthResult",
    "tau",
    "hoeffding_delta",
    "s0_lower",
    "s1_lower",
    "v1_upper",
    "gamma",
    "phase_error_upper",
    "secure_key_length",
    "expected_counts",
    "required_N",
    "RequiredN",
    "F_EC_DEFAULT",
    "SECRECY_TERMS",
]

# Lim et al. use f_EC = 1.16 in their evaluation; decoy.py (Ma et al.) uses 1.22.
F_EC_DEFAULT = 1.16
# eps_sec = 21 * eps (supp Eq 14, with alpha_4 = alpha_5 = 0 and every term set to eps).
SECRECY_TERMS = 21


@dataclass(frozen=True)
class DecoyCounts:
    """
    Measured per-intensity counts for one block, in the key basis X and the test basis Z.

    intensities = (mu1, mu2, mu3) = (signal, decoy, vacuum), mu1 > mu2 + mu3, mu2 > mu3 >= 0.
    probs = (p1, p2, p3), one send-probability per intensity, summing to 1.
    n_X[i] / n_Z[i] are Bob's detections when Alice sent intensity i in a sifted X / Z event;
    m_X[i] / m_Z[i] are the bit errors among them. All are non-negative (reals are fine: the
    expected-count path passes fractional values).
    """

    intensities: tuple[float, float, float]
    probs: tuple[float, float, float]
    n_X: tuple[float, float, float]
    m_X: tuple[float, float, float]
    n_Z: tuple[float, float, float]
    m_Z: tuple[float, float, float]

    def __post_init__(self) -> None:
        mu1, mu2, mu3 = self.intensities
        if not (mu1 > mu2 + mu3 and mu2 > mu3 >= 0.0):
            raise ValueError(f"need mu1 > mu2 + mu3 and mu2 > mu3 >= 0, got {self.intensities}")
        if not math.isclose(sum(self.probs), 1.0, abs_tol=1e-9) or any(p < 0 for p in self.probs):
            raise ValueError(f"probs must be non-negative and sum to 1, got {self.probs}")
        for name in ("n_X", "m_X", "n_Z", "m_Z"):
            vals = getattr(self, name)
            if len(vals) != 3 or any(v < 0 for v in vals):
                raise ValueError(f"{name} must be three non-negative counts, got {vals}")


@dataclass(frozen=True)
class KeyLengthResult:
    """The composable secure length and the intermediate bounds that produced it."""

    ell: int            # floored at 0: the number of extractable secret bits
    raw: float          # the unfloored length (may be negative), for comparisons/convergence
    s_x0: float         # vacuum events in X (secure: Eve has no information on them)
    s_x1: float         # single-photon events in X
    s_z1: float         # single-photon events in Z (for the phase estimate)
    v_z1: float         # single-photon bit errors in Z
    phi_x: float        # single-photon phase error rate bound
    e_x: float          # observed X-basis error rate
    leak_ec: float      # bits revealed by error correction


# ── building blocks ──────────────────────────────────────────────────────────

def tau(n: int, intensities, probs) -> float:
    """tau_n = sum_k e^{-mu_k} mu_k^n p_k / n!: the probability Alice sends an n-photon state."""
    fact = math.factorial(n)
    return sum(p * math.exp(-mu) * mu ** n / fact for mu, p in zip(intensities, probs))


def hoeffding_delta(m_total: float, eps_sec: float) -> float:
    """delta(M) = sqrt( (M/2) ln(21/eps_sec) ): the Hoeffding deviation (supp Eq 1)."""
    if m_total <= 0.0:
        return 0.0
    return math.sqrt(m_total / 2.0 * math.log(SECRECY_TERMS / eps_sec))


def _tilt(count: float, mu: float, p: float, delta: float, sign: float) -> float:
    """n_pm[k] = (e^{mu}/p)(count +/- delta): the finite-sample tilt of one count (supp Eqs 7-10)."""
    return math.exp(mu) / p * (count + sign * delta)


def s0_lower(n_k, delta: float, intensities, probs) -> float:
    """Lower bound on vacuum events (Eq 2), clamped to >= 0."""
    mu2, mu3 = intensities[1], intensities[2]
    n_minus_3 = _tilt(n_k[2], mu3, probs[2], delta, -1.0)
    n_plus_2 = _tilt(n_k[1], mu2, probs[1], delta, +1.0)
    s0 = tau(0, intensities, probs) * (mu2 * n_minus_3 - mu3 * n_plus_2) / (mu2 - mu3)
    return max(0.0, s0)


def s1_lower(n_k, delta: float, s0: float, intensities, probs) -> float:
    """Lower bound on single-photon events (Eq 3), clamped to >= 0. ``s0`` is s0_lower above."""
    mu1, mu2, mu3 = intensities
    t0 = tau(0, intensities, probs)
    t1 = tau(1, intensities, probs)
    n_minus_2 = _tilt(n_k[1], mu2, probs[1], delta, -1.0)
    n_plus_3 = _tilt(n_k[2], mu3, probs[2], delta, +1.0)
    n_plus_1 = _tilt(n_k[0], mu1, probs[0], delta, +1.0)
    bracket = n_minus_2 - n_plus_3 - (mu2 ** 2 - mu3 ** 2) / mu1 ** 2 * (n_plus_1 - s0 / t0)
    denom = mu1 * (mu2 - mu3) - mu2 ** 2 + mu3 ** 2
    return max(0.0, t1 * mu1 * bracket / denom)


def v1_upper(m_k, delta: float, intensities, probs) -> float:
    """Upper bound on single-photon bit errors (Eq 4), clamped to >= 0."""
    mu2, mu3 = intensities[1], intensities[2]
    m_plus_2 = _tilt(m_k[1], mu2, probs[1], delta, +1.0)
    m_minus_3 = _tilt(m_k[2], mu3, probs[2], delta, -1.0)
    return max(0.0, tau(1, intensities, probs) * (m_plus_2 - m_minus_3) / (mu2 - mu3))


def gamma(a: float, b: float, c: float, d: float) -> float:
    """
    Random-sampling-without-replacement tail (Eq 5 / supp Eq 12):

        gamma(a,b,c,d) = sqrt( (c+d)(1-b)b / (c d ln2) * log2( (c+d)/(c d (1-b) b) * 21^2/a^2 ) )

    with a = eps_sec, b the Z single-photon error rate, c = s_{Z,1}, d = s_{X,1}. Returns 0 when
    any argument is degenerate (so the phase bound falls back to the point estimate b).
    """
    if c <= 0.0 or d <= 0.0 or not 0.0 < b < 1.0:
        return 0.0
    arg = (c + d) / (c * d * (1.0 - b) * b) * (SECRECY_TERMS ** 2) / (a * a)
    if arg <= 1.0:
        return 0.0
    val = (c + d) * (1.0 - b) * b / (c * d * math.log(2.0)) * math.log2(arg)
    return math.sqrt(val) if val > 0.0 else 0.0


def phase_error_upper(v_z1: float, s_z1: float, s_x1: float, eps_sec: float,
                      *, finite: bool = True) -> float:
    """phi_X <= v_{Z,1}/s_{Z,1} + gamma(...) (Eq 5), clamped to [0, 1/2]."""
    if s_z1 <= 0.0 or s_x1 <= 0.0:
        return 0.5
    b = v_z1 / s_z1
    if b >= 0.5:
        return 0.5
    g = gamma(eps_sec, b, s_z1, s_x1) if finite else 0.0
    return min(0.5, b + g)


# ── the composable secure length (Eq 1) ──────────────────────────────────────

def _length(counts: DecoyCounts, eps_sec: float, eps_cor: float, f_ec: float,
            *, finite: bool) -> KeyLengthResult:
    intensities, probs = counts.intensities, counts.probs
    n_x, n_z = sum(counts.n_X), sum(counts.n_Z)
    m_x, m_z = sum(counts.m_X), sum(counts.m_Z)

    delta_x = hoeffding_delta(n_x, eps_sec) if finite else 0.0
    delta_z = hoeffding_delta(n_z, eps_sec) if finite else 0.0
    delta_mz = hoeffding_delta(m_z, eps_sec) if finite else 0.0

    s_x0 = s0_lower(counts.n_X, delta_x, intensities, probs)
    s_x1 = s1_lower(counts.n_X, delta_x, s_x0, intensities, probs)
    s_z0 = s0_lower(counts.n_Z, delta_z, intensities, probs)
    s_z1 = s1_lower(counts.n_Z, delta_z, s_z0, intensities, probs)
    v_z1 = v1_upper(counts.m_Z, delta_mz, intensities, probs)
    phi_x = phase_error_upper(v_z1, s_z1, s_x1, eps_sec, finite=finite)

    e_x = m_x / n_x if n_x > 0 else 0.0
    leak_ec = f_ec * n_x * binary_entropy(e_x)

    raw = s_x0 + s_x1 * (1.0 - binary_entropy(phi_x)) - leak_ec
    if finite:
        raw -= 6.0 * math.log2(SECRECY_TERMS / eps_sec) + math.log2(2.0 / eps_cor)
    return KeyLengthResult(max(0, math.floor(raw)), raw, s_x0, s_x1, s_z1, v_z1, phi_x, e_x, leak_ec)


def secure_key_length(counts: DecoyCounts, eps_sec: float, eps_cor: float,
                      f_ec: float = F_EC_DEFAULT) -> KeyLengthResult:
    """
    The composable eps_sec-secret, eps_cor-correct key length from measured counts (Lim Eq 1).

    Pass ``eps_sec``, ``eps_cor`` explicitly (the single-photon path uses 1e-10 / 1e-15).
    """
    return _length(counts, eps_sec, eps_cor, f_ec, finite=True)


def asymptotic_key_length(counts: DecoyCounts, f_ec: float = F_EC_DEFAULT) -> KeyLengthResult:
    """
    The same decomposition with every finite-sample penalty removed (Hoeffding deviations, the
    phase-estimation gamma, and the two secrecy/correctness log terms all set to 0). This is the
    N -> infinity limit of ``secure_key_length`` at the same counts, and the upper bound every
    finite key must respect. ``eps`` values are irrelevant here and are not taken.
    """
    return _length(counts, 1.0, 1.0, f_ec, finite=False)


# ── expected honest counts (for sizing and the asymptotic cross-check) ────────

def expected_counts(params: ChannelParams, n_pulses: float, intensities, probs,
                    q_x: float = 0.5) -> DecoyCounts:
    """
    The honest expected per-intensity counts for ``n_pulses`` total pulses.

    Alice and Bob each pick basis X independently with probability ``q_x``, so a sifted-X event
    has probability q_x^2 and a sifted-Z event (1 - q_x)^2. At intensity mu_i (prob p_i) the
    expected sifted-X detections are n_pulses p_i q_x^2 Q(mu_i) and the expected errors are that
    times E(mu_i), with Q, E the exact gain/QBER from ``decoy``. Counts are real-valued.
    """
    intensities = tuple(float(x) for x in intensities)
    probs = tuple(float(x) for x in probs)
    gains = tuple(decoy.gain(params, mu) for mu in intensities)
    qbers = tuple(decoy.qber(params, mu) for mu in intensities)
    fx, fz = q_x * q_x, (1.0 - q_x) * (1.0 - q_x)
    n_X = tuple(n_pulses * p * fx * g for p, g in zip(probs, gains))
    m_X = tuple(n_pulses * p * fx * g * e for p, g, e in zip(probs, gains, qbers))
    n_Z = tuple(n_pulses * p * fz * g for p, g in zip(probs, gains))
    m_Z = tuple(n_pulses * p * fz * g * e for p, g, e in zip(probs, gains, qbers))
    return DecoyCounts(intensities, probs, n_X, m_X, n_Z, m_Z)


# ── required block size per distance ─────────────────────────────────────────

@dataclass(frozen=True)
class RequiredN:
    """Smallest block size reaching ``ell_min`` at one distance, or feasibility = False."""

    length_km: float
    feasible: bool          # a positive key exists at any N (asymptotic length > ell_min)
    n_pulses: int | None    # smallest N with ell >= ell_min, or None if infeasible
    ell_at_n: int | None    # the composable length at that N (>= ell_min), or None


def _ell_at(params, n_pulses, intensities, probs, q_x, eps_sec, eps_cor, f_ec) -> int:
    counts = expected_counts(params, n_pulses, intensities, probs, q_x)
    return secure_key_length(counts, eps_sec, eps_cor, f_ec).ell


def required_N(params: ChannelParams, distances, intensities, probs,
               eps_sec: float = 1e-10, eps_cor: float = 1e-15, ell_min: int = 256,
               q_x: float = 0.5, f_ec: float = F_EC_DEFAULT,
               n_cap: float = 1e14) -> list[RequiredN]:
    """
    For each distance, the smallest N whose composable key reaches ``ell_min`` bits.

    The honest expected gains/QBERs at that distance are fed as the observed counts and N is
    found by doubling to a bracket and bisecting. ``feasible`` is False when even the asymptotic
    length (N -> infinity) stays below ``ell_min`` (no positive key at any size); then n_pulses is
    None. ``n_cap`` bounds the search so an all-but-infeasible distance returns promptly.
    """
    results: list[RequiredN] = []
    for length in distances:
        at = params.at_length(float(length))
        # Asymptotic length per pulse decides feasibility without a size search: ell grows ~ N.
        asym = asymptotic_key_length(expected_counts(at, 1e12, intensities, probs, q_x), f_ec)
        if asym.ell < ell_min:
            results.append(RequiredN(float(length), False, None, None))
            continue
        hi = 1 << 12
        while _ell_at(at, hi, intensities, probs, q_x, eps_sec, eps_cor, f_ec) < ell_min:
            hi *= 2
            if hi > n_cap:
                results.append(RequiredN(float(length), False, None, None))
                break
        else:
            lo = hi // 2
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if _ell_at(at, mid, intensities, probs, q_x, eps_sec, eps_cor, f_ec) >= ell_min:
                    hi = mid
                else:
                    lo = mid
            results.append(RequiredN(float(length), True, hi,
                                     _ell_at(at, hi, intensities, probs, q_x, eps_sec, eps_cor, f_ec)))
    return results
