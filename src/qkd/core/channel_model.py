"""
Lossy, noisy channel and threshold detector for BB84 with a single-photon source.

Model (Ma, Qi, Zhao, Lo, Phys. Rev. A 72, 012326, 2005, Eq. 5 to 9; see
literature/2005_Ma-Qi-Zhao-Lo_practical-decoy-state_PRA72-012326.pdf):

    t_AB = 10^(-alpha * L / 10)          fibre transmittance, alpha in dB/km
    eta  = t_AB * eta_Bob                overall transmission and detection efficiency
    Y1   = eta + (1 - eta) * Y0          probability a sent pulse gives a click
    e1   = (e_d * eta + e0 * (1 - eta) * Y0) / Y1,  e0 = 1/2

Y0 is the background (dark count) probability per pulse and e_d the misalignment error:
the chance that an arriving photon hits the wrong detector. A click from a dark count
alone carries a uniformly random bit. Ma et al. write Y1 ~ Y0 + eta and
e1 ~ (e0 Y0 + e_d eta) / Y1, the first-order versions of the exact forms above, which this
module uses because it samples pulses one by one.

Assumptions (state them in the paper): an ideal single-photon source (no multi-photon
pulses, so no photon-number-splitting attack; decoy states lift this later), a threshold
detector, and an arriving photon taking precedence over a simultaneous dark count.

Simulation shortcut: `sample_clicks` draws which of N pulses click without touching the
others, because lost pulses never reach Bob and Alice's bits for them are discarded. Only
clicked pulses need to be simulated as qubits, which makes N = 10^7 at long distance
cheap. This is exact in distribution, not an approximation.

Pure Python and numpy; imports nothing from qiskit.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace

import numpy as np

E0 = 0.5  # error rate of a click from background alone


@dataclass(frozen=True)
class ChannelParams:
    """Physical channel and detector parameters. The defaults are a perfect channel."""

    length_km: float = 0.0
    loss_db_per_km: float = 0.0  # alpha
    detector_efficiency: float = 1.0  # eta_Bob: Bob's optics and detector efficiency
    dark_count_prob: float = 0.0  # Y0, per pulse
    misalignment: float = 0.0  # e_d

    def __post_init__(self) -> None:
        for name in ("detector_efficiency", "dark_count_prob", "misalignment"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1], got {value}")
        if self.length_km < 0 or self.loss_db_per_km < 0:
            raise ValueError("length_km and loss_db_per_km must not be negative")
        if self.misalignment > 0.5:
            raise ValueError("misalignment above 0.5 means the detectors are swapped")

    @property
    def transmittance(self) -> float:
        """t_AB = 10^(-alpha L / 10)."""
        return 10 ** (-self.loss_db_per_km * self.length_km / 10)

    @property
    def eta(self) -> float:
        """Overall efficiency: fibre transmittance times Bob's efficiency."""
        return self.transmittance * self.detector_efficiency

    @property
    def click_prob(self) -> float:
        """Y1: probability that a sent pulse produces a click."""
        return self.eta + (1 - self.eta) * self.dark_count_prob

    @property
    def error_rate(self) -> float:
        """e1: expected error rate among clicks (before any eavesdropper)."""
        y1 = self.click_prob
        if y1 == 0:
            return 0.0
        return (self.misalignment * self.eta + E0 * (1 - self.eta) * self.dark_count_prob) / y1

    @property
    def is_ideal(self) -> bool:
        return self.eta == 1.0 and self.dark_count_prob == 0.0 and self.misalignment == 0.0

    def at_length(self, length_km: float) -> "ChannelParams":
        return replace(self, length_km=length_km)


# Parameter sets from Ma et al. Table I (two fibre experiments), plus the perfect channel.
PRESETS: dict[str, ChannelParams] = {
    "ideal": ChannelParams(),
    "GYS": ChannelParams(loss_db_per_km=0.21, detector_efficiency=0.045, dark_count_prob=1.7e-6,
                         misalignment=0.033),
    "KTH": ChannelParams(loss_db_per_km=0.2, detector_efficiency=0.143, dark_count_prob=4e-4,
                         misalignment=0.01),
}


def preset(name: str, length_km: float = 0.0) -> ChannelParams:
    """A named parameter set at the given fibre length."""
    try:
        return PRESETS[name].at_length(length_km)
    except KeyError:
        raise ValueError(f"Unknown channel preset {name!r}. Known: {', '.join(PRESETS)}") from None


@dataclass(frozen=True)
class Clicks:
    """
    Which of `n_pulses` sent pulses produced a click at Bob.

    `index` holds the pulse numbers in increasing order; `signal[i]` is True when the photon
    of pulse index[i] arrived (its bit is measured), False when the click came from
    background alone (its bit is random).
    """

    n_pulses: int
    index: np.ndarray  # int64, sorted
    signal: np.ndarray  # bool, same length

    def __len__(self) -> int:
        return len(self.index)


def sample_clicks(n_pulses: int, params: ChannelParams, rng: np.random.Generator) -> Clicks:
    """
    Draw which pulses click, without simulating the others.

    Each pulse's photon arrives with probability eta. Each pulse whose photon did not arrive
    gives a background click with probability Y0. Counts are binomial draws and positions
    are drawn without replacement, so the cost is proportional to the clicks, not to N.
    """
    if n_pulses < 0:
        raise ValueError("n_pulses must not be negative")
    eta = params.eta
    n_signal = int(rng.binomial(n_pulses, eta)) if n_pulses else 0
    signal_idx = _choose(n_pulses, n_signal, rng, exclude=None)
    n_dark = int(rng.binomial(n_pulses - n_signal, params.dark_count_prob)) if n_pulses - n_signal else 0
    dark_idx = _choose(n_pulses, n_dark, rng, exclude=signal_idx)

    index = np.concatenate([signal_idx, dark_idx])
    signal = np.concatenate([np.ones(len(signal_idx), bool), np.zeros(len(dark_idx), bool)])
    order = np.argsort(index, kind="stable")
    return Clicks(n_pulses, index[order], signal[order])


def _choose(n: int, k: int, rng: np.random.Generator, exclude: np.ndarray | None) -> np.ndarray:
    """k distinct positions in range(n), avoiding `exclude`, as a sorted int64 array."""
    if k == 0:
        return np.zeros(0, np.int64)
    if exclude is None or len(exclude) == 0:
        return np.sort(rng.choice(n, size=k, replace=False)).astype(np.int64)
    # The excluded set is small compared with n at realistic loss; draw extra and filter
    taken = set(exclude.tolist())
    chosen: set[int] = set()
    while len(chosen) < k:
        for x in rng.choice(n, size=2 * (k - len(chosen)) + 8, replace=False).tolist():
            if x not in taken and x not in chosen:
                chosen.add(x)
                if len(chosen) == k:
                    break
    return np.sort(np.fromiter(chosen, np.int64, len(chosen)))


def misalignment_flips(n: int, params: ChannelParams, rng: np.random.Generator) -> np.ndarray:
    """For n measured photons, which results the misalignment error flips (bool array)."""
    return rng.random(n) < params.misalignment


def expected_secure_rate(params: ChannelParams, f_ec: float = 1.16) -> float:
    """
    Asymptotic secure bits per sent pulse for an ideal single-photon source (sifting
    factor 1/2 included): R = 1/2 * Y1 * [1 - h(e1) - f_ec * h(e1)], floored at 0.

    f_ec is the error correction inefficiency (1.16 is a typical value for practical
    codes; Ma et al. use f(e) between 1.16 and 1.22). This is the reference curve for the
    key rate vs distance experiment (N1); finite-size effects lower the measured rate.
    """
    e = params.error_rate
    h = 0.0 if e <= 0 or e >= 1 else -e * math.log2(e) - (1 - e) * math.log2(1 - e)
    return max(0.0, 0.5 * params.click_prob * (1 - h - f_ec * h))


# ── wire format of the qubit message (step 1) ───────────────────────────────

def encode_pulses(n_pulses: int, index: list[int] | None, qubits: list[str | None]) -> dict:
    """
    The step-1 message: {"n": pulses sent, "index": pulse numbers or None, "qubits": [...]}.

    One entry per pulse that clicked at Bob: a QASM string when its photon arrived, None
    when the click came from background alone. `index` is None when every pulse clicked
    in order (the ideal channel), which keeps that message the same size as before.
    """
    if index is not None and len(index) != len(qubits):
        raise ValueError("index and qubits must have the same length")
    full = index is None or (len(index) == n_pulses and all(i == k for k, i in enumerate(index)))
    return {"n": n_pulses, "index": None if full else list(index), "qubits": list(qubits)}


def decode_pulses(msg: object) -> tuple[int, list[int], list[str | None]]:
    """
    Parse and check a step-1 message. Returns (pulses sent, pulse numbers, qubits).

    Raises ValueError if it is malformed: wrong types, index not strictly increasing or
    out of range, or index and qubits of different lengths.
    """
    if not isinstance(msg, dict):
        raise ValueError("qubit message must be a JSON object")
    n, index, qubits = msg.get("n"), msg.get("index"), msg.get("qubits")
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("qubit message: n must be a non-negative integer")
    # A qubit entry is a QASM string (aer backend), an integer code 0-3 (analytic backend), or
    # null for a background-only click. bools are JSON ints but never valid codes.
    def _ok(q: object) -> bool:
        return q is None or isinstance(q, str) or (isinstance(q, int) and not isinstance(q, bool) and 0 <= q <= 3)
    if not isinstance(qubits, list) or not all(_ok(q) for q in qubits):
        raise ValueError("qubit message: qubits must be a list of QASM strings, integer codes 0-3, or nulls")
    if len(qubits) > n:
        raise ValueError("qubit message: more qubits than pulses")
    if index is None:
        if len(qubits) != n:
            raise ValueError("qubit message: without an index, every pulse must be present")
        return n, list(range(n)), qubits
    if (not isinstance(index, list) or len(index) != len(qubits)
            or not all(isinstance(i, int) and not isinstance(i, bool) for i in index)):
        raise ValueError("qubit message: index must be a list of integers matching qubits")
    if any(b <= a for a, b in zip(index, index[1:])) or (index and (index[0] < 0 or index[-1] >= n)):
        raise ValueError("qubit message: index must be strictly increasing and below n")
    return n, index, qubits
