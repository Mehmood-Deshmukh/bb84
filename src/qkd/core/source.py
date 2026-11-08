"""
Weak coherent source with decoy intensities for BB84 (Phase 2).

The single-photon source lives in channel_model.sample_clicks: every pulse is one photon,
and the fast "simulate only clicked pulses" shortcut draws the clicks directly. A decoy
source instead sends, per pulse, a mean photon number drawn from one of three intensities
(signal, decoy, vacuum), and the photon number of each pulse follows Poisson(mu_k). This
module does the equivalent sampling for the decoy source.

Model (Ma, Qi, Zhao, Lo, PRA 72, 012326, 2005; matches core/decoy.py):
  - intensity label k ~ probs
  - photon number n ~ Poisson(mu_k)
  - arrivals ~ Binomial(n, eta): photons that reach Bob's detector
  - a click if any photon arrived; otherwise a dark click with probability Y0
    (the "arriving photon takes precedence over a dark count" convention, as in
    channel_model.sample_clicks). Bob's misalignment error is applied at Bob, unchanged.

Only clicked pulses become qubits later, exactly as in the single-photon path. Unlike
channel_model.sample_clicks (which draws clicks without the photon numbers), this returns
the per-click intensity label and photon number n, because Phase 3's photon-number-splitting
Eve needs n, and the decoy reveal (wire step 2d) needs the labels.

Pure NumPy; imports only ChannelParams from channel_model, so no qiskit.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from qkd.core.channel_model import ChannelParams

# Fixed label order (index into intensities/probs): 0 signal, 1 decoy, 2 vacuum.
SIGNAL, DECOY, VACUUM = 0, 1, 2


@dataclass(frozen=True)
class DecoyClicks:
    """
    Which of `n_pulses` sent pulses clicked at Bob, with the decoy bookkeeping.

    index    clicked pulse numbers, sorted (int64).
    signal   True where a photon arrived (bit is measured), False for a dark-only click.
    label    intensity label (0/1/2) of each clicked pulse (int8), aligned with index.
    photons  photon number n of each clicked pulse (int64), aligned with index; Phase 3's
             PNS Eve needs this. (Pulses that did not click are not reported.)
    sent     number of pulses sent at each intensity (int64, length = len(intensities)),
             counted over all n_pulses, which Bob needs for the per-intensity gains.
    """

    n_pulses: int
    index: np.ndarray
    signal: np.ndarray
    label: np.ndarray
    photons: np.ndarray
    sent: np.ndarray

    def __len__(self) -> int:
        return len(self.index)


def sample_clicks_decoy(n_pulses: int, intensities, probs, params: ChannelParams,
                        rng: np.random.Generator) -> DecoyClicks:
    """
    Sample the clicked pulses for a decoy source over a block of n_pulses, vectorised.

    intensities/probs are the (signal, decoy, vacuum) mean photon numbers and their sending
    probabilities. Every pulse is handled in NumPy over all n_pulses; only the clicked ones
    are returned (they become qubits later). Exact in distribution, like sample_clicks.
    """
    intensities = np.asarray(intensities, dtype=float)
    probs = np.asarray(probs, dtype=float)
    if intensities.shape != probs.shape or intensities.ndim != 1:
        raise ValueError("intensities and probs must be 1-D arrays of the same length")
    if n_pulses < 0:
        raise ValueError("n_pulses must not be negative")
    eta, y0 = params.eta, params.dark_count_prob

    if n_pulses == 0:
        empty_i, empty_b = np.zeros(0, np.int64), np.zeros(0, bool)
        return DecoyClicks(0, empty_i, empty_b, np.zeros(0, np.int8), empty_i,
                           np.zeros(len(intensities), np.int64))

    labels = rng.choice(len(intensities), size=n_pulses, p=probs)   # intensity per pulse
    photons = rng.poisson(intensities[labels])                       # n ~ Poisson(mu_k)
    arrived = rng.binomial(photons, eta)                             # photons reaching Bob
    signal_click = arrived >= 1
    # A dark count gives a click only when no photon arrived (photon precedence).
    dark_click = (~signal_click) & (rng.random(n_pulses) < y0)
    click = signal_click | dark_click

    idx = np.nonzero(click)[0].astype(np.int64)
    sent = np.bincount(labels, minlength=len(intensities)).astype(np.int64)
    return DecoyClicks(
        n_pulses,
        idx,
        signal_click[idx],
        labels[idx].astype(np.int8),
        photons[idx].astype(np.int64),
        sent,
    )
