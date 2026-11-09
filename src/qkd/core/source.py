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

# Pulses per chunk in sample_clicks_decoy: caps its working memory so N = 10^8 fits in RAM.
_CHUNK = 4_000_000


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


def sample_photon_numbers(n_pulses: int, intensities, probs,
                          rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Draw the intensity label and Poisson photon number of every one of n_pulses pulses,
    BEFORE any channel loss. Returns (labels, photons, sent).

    labels[i] in range(len(intensities)); photons[i] ~ Poisson(intensities[labels[i]]); sent is
    the per-intensity pulse count over all n_pulses. This is what a photon-number-splitting Eve
    sees when Alice hands her the pulses in front of the fibre (usecases/send_file eve-mode): the
    photon number stands in for Eve's quantum non-demolition measurement of the pulse. The honest
    path never calls this; it uses sample_clicks_decoy, which only materialises the clicked pulses.
    """
    intensities = np.asarray(intensities, dtype=float)
    probs = np.asarray(probs, dtype=float)
    if intensities.shape != probs.shape or intensities.ndim != 1:
        raise ValueError("intensities and probs must be 1-D arrays of the same length")
    if n_pulses < 0:
        raise ValueError("n_pulses must not be negative")
    if n_pulses == 0:
        return (np.zeros(0, np.int8), np.zeros(0, np.int64), np.zeros(len(intensities), np.int64))
    labels = rng.choice(len(intensities), size=n_pulses, p=probs)
    photons = rng.poisson(intensities[labels])
    sent = np.bincount(labels, minlength=len(intensities)).astype(np.int64)
    return labels.astype(np.int8), photons.astype(np.int64), sent


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
    eta, y0, k = params.eta, params.dark_count_prob, len(intensities)

    if n_pulses == 0:
        empty_i, empty_b = np.zeros(0, np.int64), np.zeros(0, bool)
        return DecoyClicks(0, empty_i, empty_b, np.zeros(0, np.int8), empty_i,
                           np.zeros(k, np.int64))

    # Process the N pulses in chunks and keep only the clicked ones, so the memory is proportional
    # to the clicks (plus one chunk), not to N. This makes N = 10^8 feasible on a normal machine;
    # it is exact in distribution (each pulse is independent), only the RNG draw order changes.
    sent = np.zeros(k, np.int64)
    idx_parts, sig_parts, lab_parts, pho_parts = [], [], [], []
    for start in range(0, n_pulses, _CHUNK):
        size = min(_CHUNK, n_pulses - start)
        labels = rng.choice(k, size=size, p=probs).astype(np.int8)      # intensity per pulse
        photons = rng.poisson(intensities[labels]).astype(np.int64)      # n ~ Poisson(mu_k)
        arrived = rng.binomial(photons, eta)                             # photons reaching Bob
        signal_click = arrived >= 1
        # A dark count gives a click only when no photon arrived (photon precedence).
        dark_click = (~signal_click) & (rng.random(size) < y0)
        click = signal_click | dark_click
        sent += np.bincount(labels, minlength=k).astype(np.int64)
        local = np.nonzero(click)[0]
        if local.size:
            idx_parts.append(local.astype(np.int64) + start)
            sig_parts.append(signal_click[local])
            lab_parts.append(labels[local])
            pho_parts.append(photons[local])

    empty_i, empty_b = np.zeros(0, np.int64), np.zeros(0, bool)
    idx = np.concatenate(idx_parts) if idx_parts else empty_i
    signal = np.concatenate(sig_parts) if sig_parts else empty_b
    label = np.concatenate(lab_parts) if lab_parts else np.zeros(0, np.int8)
    photons_out = np.concatenate(pho_parts) if pho_parts else empty_i
    return DecoyClicks(n_pulses, idx, signal, label, photons_out, sent)
