"""
Streaming pre-loss PNS handoff (Phase 5b memory refactor). Alice streams the N pulses to Eve in
chunks and Eve accumulates only the forwarded/stored pulses, so the 50 km attack runs in bounded
memory. This checks the streamed path is deterministic for a fixed seed and reproduces the PNS
signature (the signal gain is pulled up so the single-photon yield bound collapses). The end-to-end
abort-at-the-decoy-gate behaviour is covered by tests/invariants/test_pns.py.
"""

from __future__ import annotations

import numpy as np

from qkd.core import decoy
from qkd.core.channel_model import preset
from qkd.core.quantum_channel import PnsAccumulator, pns_accumulate, pns_forward_fractions
from qkd.usecases.send_file import _preloss_chunks

LINK = preset("GYS", 25)
MIX_I, MIX_P = (0.5, 0.1, 0.0), (0.3, 0.5, 0.2)
N, CHUNK = 2_000_000, 250_000


def _stream(seed_gen: int, seed_eve: int, multi_fraction=1.0):
    """Run the chunked generation + Eve accumulation, returning (accumulator, per-intensity sent)."""
    mf, sf = pns_forward_fractions(LINK, MIX_I, MIX_P, None, multi_fraction)
    acc = PnsAccumulator(3)
    sent = np.zeros(3, dtype=np.int64)
    rng = np.random.default_rng(seed_eve)
    for start, labels, photons, bits, bases in _preloss_chunks(N, MIX_I, MIX_P, seed_gen, CHUNK):
        sent += np.bincount(labels, minlength=3).astype(np.int64)
        wp = np.nonzero(photons >= 1)[0]
        codes = (bits[wp] | (bases[wp] << 1)).tolist()        # analytic qubit codes
        pns_accumulate(acc, (wp + start).tolist(), labels[wp].tolist(),
                       photons[wp].tolist(), codes, mf, sf, rng)
    return acc, sent


def test_streaming_is_deterministic_for_a_fixed_seed() -> None:
    a, sa = _stream(123, 7)
    b, sb = _stream(123, 7)
    assert a.forward_index == b.forward_index
    assert a.forward_qubits == b.forward_qubits
    assert a.forward_label == b.forward_label
    assert a.stored_index == b.stored_index
    assert a.split == b.split and a.blocked == b.blocked
    assert sa.tolist() == sb.tolist()


def test_different_seed_gives_a_different_stream() -> None:
    a, _ = _stream(123, 7)
    c, _ = _stream(124, 7)
    assert a.forward_index != c.forward_index


def test_pns_signature_collapses_the_single_photon_yield() -> None:
    # With multi_fraction = 1 Eve forwards and stores every multi-photon pulse and no single-photon
    # pulse, so every forwarded pulse is one she knows, and the signal/decoy gains move apart from
    # the honest ratio -- the decoy single-photon yield bound Y1_L goes to 0.
    acc, sent = _stream(123, 7)
    assert sum(acc.forwarded_single) == 0          # no single-photon pulses forwarded
    assert sum(acc.split) > 0 and acc.stored_index == acc.forward_index  # every forward is stored
    forwarded = np.zeros(3, dtype=np.int64)
    for g, k in zip(acc.forward_index, acc.forward_label):
        forwarded[k] += 1
    gains = [forwarded[k] / sent[k] if sent[k] else 0.0 for k in range(3)]
    y1_l = decoy.y1_lower(MIX_I[0], MIX_I[1], gains[0], gains[1], gains[2])
    true_y1 = decoy.single_photon_yield(LINK)
    assert y1_l <= 0.1 * true_y1                    # the bound has collapsed toward 0
