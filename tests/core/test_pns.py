"""
Unit tests for the photon-number-splitting eavesdropper (core/quantum_channel.eve_pns).

These are numbers only: no sockets, no protocol. They check that the forwarding decision follows
the photon numbers, that Eve forwards each pulse's state unchanged (she introduces no error), and
that the default forwarding fractions match Bob's gain to the honest channel.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from qkd.core.channel_model import preset
from qkd.core.quantum_channel import eve_passthrough, eve_pns, pns_forward_fractions
from qkd.core.source import sample_photon_numbers

GYS_25 = preset("GYS", 25)


def _handover(n, intensities, probs, rng):
    """The pulses (with n >= 1) Alice would hand Eve, with placeholder QASM states."""
    labels, photons, _sent = sample_photon_numbers(n, intensities, probs, rng)
    index = [i for i in range(n) if photons[i] >= 1]
    qubits = [f"qasm-{i}" for i in index]
    return index, [int(labels[i]) for i in index], [int(photons[i]) for i in index], qubits


def test_pns_forwards_all_multi_blocks_single_when_pinned():
    rng = np.random.default_rng(1)
    index, labels, photons, qubits = _handover(20000, (0.48,), (1.0,), rng)
    plan = eve_pns(index, labels, photons, qubits, 20000, 1, GYS_25, (0.48,), (1.0,), rng,
                   forward_fraction=0.0, multi_fraction=1.0)

    n_multi = sum(1 for p in photons if p >= 2)
    n_single = sum(1 for p in photons if p == 1)
    # Every multi-photon pulse is split and forwarded; every single-photon pulse is blocked.
    assert plan.split[0] == n_multi
    assert plan.forwarded_single[0] == 0
    assert plan.blocked[0] == n_single
    assert len(plan.forward_index) == n_multi
    assert plan.stored_index == plan.forward_index  # every forwarded pulse is a stored multi-photon


def test_pns_introduces_no_error_on_forwarded_pulses():
    rng = np.random.default_rng(2)
    index, labels, photons, qubits = _handover(5000, (0.48,), (1.0,), rng)
    qubit_of = dict(zip(index, qubits))
    plan = eve_pns(index, labels, photons, qubits, 5000, 1, GYS_25, (0.48,), (1.0,), rng,
                   forward_fraction=0.0, multi_fraction=1.0)
    # Forwarded state is byte-identical to what Alice prepared: Eve splits, never re-prepares.
    for g, q in zip(plan.forward_index, plan.forward_qubits):
        assert q == qubit_of[g]
    assert sorted(plan.forward_index) == plan.forward_index  # strictly increasing for encode_pulses


def test_pns_split_counts_match_poisson_expectation():
    rng = np.random.default_rng(3)
    n = 200000
    mu = 0.48
    index, labels, photons, qubits = _handover(n, (mu,), (1.0,), rng)
    plan = eve_pns(index, labels, photons, qubits, n, 1, GYS_25, (mu,), (1.0,), rng,
                   forward_fraction=0.0, multi_fraction=1.0)
    expected_multi = n * (1 - math.exp(-mu) * (1 + mu))
    assert plan.split[0] == pytest.approx(expected_multi, rel=0.05)


def test_default_fractions_match_honest_gain():
    # The default policy tunes the forwarding so Bob's overall gain equals the honest gain.
    for mix in [((0.48,), (1.0,)), ((0.48, 0.1, 0.0), (0.7, 0.2, 0.1))]:
        intensities, probs = mix
        multi_frac, single_frac = pns_forward_fractions(GYS_25, intensities, probs, None, None)
        p_multi = sum(p * (1 - math.exp(-mu) * (1 + mu)) for mu, p in zip(intensities, probs))
        p_single = sum(p * mu * math.exp(-mu) for mu, p in zip(intensities, probs))
        honest = sum(p * (1 - (1 - GYS_25.dark_count_prob) * math.exp(-GYS_25.eta * mu))
                     for mu, p in zip(intensities, probs))
        delivered = multi_frac * p_multi + single_frac * p_single
        assert delivered == pytest.approx(honest, rel=1e-6)
        # At fibre distance the multi-photon supply exceeds the honest gain: throttle multi, no singles.
        assert 0.0 < multi_frac < 1.0
        assert single_frac == 0.0


def test_passthrough_reproduces_honest_gain():
    rng = np.random.default_rng(5)
    n = 300000
    index, labels, photons, qubits = _handover(n, (0.48,), (1.0,), rng)
    plan = eve_passthrough(index, photons, qubits, n, GYS_25, rng)
    honest = 1 - (1 - GYS_25.dark_count_prob) * math.exp(-GYS_25.eta * 0.48)
    assert len(plan.forward_index) / n == pytest.approx(honest, rel=0.05)
    assert plan.stored_index == []  # the control stores nothing
