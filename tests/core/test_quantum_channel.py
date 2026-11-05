"""
Physics of the simulated quantum channel: preparation, measurement, and Eve.

These pin the behaviour of the batched Aer measurement in measure_qubits, so
that speeding up the simulation cannot silently change the statistics.
"""

from __future__ import annotations

from qkd.core.bb84_protocol import generate_random_bases, generate_random_bits
from qkd.core.quantum_channel import eve_intercept_resend, measure_qubit, measure_qubits, prepare_qubits

N = 4000


def test_empty_batch() -> None:
    assert measure_qubits([], []) == []


def test_single_qubit_in_matching_basis() -> None:
    for bit in (0, 1):
        for basis in ("+", "x"):
            assert measure_qubit(prepare_qubits([bit], [basis])[0], basis) == bit


def test_matching_bases_always_decode_and_conjugate_bases_are_random() -> None:
    bits = generate_random_bits(N)
    bases = generate_random_bases(N)
    bob_bases = generate_random_bases(N)
    measured = measure_qubits(prepare_qubits(bits, bases), bob_bases)

    same = [i for i in range(N) if bases[i] == bob_bases[i]]
    other = [i for i in range(N) if bases[i] != bob_bases[i]]
    assert all(measured[i] == bits[i] for i in same)
    # Wrong basis gives a fair coin: agreement near 50% (about 7 standard deviations of slack)
    agree = sum(measured[i] == bits[i] for i in other) / len(other)
    assert 0.40 < agree < 0.60


def test_full_intercept_resend_gives_about_25_percent_error() -> None:
    bits = generate_random_bits(N)
    bases = generate_random_bases(N)
    tampered, eve_bits, eve_bases = eve_intercept_resend(prepare_qubits(bits, bases))
    assert len(tampered) == len(eve_bits) == len(eve_bases) == N

    bob_bases = generate_random_bases(N)
    measured = measure_qubits(tampered, bob_bases)
    sifted = [i for i in range(N) if bases[i] == bob_bases[i]]
    qber = sum(measured[i] != bits[i] for i in sifted) / len(sifted)
    # Expected 0.25; the standard deviation is about 0.01 for ~2000 sifted bits
    assert 0.19 < qber < 0.31


def test_partial_intercept_attacks_about_the_fraction_and_disturbs_a_quarter_of_it() -> None:
    bits = generate_random_bits(N)
    bases = generate_random_bases(N)
    tampered, eve_bits, eve_bases = eve_intercept_resend(prepare_qubits(bits, bases), fraction=0.4)
    attacked = sum(b is not None for b in eve_bits)
    assert 0.34 < attacked / N < 0.46
    assert all((b is None) == (s is None) for b, s in zip(eve_bits, eve_bases))

    bob_bases = generate_random_bases(N)
    measured = measure_qubits(tampered, bob_bases)
    sifted = [i for i in range(N) if bases[i] == bob_bases[i]]
    qber = sum(measured[i] != bits[i] for i in sifted) / len(sifted)
    assert 0.06 < qber < 0.14  # expected 0.4 / 4 = 0.10


def test_zero_fraction_leaves_every_qubit_alone() -> None:
    qubits = prepare_qubits([0, 1, 1, 0], ["+", "x", "+", "x"])
    tampered, eve_bits, _ = eve_intercept_resend(qubits, fraction=0.0)
    assert tampered == qubits and eve_bits == [None] * 4


def test_fraction_out_of_range_is_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="fraction"):
        eve_intercept_resend([], fraction=1.5)
