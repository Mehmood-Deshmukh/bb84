"""Finite-key secure length (core/finite_key.py), checked against the formula and the defaults."""

from __future__ import annotations

import math

import pytest

from qkd.core.config import EPS_COR, EPS_SEC, FINAL_KEY_BITS, NUM_QUBITS, QBER_SAMPLE_FRACTION
from qkd.core.finite_key import binary_entropy, deviation, secure_key_length


def _expected_sizes(num_qubits: int) -> tuple[int, int]:
    """(kept, sample) for a typical run: half the qubits sift, a fraction is sampled."""
    sifted = num_qubits // 2
    sample = max(1, int(sifted * QBER_SAMPLE_FRACTION))
    return sifted - sample, sample


def test_binary_entropy() -> None:
    assert binary_entropy(0.0) == 0.0
    assert binary_entropy(0.5) == 1.0
    assert binary_entropy(0.7) == 1.0
    assert binary_entropy(0.11) == pytest.approx(0.4999, abs=1e-3)


def test_deviation_matches_formula() -> None:
    n, k, eps = 3000, 600, 1e-10
    assert deviation(n, k, eps) == pytest.approx(math.sqrt((n + k) / (n * k) * (k + 1) / k * math.log(2 / eps)))
    assert math.isinf(deviation(0, 10, eps)) and math.isinf(deviation(10, 0, eps))


def test_secure_length_matches_formula() -> None:
    n, k, q = 3000, 600, 0.01
    mu = deviation(n, k, EPS_SEC)
    expected = n * (1 - binary_entropy(q + mu)) - math.log2(2 / EPS_COR) - math.log2(2 / (EPS_SEC**2 * EPS_COR))
    assert secure_key_length(n, k, q, EPS_SEC, EPS_COR) == math.floor(expected)


def test_old_default_of_128_qubits_has_no_secure_bits() -> None:
    assert secure_key_length(*_expected_sizes(128), 0.0, EPS_SEC, EPS_COR) == 0


def test_default_qubits_give_a_full_key_on_a_clean_channel() -> None:
    assert secure_key_length(*_expected_sizes(NUM_QUBITS), 0.0, EPS_SEC, EPS_COR) >= FINAL_KEY_BITS


def test_errors_reduce_the_secure_length() -> None:
    lengths = [secure_key_length(*_expected_sizes(NUM_QUBITS), q, EPS_SEC, EPS_COR) for q in (0.0, 0.01, 0.03, 0.25)]
    assert lengths == sorted(lengths, reverse=True)
    assert lengths[-1] == 0  # full intercept-resend leaves nothing


def test_never_negative() -> None:
    assert secure_key_length(10, 2, 0.4, EPS_SEC, EPS_COR) == 0
