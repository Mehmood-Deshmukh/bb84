"""Sifting, QBER sampling, and key trimming helpers shared by Alice and Bob."""

from __future__ import annotations

import random

import pytest

from qkd.core.bb84_protocol import (
    choose_sample_indices,
    compute_qber,
    discard_indices,
    matching_basis_indices,
    privacy_amplification,
    qber_exceeds_threshold,
    toeplitz_seed_bytes,
)


def test_matching_basis_indices() -> None:
    assert matching_basis_indices(["+", "x", "x", "+"], ["+", "+", "x", "x"]) == [0, 2]


@pytest.mark.parametrize("n", [0, 1, 6, 7, 60, 1000])
def test_sample_indices_sorted_unique_in_range(n: int) -> None:
    idx = choose_sample_indices(n, 0.15)
    assert idx == sorted(set(idx))
    assert all(0 <= i < n for i in idx)
    assert len(idx) == min(n, max(1, int(n * 0.15)))


def test_sampling_and_salt_ignore_the_random_module_seed() -> None:
    """
    Sample positions and the salt must come from the OS CSPRNG. If they used the
    random module, reseeding it would reproduce them.
    """
    runs = []
    for _ in range(2):
        random.seed(1234)
        runs.append((choose_sample_indices(1000, 0.15), privacy_amplification([0, 1] * 64)[0]))
    assert runs[0][0] != runs[1][0]
    assert runs[0][1] != runs[1][1]
    assert len(runs[0][1]) == toeplitz_seed_bytes(128, 256)


def test_compute_qber() -> None:
    assert compute_qber([0, 1, 1, 0], [0, 1, 0, 1]) == 0.5
    assert compute_qber([], []) == 0.0


def test_discard_indices_keeps_order() -> None:
    assert discard_indices([10, 11, 12, 13, 14], [1, 3]) == [10, 12, 14]


@pytest.mark.parametrize(("qber", "aborts"), [(0.0, False), (0.1099, False), (0.11, True), (0.25, True), (1.0, True)])
def test_threshold_is_inclusive(qber: float, aborts: bool) -> None:
    assert qber_exceeds_threshold(qber, 0.11) is aborts
