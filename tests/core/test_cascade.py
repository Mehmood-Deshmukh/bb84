"""
Cascade reconciliation (core/cascade.py), run locally without a network.

Martinez-Mateo et al. (QIC 2015) report that original Cascade leaves residual errors in a
small fraction of frames and reveals somewhat more than the Shannon minimum n h(Q); these
tests check the same qualitative behaviour on frames of the size our protocol produces.
"""

from __future__ import annotations

import math
import random

import pytest

from qkd.core.cascade import (
    PASSES,
    CascadeBob,
    alice_parities,
    first_block_size,
    reconcile_locally,
    shuffled_orders,
)


def h(q: float) -> float:
    return 0.0 if q <= 0 or q >= 1 else -q * math.log2(q) - (1 - q) * math.log2(1 - q)


def noisy_pair(n: int, q: float, rng: random.Random) -> tuple[list[int], list[int], int]:
    alice = [rng.randrange(2) for _ in range(n)]
    bob = [b ^ (rng.random() < q) for b in alice]
    return alice, bob, sum(a != b for a, b in zip(alice, bob))


def test_first_block_size() -> None:
    assert first_block_size(0.033, 600, 4000) == math.ceil(0.73 / 0.033)
    assert first_block_size(0.0, 600, 4000) == math.ceil(0.73 * 600)  # zero errors: Q = 1/600
    assert first_block_size(0.0, 600, 100) == 100  # capped at n
    assert first_block_size(0.9, 600, 4000) == 1


def test_orders_are_deterministic_permutations_with_identity_first() -> None:
    a = shuffled_orders(b"seed", 500)
    assert a == shuffled_orders(b"seed", 500)
    assert a != shuffled_orders(b"other", 500)
    assert len(a) == PASSES and a[0] == list(range(500))
    assert all(sorted(o) == list(range(500)) for o in a)
    assert a[1] != a[0] and a[1] != a[2]


@pytest.mark.parametrize("q", [0.01, 0.03, 0.05, 0.1])
def test_cascade_corrects_typical_frames(q: float) -> None:
    rng = random.Random(int(q * 1000))
    trials, n = 20, 3500
    ok, efficiencies = 0, []
    for t in range(trials):
        alice, bob, errors = noisy_pair(n, q, rng)
        sample = 600
        res = reconcile_locally(alice, bob, qber=q, sample_size=sample, seed=bytes([t]) * 8)
        residual = sum(a != b for a, b in zip(alice, res.bob_bits))
        ok += residual == 0
        # Every flip fixes a real error, never creates one
        assert res.stats.errors_corrected == errors - residual
        efficiencies.append(res.stats.leaked_bits / (n * h(q)))
    # Original Cascade fails on a small share of frames; allow a few at these sizes
    assert ok >= trials - 2, f"only {ok}/{trials} frames fully corrected at Q={q}"
    f = sorted(efficiencies)[len(efficiencies) // 2]
    # Above the Shannon limit (f >= 1) and in the range reported for original Cascade
    assert 1.0 <= f <= 1.8, f"median efficiency {f:.2f} at Q={q}"


def test_identical_keys_cost_only_the_block_parities() -> None:
    rng = random.Random(1)
    alice = [rng.randrange(2) for _ in range(2000)]
    res = reconcile_locally(alice, list(alice), qber=0.0, sample_size=300, seed=b"s")
    assert res.bob_bits == alice and res.stats.errors_corrected == 0
    k1 = res.k1
    blocks = sum(math.ceil(2000 / min(2000, k1 * 2 ** p)) for p in range(PASSES))
    assert res.stats.leaked_bits <= blocks
    assert res.stats.rounds <= PASSES


def test_rounds_follow_search_depth_not_error_count() -> None:
    rng = random.Random(5)
    alice, bob, errors = noisy_pair(3500, 0.05, rng)
    res = reconcile_locally(alice, bob, qber=0.05, sample_size=600, seed=b"r")
    assert errors > 100
    assert res.stats.rounds < 100  # batched: far fewer rounds than errors


def test_alice_rejects_out_of_range_queries() -> None:
    orders = shuffled_orders(b"x", 10)
    assert alice_parities([1] * 10, orders, [(0, 0, 3), (1, 2, 10)]) == [1, 0]
    for bad in [(4, 0, 1), (0, 5, 5), (0, -1, 2), (0, 0, 11)]:
        with pytest.raises(ValueError):
            alice_parities([1] * 10, orders, [bad])


def test_bob_rejects_answers_that_do_not_match_the_questions() -> None:
    bob = CascadeBob([0, 1, 1, 0], k1=2, orders=shuffled_orders(b"y", 4))
    queries = bob.next_queries()
    with pytest.raises(ValueError):
        bob.receive([0] * (len(queries) + 1))
    with pytest.raises(ValueError):
        bob.receive([2] * len(queries))


def test_a_changed_parity_never_makes_cascade_run_away() -> None:
    """
    One parity changed in transit: Cascade must either stop with CascadeError or finish
    within MAX_ROUNDS. It may finish with keys that differ; the protocol then catches that
    at the finished signature (tests/invariants/test_reconciliation.py).
    """
    from qkd.core.cascade import MAX_ROUNDS, CascadeError

    outcomes = {"cascade_error": 0, "finished_equal": 0, "finished_different": 0}
    for seed in range(30):
        rng = random.Random(seed)
        alice, bob_bits, _ = noisy_pair(2000, 0.05, rng)
        orders = shuffled_orders(bytes([seed]) * 4, 2000)
        bob = CascadeBob(list(bob_bits), first_block_size(0.05, 300, 2000), orders)
        tamper_round = rng.randrange(1, 6)
        try:
            while queries := bob.next_queries():
                answers = alice_parities(alice, orders, queries)
                if bob.stats.rounds + 1 == tamper_round:
                    answers[rng.randrange(len(answers))] ^= 1
                bob.receive(answers)
        except CascadeError:
            outcomes["cascade_error"] += 1
            continue
        assert bob.stats.rounds < MAX_ROUNDS
        outcomes["finished_equal" if bob.bits == alice else "finished_different"] += 1
    assert sum(outcomes.values()) == 30
    assert outcomes["cascade_error"] > 0  # the double-flip check does fire
