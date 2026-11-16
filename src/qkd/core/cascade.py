"""
Cascade information reconciliation (Brassard and Salvail, EUROCRYPT 1993), the original
parameters as analysed by Martinez-Mateo et al., QIC 2015:

- 4 passes; block size k1 = ceil(0.73 / Q) in pass 1, doubled each pass (capped at n).
- Pass 1 uses the key as is; later passes use a shuffled order, the same on both sides.
- In each block whose parities differ, a binary search finds one error, which Bob flips.
  Flipping a bit changes the parity of the block that holds it in every other pass, so
  blocks in earlier passes may become odd again and are searched too (the "cascade").

Roles: Bob corrects his bits towards Alice's. Bob asks for the parity of ranges of Alice's
key (one range = (pass, start, end) in that pass's order); Alice only answers. Each
parity Alice reveals is one bit of information about her key and is counted in
`leaked_bits`, which the finite-key bound charges. A right-half parity that follows from
the block's and the left half's is derived, not asked, so it costs nothing.

Rounds are batched: in each round every active search asks one question, so the number
of messages follows the search depth, not the number of errors.

This module is pure Python with no network or qiskit: `CascadeBob` is a state machine
fed by `alice_parities`; `reconcile_locally` runs both sides in one process (tests and
offline experiments). The wire protocol drives the same two pieces over a socket.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Optional

PASSES = 4
FIRST_BLOCK_FACTOR = 0.73  # k1 = ceil(0.73 / Q), Martinez-Mateo et al. Table 1, "original"
MAX_ROUNDS = 1000  # honest runs need about 40 rounds; a peer that never finishes is cut off

Query = tuple[int, int, int]  # (pass, start, end) in that pass's order, end exclusive


class CascadeError(ValueError):
    """
    Alice's answers are inconsistent, so reconciliation cannot finish.

    In honest Cascade every flip corrects a real error, so no bit is ever flipped twice.
    A second flip of the same bit means some parity Bob was given is wrong (for example
    changed in transit); without this check Bob could chase it back and forth forever.
    """


def first_block_size(qber: float, sample_size: int, n: int) -> int:
    """
    k1 = ceil(0.73 / Q), between 1 and n.

    With no error in the sample, Q = 0 would give an infinite block; use 1 / sample_size
    instead, the rate if the next sampled bit had been wrong.
    """
    q = qber if qber > 0 else 1 / max(1, sample_size)
    return max(1, min(n, math.ceil(FIRST_BLOCK_FACTOR / q)))


def shuffled_orders(seed: bytes, n: int, passes: int = PASSES) -> list[list[int]]:
    """
    One order of range(n) per pass: identity for pass 0, then deterministic shuffles.

    Fisher-Yates driven by SHA-256(seed || pass || counter), so both peers derive the same
    orders from the seed regardless of library versions.
    """
    orders = [list(range(n))]
    for p in range(1, passes):
        order = list(range(n))
        stream = _HashStream(seed + p.to_bytes(4, "big"))
        for i in range(n - 1, 0, -1):
            j = stream.below(i + 1)
            order[i], order[j] = order[j], order[i]
        orders.append(order)
    return orders


class _HashStream:
    """Uniform integers from SHA-256 in counter mode (rejection sampling, no modulo bias)."""

    def __init__(self, key: bytes) -> None:
        self.key, self.counter, self.pool = key, 0, b""

    def _bytes(self, k: int) -> bytes:
        while len(self.pool) < k:
            self.pool += hashlib.sha256(self.key + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        out, self.pool = self.pool[:k], self.pool[k:]
        return out

    def below(self, bound: int) -> int:
        nbytes = max(1, (bound.bit_length() + 7) // 8)
        limit = (256 ** nbytes) // bound * bound
        while True:
            x = int.from_bytes(self._bytes(nbytes), "big")
            if x < limit:
                return x % bound


def alice_parities(bits: list[int], orders: list[list[int]], queries: list[Query]) -> list[int]:
    """Alice's answer: the parity of her bits over each queried range."""
    out = []
    for p, start, end in queries:
        if not (0 <= p < len(orders) and 0 <= start < end <= len(bits)):
            raise ValueError(f"cascade query out of range: {(p, start, end)}")
        order = orders[p]
        out.append(sum(bits[order[i]] for i in range(start, end)) & 1)
    return out


@dataclass
class CascadeStats:
    rounds: int = 0
    leaked_bits: int = 0  # parities Alice revealed
    errors_corrected: int = 0


@dataclass
class _Search:
    """A binary search for one error in a range whose parities differ."""

    p: int
    start: int
    end: int
    asked: Optional[Query] = None  # the left-half query awaiting an answer


@dataclass
class CascadeBob:
    """
    Bob's side. Loop: `queries = next_queries()`; if empty, done; else send them, get
    Alice's parities, call `receive(parities)`. `bits` ends up corrected.
    """

    bits: list[int]
    k1: int
    orders: list[list[int]]
    stats: CascadeStats = field(default_factory=CascadeStats)

    def __post_init__(self) -> None:
        self.n = len(self.bits)
        self.passes = len(self.orders)
        self.block = [min(self.n, self.k1 * 2 ** p) if self.n else 1 for p in range(self.passes)]
        # position of each original index within each pass's order
        self.where = [[0] * self.n for _ in range(self.passes)]
        for p, order in enumerate(self.orders):
            for pos, idx in enumerate(order):
                self.where[p][idx] = pos
        self.alice: dict[Query, int] = {}  # Alice's parities known so far (asked or derived)
        self.searches: list[_Search] = []
        self.pass_ = -1  # last pass whose top-level blocks were asked
        self.pending: list[Query] = []
        self.flipped: set[int] = set()
        self.awaiting_blocks = False  # the pending queries are a new pass's block parities

    # ── helpers ──
    def _bob_parity(self, p: int, start: int, end: int) -> int:
        order = self.orders[p]
        return sum(self.bits[order[i]] for i in range(start, end)) & 1

    def _odd(self, p: int, start: int, end: int) -> bool:
        return self.alice[(p, start, end)] != self._bob_parity(p, start, end)

    def _blocks(self, p: int) -> list[Query]:
        k = self.block[p]
        return [(p, s, min(s + k, self.n)) for s in range(0, self.n, k)]

    def _block_of(self, p: int, idx: int) -> Query:
        k = self.block[p]
        s = (self.where[p][idx] // k) * k
        return (p, s, min(s + k, self.n))

    def _flip(self, idx: int, origin_pass: int) -> None:
        if idx in self.flipped:
            raise CascadeError(f"bit {idx} would be flipped twice: the parities received are inconsistent")
        self.flipped.add(idx)
        self.bits[idx] ^= 1
        self.stats.errors_corrected += 1
        # The cascade: in every other started pass, the block holding idx changed parity
        active = {(s.p, s.start, s.end) for s in self.searches}
        for q in range(self.pass_ + 1):
            if q == origin_pass:
                continue
            blk = self._block_of(q, idx)
            if blk in self.alice and blk not in active and self._odd(*blk):
                self.searches.append(_Search(*blk))

    # ── the protocol ──
    def next_queries(self) -> list[Query]:
        """The parities to ask next; an empty list means reconciliation is finished."""
        if self.pending:
            raise RuntimeError("answer the previous queries first")
        if self.stats.rounds >= MAX_ROUNDS:
            raise CascadeError(f"cascade did not finish within {MAX_ROUNDS} rounds")
        while True:
            # Drop searches whose range is no longer odd (a flip elsewhere fixed it)
            self.searches = [s for s in self.searches if self._odd(s.p, s.start, s.end)]
            queries: list[Query] = []
            for s in self.searches:
                mid = (s.start + s.end) // 2
                left = (s.p, s.start, mid)
                if left not in self.alice and left not in queries:
                    queries.append(left)
                s.asked = left
            if queries:
                break
            if self.searches:
                self._advance_known()  # every needed parity is already known
                continue
            if self.pass_ + 1 >= self.passes or self.n == 0:
                return []
            self.pass_ += 1
            queries = [b for b in self._blocks(self.pass_) if b not in self.alice]
            if queries:
                self.awaiting_blocks = True
                break
            self._start_searches(self.pass_)
        self.pending = queries
        return list(queries)

    def receive(self, parities: list[int]) -> None:
        """Alice's answers to the last `next_queries()`, in the same order."""
        if len(parities) != len(self.pending) or any(b not in (0, 1) for b in parities):
            raise ValueError("cascade answer does not match the questions")
        self.stats.rounds += 1
        self.stats.leaked_bits += len(parities)
        for q, b in zip(self.pending, parities):
            self.alice[q] = b
        self.pending = []
        if self.awaiting_blocks:
            self.awaiting_blocks = False
            self._start_searches(self.pass_)
        self._advance_known()

    def _start_searches(self, p: int) -> None:
        for blk in self._blocks(p):
            if self._odd(*blk) and not any((s.p, s.start, s.end) == blk for s in self.searches):
                self.searches.append(_Search(*blk))

    def _advance_known(self) -> None:
        """Move every search whose left-half parity is known; flip bits at single-bit ranges."""
        progress = True
        while progress:
            progress = False
            for s in list(self.searches):
                if s not in self.searches or not self._odd(s.p, s.start, s.end):
                    continue
                if s.end - s.start == 1:
                    self.searches.remove(s)
                    self._flip(self.orders[s.p][s.start], s.p)
                    progress = True
                    continue
                mid = (s.start + s.end) // 2
                left, right = (s.p, s.start, mid), (s.p, mid, s.end)
                if left not in self.alice:
                    continue
                # Alice's right half follows from her block and left half: derived, not asked
                self.alice.setdefault(right, self.alice[(s.p, s.start, s.end)] ^ self.alice[left])
                s.start, s.end = (s.start, mid) if self._odd(*left) else (mid, s.end)
                s.asked = None
                progress = True


@dataclass(frozen=True)
class ReconcileResult:
    bob_bits: list[int]
    stats: CascadeStats
    k1: int


def reconcile_locally(alice_bits: list[int], bob_bits: list[int], qber: float, sample_size: int,
                      seed: bytes, passes: int = PASSES) -> ReconcileResult:
    """Run both sides in one process (tests and offline experiments)."""
    n = len(alice_bits)
    k1 = first_block_size(qber, sample_size, n)
    orders = shuffled_orders(seed, n, passes)
    bob = CascadeBob(list(bob_bits), k1, orders)
    while queries := bob.next_queries():
        bob.receive(alice_parities(alice_bits, orders, queries))
    return ReconcileResult(bob.bits, bob.stats, k1)
