"""
Wire step 3c: Cascade reconciliation between the QBER step and the salt (see core/cascade.py).

  3c  Alice -> {"cascade_seed": hex}                       the seed for the shuffled orders
      Bob   -> {"cascade": [[pass, start, end], ...]}      parity questions (one round)
      Alice -> {"parities": [0/1, ...]}                    her answers, same order
      ... repeated until Bob sends {"cascade": []}

All messages go through the TranscriptChannel (tracked), so in signed modes any change
to them makes the finished signatures fail. Both sides count the parities Alice revealed
the same way; that count is charged in the finite-key bound.

Only run when the security policy says reconciliation is "cascade".
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from qkd.core.cascade import MAX_ROUNDS, PASSES, CascadeBob, alice_parities, first_block_size, shuffled_orders
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel

SEED_BYTES = 16


@dataclass(frozen=True)
class Reconciled:
    bits: list[int]  # Bob: corrected bits; Alice: her bits unchanged
    leaked_bits: int  # parities Alice revealed
    rounds: int
    errors_corrected: int  # Bob only; Alice reports 0 (she never sees the errors)


def _report(reporter: Reporter, r: Reconciled, elapsed: float, n: int, bob: bool) -> None:
    reporter.success(f"Cascade: {r.rounds} rounds, {r.leaked_bits} parity bits revealed"
                     + (f", {r.errors_corrected} errors corrected" if bob else ""))
    metrics = dict(reconciliation_rounds=r.rounds, leaked_bits=r.leaked_bits,
                   leaked_bits_conservative=2 * r.leaked_bits,  # counting Bob's parities too
                   reconciliation_ms=round(elapsed * 1000, 3))
    if bob:
        metrics["errors_corrected"] = r.errors_corrected
    reporter.metrics(**metrics)


def _queries(msg: object) -> list[tuple[int, int, int]]:
    if not isinstance(msg, dict) or not isinstance(msg.get("cascade"), list):
        raise ValueError("malformed cascade message")
    out = []
    for q in msg["cascade"]:
        if (not isinstance(q, list) or len(q) != 3
                or not all(isinstance(x, int) and not isinstance(x, bool) for x in q)):
            raise ValueError("malformed cascade query")
        out.append((q[0], q[1], q[2]))
    return out


def alice_reconcile(channel: TranscriptChannel, bits: list[int], reporter: Reporter) -> Reconciled:
    """Alice: send the seed, then answer parity questions until Bob sends none."""
    reporter.stage("reconciliation")
    reporter.info("Reconciling errors with Cascade...")
    t0 = time.perf_counter()
    seed = secrets.token_bytes(SEED_BYTES)
    orders = shuffled_orders(seed, len(bits), PASSES)
    channel.send_json({"cascade_seed": seed.hex()})
    leaked = rounds = 0
    while True:
        queries = _queries(channel.recv_json())
        if not queries:
            break
        rounds += 1
        if rounds > MAX_ROUNDS:
            raise ValueError("cascade: too many rounds")
        answers = alice_parities(bits, orders, queries)
        leaked += len(answers)
        channel.send_json({"parities": answers})
    result = Reconciled(bits, leaked, rounds, 0)
    _report(reporter, result, time.perf_counter() - t0, len(bits), bob=False)
    return result


def bob_reconcile(channel: TranscriptChannel, bits: list[int], qber: float, sample_size: int,
                  reporter: Reporter) -> Reconciled:
    """Bob: receive the seed, then ask parities round by round and correct his bits."""
    reporter.stage("reconciliation")
    reporter.info("Reconciling errors with Cascade...")
    t0 = time.perf_counter()
    msg = channel.recv_json()
    try:
        seed = bytes.fromhex(msg["cascade_seed"])
    except (TypeError, KeyError, ValueError):
        raise ValueError("malformed cascade seed") from None
    if len(seed) != SEED_BYTES:
        raise ValueError("malformed cascade seed")
    orders = shuffled_orders(seed, len(bits), PASSES)
    bob = CascadeBob(list(bits), first_block_size(qber, sample_size, len(bits)), orders)
    while True:
        queries = bob.next_queries()
        channel.send_json({"cascade": [list(q) for q in queries]})
        if not queries:
            break
        reply = channel.recv_json()
        if not isinstance(reply, dict) or not isinstance(reply.get("parities"), list):
            raise ValueError("malformed cascade answer")
        bob.receive(reply["parities"])
    result = Reconciled(bob.bits, bob.stats.leaked_bits, bob.stats.rounds, bob.stats.errors_corrected)
    _report(reporter, result, time.perf_counter() - t0, len(bits), bob=True)
    return result
