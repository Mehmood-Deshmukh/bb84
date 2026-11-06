"""
Partial-fraction-f eavesdropper for the paper experiments, implemented WITHOUT editing
src/. src/ only has full intercept-resend (quantum_channel.eve_intercept_resend, every
qubit). The paper's detection model is a per-qubit Eve who attacks each qubit
independently with probability f.

The wrapper below keeps the real per-qubit attack path: for each qubit, with probability
f drawn from the OS CSPRNG, it runs the SAME measure-and-re-prepare code that
eve_intercept_resend uses (generate_random_bases -> measure_qubits -> prepare_qubits) on
that qubit; otherwise it forwards the qubit unchanged. The attacked qubits are measured
as one batched Aer job (the same single-job path as the real Eve), so the physics per
attacked qubit is identical.

It is injected into run_eavesdrop's flow by monkeypatching
qkd.usecases.eavesdrop_demo.eve_intercept_resend at runtime (install_partial_eve).
"""

from __future__ import annotations

import secrets
from contextlib import contextmanager
from typing import Iterator

from qkd.core.quantum_channel import (
    eve_intercept_resend as real_eve_intercept_resend,
    measure_qubits,
    prepare_qubits,
)
from qkd.core.bb84_protocol import generate_random_bases
from qkd.usecases import eavesdrop_demo

_csprng = secrets.SystemRandom()  # per-qubit attack coin, from the OS CSPRNG
_NOT_MEASURED = "?"  # basis sentinel for un-attacked qubits (never equals '+'/'x')


def partial_eve_intercept_resend(f: float):
    """
    Return a drop-in for eve_intercept_resend that attacks each qubit with probability f.

    Signature and return shape match the real function:
        (modified_qasm, eve_bits, eve_bases)
    For un-attacked positions eve_bases[i] is '?' (so downstream 'known bits' counting,
    which compares eve_bases[i] == bob_bases[i], correctly excludes them) and the qubit
    is forwarded unchanged.
    """

    def wrapper(qasm_strings: list[str]) -> tuple[list[str], list[int], list[str]]:
        n = len(qasm_strings)
        attacked = [i for i in range(n) if _csprng.random() < f]
        new_qasm = list(qasm_strings)
        eve_bases = [_NOT_MEASURED] * n
        eve_bits = [0] * n
        if attacked:
            sub_bases = generate_random_bases(len(attacked))          # same basis RNG
            sub_bits = measure_qubits([qasm_strings[i] for i in attacked], sub_bases)  # one job
            resent = prepare_qubits(sub_bits, sub_bases)              # same re-prepare
            for j, i in enumerate(attacked):
                new_qasm[i] = resent[j]
                eve_bases[i] = sub_bases[j]
                eve_bits[i] = sub_bits[j]
        return new_qasm, eve_bits, eve_bases

    return wrapper


@contextmanager
def install_partial_eve(f: float) -> Iterator[None]:
    """Monkeypatch run_eavesdrop's eve_intercept_resend to the partial-f wrapper."""
    orig = eavesdrop_demo.eve_intercept_resend
    eavesdrop_demo.eve_intercept_resend = partial_eve_intercept_resend(f)
    try:
        yield
    finally:
        eavesdrop_demo.eve_intercept_resend = orig


# ── sanity-check helper: channel-level sifted error rate ─────────────────────
def sifted_error_counts(eve_fn, n: int) -> tuple[int, int]:
    """
    Run one Alice->Eve->Bob round at the channel level with `eve_fn` and return
    (sifted_errors, sifted_count): errors on positions where Alice's and Bob's bases match.

    Uses the real src functions only; this is the quantity the detection model is about.
    """
    from qkd.core.bb84_protocol import generate_random_bits

    a_bits = generate_random_bits(n)
    a_bases = generate_random_bases(n)
    qubits = prepare_qubits(a_bits, a_bases)
    mod_qasm, _, _ = eve_fn(qubits)
    b_bases = generate_random_bases(n)
    b_bits = measure_qubits(mod_qasm, b_bases)
    matching = [i for i in range(n) if a_bases[i] == b_bases[i]]
    errors = sum(1 for i in matching if a_bits[i] != b_bits[i])
    return errors, len(matching)
