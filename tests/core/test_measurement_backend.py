"""
Analytic measurement backend (core/quantum_channel.measure_codes / prepare_codes) and the
composable decoy gate wiring. The analytic path computes Bob's outcomes in NumPy with no Qiskit;
it must be exact for BB84 states measured in a BB84 basis, which is what honest and PNS runs use.
"""

from __future__ import annotations

import numpy as np
import pytest

from qkd.core.channel_model import decode_pulses, encode_pulses
from qkd.core.quantum_channel import (
    measure_codes,
    measure_qubits,
    measure_qubits_backend,
    prepare_codes,
    prepare_qubit,
    prepare_qubits,
)


def test_code_encoding_round_trips_bit_and_basis() -> None:
    # code = bit | (basis=='x')<<1; 0:|0> 1:|1> 2:|+> 3:|->.
    assert prepare_codes([0, 1, 0, 1], ["+", "+", "x", "x"]) == [0, 1, 2, 3]


@pytest.mark.parametrize("bit", [0, 1])
@pytest.mark.parametrize("basis", ["+", "x"])
def test_matching_basis_returns_alice_bit(bit: int, basis: str) -> None:
    rng = np.random.default_rng(0)
    (code,) = prepare_codes([bit], [basis])
    # Measured in the preparation basis, the outcome is deterministic and equals Alice's bit.
    out = measure_codes([code] * 200, [basis] * 200, rng)
    assert all(o == bit for o in out)


def test_mismatched_basis_is_uniform() -> None:
    rng = np.random.default_rng(1)
    code = prepare_codes([0], ["+"])[0]           # |0>, measured in x -> 50/50
    out = measure_codes([code] * 4000, ["x"] * 4000, rng)
    assert 0.45 < sum(out) / len(out) < 0.55


def test_analytic_agrees_with_aer_on_every_state() -> None:
    # For all four BB84 states and both measurement bases, the analytic outcome distribution
    # matches Aer: deterministic where bases match, and Aer's own result is reproduced bit for bit
    # in that case (mismatched bases are random on both and only checked for being 0/1).
    rng = np.random.default_rng(2)
    for bit in (0, 1):
        for prep in ("+", "x"):
            qasm = prepare_qubit(bit, prep)
            for meas in ("+", "x"):
                aer = measure_qubits([qasm] * 50, [meas] * 50)
                ana = measure_codes(prepare_codes([bit], [prep]) * 50, [meas] * 50, rng)
                if prep == meas:
                    assert set(aer) == {bit} and set(ana) == {bit}
                else:
                    assert set(aer) <= {0, 1} and set(ana) <= {0, 1}


def test_backend_dispatch_matches_direct_calls() -> None:
    rng = np.random.default_rng(3)
    bits, bases = [0, 1, 1, 0], ["+", "x", "+", "x"]
    # aer dispatch returns QASM; analytic dispatch returns codes.
    from qkd.core.quantum_channel import prepare_qubits_backend
    assert prepare_qubits_backend(bits, bases, "aer") == prepare_qubits(bits, bases)
    assert prepare_qubits_backend(bits, bases, "analytic") == prepare_codes(bits, bases)
    codes = prepare_codes(bits, bases)
    assert measure_qubits_backend(codes, bases, "analytic", rng) == bits  # matching bases


def test_integer_codes_survive_the_wire_schema() -> None:
    # encode/decode_pulses must accept integer codes (analytic) as well as QASM strings and nulls.
    msg = encode_pulses(3, [0, 1, 2], [2, None, 3])
    n, index, qubits = decode_pulses(msg)
    assert n == 3 and index == [0, 1, 2] and qubits == [2, None, 3]
    with pytest.raises(ValueError):
        decode_pulses({"n": 2, "index": None, "qubits": [0, 4]})   # 4 is out of the 0-3 code range
