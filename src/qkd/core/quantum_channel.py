"""
Quantum Channel Simulation for BB84 QKD.

Simulates:
  1. Qubit preparation (encoding random bits in random bases)
  2. Eavesdropper interception (intercept-resend attack)
  3. Qubit measurement in a chosen basis

Each qubit travels as a one-qubit QASM 2 circuit. The channel itself is
noiseless: nothing changes a qubit between Alice and Bob except Eve.

Bases:
  '+' (rectilinear) — computational basis |0⟩, |1⟩
  'x' (diagonal)    — Hadamard basis |+⟩, |−⟩

The No-Cloning Theorem guarantees that Eve cannot perfectly copy
an unknown quantum state; her measurement collapses the superposition,
introducing detectable errors (~25% QBER).
"""

from __future__ import annotations
import secrets
from typing import Optional

from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit.qasm2 import dumps

from qkd.core.bb84_protocol import generate_random_bases

# Shared simulator backend
_backend = Aer.get_backend("qasm_simulator")
# Eve picks which qubits to attack with the OS CSPRNG
_csprng = secrets.SystemRandom()


# ─────────────────────────────────────────────
# Qubit Preparation (Alice's side)
# ─────────────────────────────────────────────

def prepare_qubit(bit: int, basis: str) -> str:
    """
    Prepare a single qubit encoding `bit` in `basis`.

    Quantum Superposition:
      - Basis '+': |0⟩ or |1⟩ (computational)
      - Basis 'x': H|0⟩ = |+⟩ = (|0⟩+|1⟩)/√2
                    H|1⟩ = |−⟩ = (|0⟩−|1⟩)/√2

    Returns the QASM string representation of the circuit.
    """
    qc = QuantumCircuit(1)

    if bit == 1:
        qc.x(0)  # Flip to |1⟩

    if basis == "x":
        qc.h(0)  # Apply Hadamard for diagonal basis

    return dumps(qc)


def prepare_qubits(bits: list[int], bases: list[str]) -> list[str]:
    """Prepare a batch of qubits from bits and bases."""
    return [prepare_qubit(b, basis) for b, basis in zip(bits, bases)]


# ─────────────────────────────────────────────
# Eavesdropper Interception (Eve's Attack)
# ─────────────────────────────────────────────

def eve_intercept_resend(
    qasm_strings: list[str], fraction: float = 1.0
) -> tuple[list[str], list[Optional[int]], list[Optional[str]]]:
    """
    Simulate Eve's intercept-resend attack on a `fraction` of the qubits.

    Eve's Strategy:
      1. Pick which qubits to attack: each one independently with probability
         `fraction` (1.0 attacks every qubit)
      2. Measure each attacked qubit in a random basis (collapsing its state)
      3. Re-prepare a new qubit from her result; the others pass untouched

    Why This Causes Errors:
      - If Eve's basis matches Alice's, she gets the correct bit and
        re-prepares the correct state → no error introduced.
      - If Eve's basis differs (50% chance), her measurement gives a
        random result, and she re-prepares in the wrong state → 50%
        chance of error when Bob measures in Alice's basis.
      - Overall: about fraction / 4 of the sifted bits are wrong
        (25% QBER for a full attack).

    The No-Cloning Theorem prevents Eve from copying the qubit first;
    she MUST measure it, destroying the original state.

    Returns:
        (modified_qasm_strings, eve_bits, eve_bases), with None in eve_bits and
        eve_bases at positions Eve left alone.
    """
    if not 0.0 <= fraction <= 1.0:
        raise ValueError(f"fraction must be in [0, 1], got {fraction}")
    n = len(qasm_strings)
    attacked = [i for i in range(n) if fraction >= 1.0 or _csprng.random() < fraction]
    bases = generate_random_bases(len(attacked))
    measured = measure_qubits([qasm_strings[i] for i in attacked], bases)
    replaced = prepare_qubits(measured, bases)

    new_qasm = list(qasm_strings)
    eve_bits: list[Optional[int]] = [None] * n
    eve_bases: list[Optional[str]] = [None] * n
    for i, bit, basis, qasm in zip(attacked, measured, bases, replaced):
        new_qasm[i], eve_bits[i], eve_bases[i] = qasm, bit, basis
    return new_qasm, eve_bits, eve_bases


# ─────────────────────────────────────────────
# Qubit Measurement (Bob's side)
# ─────────────────────────────────────────────

def _measurement_circuit(qasm_str: str, basis: str) -> QuantumCircuit:
    """The received qubit followed by a measurement in `basis`."""
    qc = QuantumCircuit(1, 1)
    qc.compose(QuantumCircuit.from_qasm_str(qasm_str), inplace=True)
    if basis == "x":
        qc.h(0)  # Rotate back to computational basis before measurement
    qc.measure(0, 0)
    return qc


def measure_qubit(qasm_str: str, basis: str) -> int:
    """
    Measure a single qubit in the given basis.

    Quantum Measurement Disturbance:
      - Measuring in the preparation basis → deterministic result
      - Measuring in the conjugate basis → completely random (50/50)

    This is why BB84 works: only matching-basis measurements yield
    correlated bits between Alice and Bob.
    """
    return measure_qubits([qasm_str], [basis])[0]


def measure_qubits(qasm_strings: list[str], bases: list[str]) -> list[int]:
    """
    Measure a batch of qubits in their respective bases.

    Every qubit is still its own one-qubit circuit measured once, so the
    physics is unchanged; the circuits are just submitted to Aer as one job.
    They use only x, h, and measure, which Aer runs natively, so there is no
    transpile step. This is about 250 times faster than one job per qubit.
    """
    if not qasm_strings:
        return []
    circuits = [_measurement_circuit(q, b) for q, b in zip(qasm_strings, bases)]
    result = _backend.run(circuits, shots=1, memory=True).result()
    return [int(result.get_memory(i)[0]) for i in range(len(circuits))]
