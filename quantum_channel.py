"""
Quantum Channel Simulation for BB84 QKD.

Simulates:
  1. Qubit preparation (encoding random bits in random bases)
  2. Depolarizing noise (random bit flips modeling fiber-optic loss)
  3. Eavesdropper interception (intercept-resend attack)
  4. Qubit measurement in a chosen basis

Bases:
  '+' (rectilinear) — computational basis |0⟩, |1⟩
  'x' (diagonal)    — Hadamard basis |+⟩, |−⟩

The No-Cloning Theorem guarantees that Eve cannot perfectly copy
an unknown quantum state; her measurement collapses the superposition,
introducing detectable errors (~25% QBER).
"""

import random
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from qiskit.qasm2 import dumps

from config import NOISE_PROBABILITY

# Shared simulator backend
_backend = Aer.get_backend("qasm_simulator")


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
# Depolarizing Noise Channel
# ─────────────────────────────────────────────

def apply_depolarizing_noise(qasm_str: str, p: float = NOISE_PROBABILITY) -> str:
    """
    Simulate a depolarizing channel by randomly applying a bit-flip (X gate)
    with probability `p`.

    In a real fiber-optic channel, environmental noise causes random errors.
    The depolarizing channel is the standard model:
        ρ → (1−p)ρ + p/3 (XρX + YρY + ZρZ)

    For simplicity, we model the dominant error (bit-flip):
        With probability p, apply X gate.
    """
    if random.random() < p:
        qc = QuantumCircuit.from_qasm_str(qasm_str)
        qc.x(0)  # Bit-flip error
        return dumps(qc)
    return qasm_str


def apply_channel_noise(qasm_strings: list[str], p: float = NOISE_PROBABILITY) -> list[str]:
    return [apply_depolarizing_noise(q, p) for q in qasm_strings]


# ─────────────────────────────────────────────
# Eavesdropper Interception (Eve's Attack)
# ─────────────────────────────────────────────

def eve_intercept_resend(qasm_strings: list[str]) -> tuple[list[str], list[int], list[str]]:
    """
    Simulate Eve's intercept-resend attack.

    Eve's Strategy:
      1. Choose a random measurement basis for each qubit
      2. Measure the qubit (collapsing its state — Measurement Disturbance)
      3. Re-prepare a new qubit based on her measurement result

    Why This Causes Errors:
      - If Eve's basis matches Alice's, she gets the correct bit and
        re-prepares the correct state → no error introduced.
      - If Eve's basis differs (50% chance), her measurement gives a
        random result, and she re-prepares in the wrong state → 50%
        chance of error when Bob measures in Alice's basis.
      - Overall: ~25% QBER introduced (0.5 × 0.5 = 0.25)

    The No-Cloning Theorem prevents Eve from copying the qubit first;
    she MUST measure it, destroying the original state.

    Returns:
        (modified_qasm_strings, eve_bits, eve_bases)
    """
    from bb84_protocol import generate_random_bases
    eve_bases = generate_random_bases(len(qasm_strings))
    eve_bits = []
    new_qasm = []

    for qasm_str, eve_basis in zip(qasm_strings, eve_bases):
        # Eve measures
        measured_bit = measure_qubit(qasm_str, eve_basis)
        eve_bits.append(measured_bit)

        # Eve re-prepares based on her measurement
        new_qasm.append(prepare_qubit(measured_bit, eve_basis))

    return new_qasm, eve_bits, eve_bases


# ─────────────────────────────────────────────
# Qubit Measurement (Bob's side)
# ─────────────────────────────────────────────

def measure_qubit(qasm_str: str, basis: str) -> int:
    """
    Measure a single qubit in the given basis.

    Quantum Measurement Disturbance:
      - Measuring in the preparation basis → deterministic result
      - Measuring in the conjugate basis → completely random (50/50)

    This is why BB84 works: only matching-basis measurements yield
    correlated bits between Alice and Bob.
    """
    qc_orig = QuantumCircuit.from_qasm_str(qasm_str)

    # Build a fresh circuit with exactly 1 qubit and 1 classical bit
    qc = QuantumCircuit(1, 1)
    qc.compose(qc_orig, inplace=True)

    if basis == "x":
        qc.h(0)  # Rotate back to computational basis before measurement

    qc.measure(0, 0)

    compiled = transpile(qc, _backend)
    result = _backend.run(compiled, shots=1).result()
    counts = result.get_counts()

    # Extract the measured bit
    bitstring = list(counts.keys())[0]
    return int(bitstring[-1])


def measure_qubits(qasm_strings: list[str], bases: list[str]) -> list[int]:
    """Measure a batch of qubits in their respective bases."""
    return [measure_qubit(q, b) for q, b in zip(qasm_strings, bases)]
