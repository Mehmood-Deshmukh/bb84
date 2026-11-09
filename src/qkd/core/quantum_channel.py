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
import math
import secrets
from dataclasses import dataclass
from typing import Optional

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit.qasm2 import dumps

from qkd.core.bb84_protocol import generate_random_bases
from qkd.core.channel_model import ChannelParams

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


# ── analytic backend (no Qiskit): qubits as integer codes bit | basis<<1 ─────
#
# A BB84 eigenstate is fully described by (bit, basis), so in the analytic measurement backend a
# prepared qubit is just the 2-bit code  code = bit | (basis == 'x') << 1  (0:|0>, 1:|1>, 2:|+>,
# 3:|->). These codes travel the wire in place of QASM strings; preparation and measurement are
# then pure NumPy. This is exact for BB84 states measured in a BB84 basis and when no per-qubit
# quantum attack has rotated the state (honest and PNS runs qualify: PNS splits by photon number
# and forwards the state untouched). The aer backend (default) is unaffected.

def prepare_codes(bits, bases) -> list[int]:
    """Prepare a batch of qubits as integer codes (analytic backend)."""
    return [int(b) | ((2 if basis == "x" else 0)) for b, basis in zip(bits, bases)]


def measure_codes(codes, bases, rng: np.random.Generator) -> list[int]:
    """
    Measure code-encoded qubits in ``bases`` directly in NumPy (analytic backend).

    Matching basis returns Alice's prepared bit exactly; a mismatched basis returns a uniformly
    random bit (which is sifted out downstream). Vectorised over all clicks; ``rng`` supplies the
    mismatched-basis outcomes. Equivalent in distribution to measuring the states with Aer.
    """
    codes = np.asarray(codes, dtype=np.int8)
    if codes.size == 0:
        return []
    alice_bit = codes & 1
    alice_x = (codes & 2) != 0
    bob_x = np.fromiter((b == "x" for b in bases), dtype=bool, count=len(bases))
    rand = rng.integers(0, 2, size=codes.size, dtype=np.int8)
    return np.where(alice_x == bob_x, alice_bit, rand).astype(np.int64).tolist()


def prepare_qubits_backend(bits, bases, measurement: str) -> list:
    """Prepare qubits as QASM strings (aer) or integer codes (analytic)."""
    return prepare_codes(bits, bases) if measurement == "analytic" else prepare_qubits(bits, bases)


def measure_qubits_backend(qubits, bases, measurement: str,
                           rng: Optional[np.random.Generator] = None) -> list[int]:
    """Measure a batch with the chosen backend (aer: Qiskit; analytic: NumPy codes)."""
    if measurement == "analytic":
        return measure_codes(qubits, bases, rng if rng is not None else np.random.default_rng())
    return measure_qubits(qubits, bases)


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
# Photon-Number-Splitting Eavesdropper (Eve's PNS Attack)
# ─────────────────────────────────────────────
#
# A weak coherent pulse of mean photon number mu sometimes contains two or more identical
# photons (Poisson statistics). A photon-number-splitting Eve exploits exactly those: she
# replaces the lossy fibre with a lossless line, so she must see the pulses BEFORE the loss
# (usecases/send_file hands them over in eve-mode). For each pulse she knows its photon number
# n (a quantum non-demolition stand-in: in a real attack she measures the number without
# disturbing the state):
#
#   n == 0  nothing arrived; drop it.
#   n == 1  one photon only. She cannot split it without disturbing it, so she blocks the
#           pulse (Bob gets nothing) and keeps the photon — or, to tune Bob's click rate,
#           forwards a fraction of single-photon pulses instead (she then learns nothing
#           about those).
#   n >= 2  she splits one photon off and stores it, and forwards the rest to Bob over the
#           lossless line, so the pulse always clicks. She measures the stored photon only
#           after the public basis reveal (step 2), in the now-known correct basis, so she
#           introduces NO error on what Bob receives and learns the sifted bit exactly.
#
# The forwarding decision depends only on n, never on the intensity label: in real decoy QKD
# the label is secret until after detection, and an intensity-blind strategy is what lets the
# decoy estimate catch the attack (the signal/decoy gains scale with the multi-photon content,
# ~mu^2, not linearly in mu, so the single-photon-yield bound Y1_L collapses toward 0). The
# label is carried here only so Eve can keep per-intensity counts and pick which stored photons
# to measure after the reveal. Against the single-photon (Tomamichel) gate, which never looks at
# the gains, the attack goes undetected and Eve learns a large share of the key.


@dataclass(frozen=True)
class PnsPlan:
    """
    The outcome of Eve's PNS forwarding decision over one block of pre-loss pulses.

    forward_index / forward_qubits are the pulses (global pulse numbers, sorted, and their
    unchanged QASM states) that reach Bob. stored_* are the pulses Eve split a photon from and
    will measure after the basis reveal (a subset of the forwarded multi-photon pulses). The
    per-intensity counters cover the pulses Eve was handed (those with n >= 1): `blocked` never
    reached Bob, `forwarded_single` are single-photon pulses passed through (Eve learns nothing),
    and `split` are multi-photon pulses forwarded and stored (Eve learns the bit).
    """

    n_pulses: int
    forward_index: list[int]
    forward_qubits: list[Optional[str]]
    stored_index: list[int]
    stored_qubits: list[str]
    stored_label: list[int]
    blocked: list[int]
    forwarded_single: list[int]
    split: list[int]


def _gain(channel: ChannelParams, mu: float) -> float:
    """Honest overall gain Q_mu = 1 - (1 - Y0) e^(-eta mu) (core/decoy.gain, inlined)."""
    return 1.0 - (1.0 - channel.dark_count_prob) * math.exp(-channel.eta * mu)


def _poisson_split(mu: float) -> tuple[float, float]:
    """(P(n >= 2), P(n == 1)) for a Poisson(mu) photon number."""
    e = math.exp(-mu)
    return 1.0 - e * (1.0 + mu), mu * e


def pns_forward_fractions(
    channel: ChannelParams, mix_intensities, mix_probs,
    forward_fraction: Optional[float], multi_fraction: Optional[float],
) -> tuple[float, float]:
    """
    The (multi_fraction, single_fraction) Eve forwards, intensity-blind.

    With both left as None, Eve forwards multi-photon pulses and tops up with single-photon
    pulses so that Bob's overall gain matches the honest channel's expected gain for the given
    intensity mix, while forwarding as many multi-photon pulses as possible (she learns those).
    Because the multi-photon supply usually exceeds the honest gain at fibre distances, this
    normally throttles the multi-photon fraction below 1 and forwards no single photons; only at
    very low loss does it forward all multi-photon pulses and add single ones. Either value may
    be pinned explicitly (e.g. multi_fraction=1.0 to forward every multi-photon pulse).
    """
    target = sum(p * _gain(channel, mu) for mu, p in zip(mix_intensities, mix_probs))
    p_multi = sum(p * _poisson_split(mu)[0] for mu, p in zip(mix_intensities, mix_probs))
    p_single = sum(p * _poisson_split(mu)[1] for mu, p in zip(mix_intensities, mix_probs))
    if multi_fraction is None and forward_fraction is None:
        if p_multi >= target:
            return (target / p_multi if p_multi > 0 else 0.0), 0.0
        single = (target - p_multi) / p_single if p_single > 0 else 0.0
        return 1.0, min(1.0, max(0.0, single))
    multi = 1.0 if multi_fraction is None else float(multi_fraction)
    single = 0.0 if forward_fraction is None else float(forward_fraction)
    return min(1.0, max(0.0, multi)), min(1.0, max(0.0, single))


def eve_pns(
    index: list[int], labels: list[int], photons: list[int], qubits: list[Optional[str]],
    n_pulses: int, n_intensities: int, channel: ChannelParams, mix_intensities, mix_probs,
    rng: np.random.Generator, *, forward_fraction: Optional[float] = None,
    multi_fraction: Optional[float] = None,
) -> PnsPlan:
    """
    Run the PNS forwarding decision over the pre-loss pulses Alice handed Eve.

    index/labels/photons/qubits are parallel lists for the pulses with n >= 1 (n == 0 pulses
    never reach Eve). index holds global pulse numbers in increasing order. Returns a PnsPlan;
    Eve measures the stored photons later (after the basis reveal). She forwards each pulse's
    state unchanged, so Bob sees no extra error.
    """
    multi_frac, single_frac = pns_forward_fractions(channel, mix_intensities, mix_probs,
                                                     forward_fraction, multi_fraction)
    blocked = [0] * n_intensities
    forwarded_single = [0] * n_intensities
    split = [0] * n_intensities
    fwd_index: list[int] = []
    fwd_qubits: list[Optional[str]] = []
    stored_index: list[int] = []
    stored_qubits: list[str] = []
    stored_label: list[int] = []
    draws = rng.random(len(index))
    for g, k, n, q, u in zip(index, labels, photons, qubits, draws):
        k = int(k)
        if n >= 2:
            if u < multi_frac:
                fwd_index.append(int(g)); fwd_qubits.append(q)
                stored_index.append(int(g)); stored_qubits.append(q); stored_label.append(k)
                split[k] += 1
            else:
                blocked[k] += 1
        elif n == 1:
            if u < single_frac:
                fwd_index.append(int(g)); fwd_qubits.append(q)
                forwarded_single[k] += 1
            else:
                blocked[k] += 1
        else:
            blocked[k] += 1
    return PnsPlan(n_pulses, fwd_index, fwd_qubits, stored_index, stored_qubits, stored_label,
                   blocked, forwarded_single, split)


def eve_passthrough(
    index: list[int], photons: list[int], qubits: list[Optional[str]], n_pulses: int,
    channel: ChannelParams, rng: np.random.Generator,
) -> PnsPlan:
    """
    The honest control: Eve applies the real channel loss (no splitting) and forwards survivors.

    Each pulse's photons arrive independently with probability eta; a pulse is forwarded if any
    arrived. No photon is stored, so Eve learns nothing. This reproduces the honest gains, which
    shows the proxy path itself adds no artefact. (Dark counts, ~Y0, are omitted: Alice hands over
    only pulses with n >= 1, and Y0 is negligible next to the signal gain.)
    """
    fwd_index: list[int] = []
    fwd_qubits: list[Optional[str]] = []
    for g, n, q in zip(index, photons, qubits):
        if rng.binomial(int(n), channel.eta) >= 1:
            fwd_index.append(int(g))
            fwd_qubits.append(q)
    zero: list[int] = []
    return PnsPlan(n_pulses, fwd_index, fwd_qubits, [], [], [], zero, zero, zero)


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
