"""
BB84 key distillation steps used by Alice and Bob.

  1. Random bit and basis generation (Qiskit Aer as a quantum RNG)
  2. Basis sifting over the classical channel
  3. QBER estimation on a revealed sample, abort at or above the threshold
  4. Privacy amplification (SHA-256 over salt + remaining bits)

There is no information reconciliation step: the simulated channel is
noiseless, so Alice's and Bob's remaining sifted bits already agree.

References:
  - Bennett & Brassard, 1984 (BB84 original)
  - Shor & Preskill, 2000 (11% QBER bound)
"""

from __future__ import annotations
import random
import hashlib
import struct
from typing import Optional

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from qkd.core.config import (
    QBER_SAMPLE_FRACTION,
    QBER_THRESHOLD,
    FINAL_KEY_BITS,
)


_qrng_backend = Aer.get_backend("qasm_simulator")


def _quantum_random_bits(n: int) -> list[int]:
    """n bits from measuring H|0⟩ on the Aer simulator (one shot per bit)."""
    if n == 0:
        return []

    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)

    compiled = transpile(qc, _qrng_backend)
    result = _qrng_backend.run(compiled, shots=n, memory=True).result()
    memory = result.get_memory()

    return [int(b) for b in memory]


def generate_random_bits(n: int) -> list[int]:
    """Alice's raw key bits."""
    return _quantum_random_bits(n)


def generate_random_bases(n: int) -> list[str]:
    """
    Generate n truly random measurement bases using a QRNG.

    '+' = Rectilinear (Z-basis): eigenstates |0⟩, |1⟩
    'x' = Diagonal (X-basis):    eigenstates |+⟩, |−⟩
    """
    bits = _quantum_random_bits(n)
    return ["+" if b == 0 else "x" for b in bits]



def matching_basis_indices(alice_bases: list[str], bob_bases: list[str]) -> list[int]:
    """Indices where Alice and Bob chose the same basis (basis sifting, ~50% kept)."""
    return [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]


def choose_sample_indices(n: int, sample_fraction: float = QBER_SAMPLE_FRACTION) -> list[int]:
    """
    Pick the sifted positions that Alice and Bob reveal to estimate the QBER.

    These bits are disclosed over the classical channel and are removed from
    the key afterwards.
    """
    sample_size = max(1, int(n * sample_fraction))
    return sorted(random.sample(range(n), min(sample_size, n)))


def compute_qber(alice_sample: list[int], bob_sample: list[int]) -> float:
    """
    Quantum Bit Error Rate over the revealed sample.

    QBER Interpretation:
      - QBER ≈ 0%:   No eavesdropper, minimal channel noise
      - QBER < 11%:   Safe — errors from channel noise only
      - QBER ≈ 25%:   Intercept-resend attack detected (Eve)
      - QBER ≈ 50%:   Fully random — complete interception
    """
    if not alice_sample:
        return 0.0
    errors = sum(1 for a, b in zip(alice_sample, bob_sample) if a != b)
    return errors / len(alice_sample)


def qber_exceeds_threshold(qber: float, threshold: float = QBER_THRESHOLD) -> bool:
    """
    True when the key exchange must abort.

    The 11% threshold comes from the Shor-Preskill security proof:
    BB84 can distill a secure key if and only if QBER < 11%.
    """
    return qber >= threshold


def discard_indices(bits: list[int], indices: list[int]) -> list[int]:
    """Remove the revealed sample positions from the sifted key."""
    drop = set(indices)
    return [b for i, b in enumerate(bits) if i not in drop]


def privacy_amplification(
    key_bits: list[int],
    target_bits: int = FINAL_KEY_BITS,
    salt: Optional[bytes] = None,
) -> tuple[bytes, bytes]:
    """
    Privacy amplification via universal hashing.

    Eve may have partial information about the sifted key. Privacy amplification compresses the key using a hash
    function, reducing Eve's knowledge to negligibly small.

    Theory (Bennett, Brassard, Robert, 1988):
      If Eve has at most `t` bits of Rényi entropy about the key,
      then hashing the n-bit key to (n - t - s) bits ensures Eve's
      information is bounded by 2^(-s/2).

    We use SHA-256 as the universal hash function, producing a
    256-bit key suitable for AES-256.

    The salt ensures different runs produce different keys even
    with the same raw bits (simulating a random hash function
    choice from a universal family).

    Returns:
        (salt, key) where key is `target_bits // 8` bytes.
    """
    key_bytes = bits_to_bytes(key_bits)

    if salt is None:
        salt = struct.pack(">Q", random.getrandbits(64))

    h = hashlib.sha256()
    h.update(salt)
    h.update(key_bytes)
    digest = h.digest()

    target_bytes = target_bits // 8
    return salt, digest[:target_bytes]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits to a bytes object."""
    # Pad to multiple of 8
    padded = bits + [0] * ((8 - len(bits) % 8) % 8)
    result = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | padded[i + j]
        result.append(byte)
    return bytes(result)
