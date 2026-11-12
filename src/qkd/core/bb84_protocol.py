"""
BB84 key distillation steps used by Alice and Bob.

  1. Random bit and basis generation (Qiskit Aer as a quantum RNG)
  2. Basis sifting over the classical channel
  3. QBER estimation on a revealed sample, abort at or above the threshold
  4. Finite-key length check, then privacy amplification by Toeplitz hashing

There is no information reconciliation step: the simulated channel is
noiseless, so Alice's and Bob's remaining sifted bits already agree.

References:
  - Bennett & Brassard, 1984 (BB84 original)
  - Shor & Preskill, 2000 (11% QBER bound)
"""

from __future__ import annotations
import secrets
from typing import Optional

import numpy as np

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from qkd.core.config import (
    QBER_SAMPLE_FRACTION,
    QBER_THRESHOLD,
    FINAL_KEY_BITS,
)


_qrng_backend = Aer.get_backend("qasm_simulator")

# Sample positions and the privacy amplification salt come from the OS CSPRNG.
# The random module (Mersenne Twister) is predictable once enough of its output
# has been observed, and predictable sample positions would let an eavesdropper
# avoid the bits that are checked.
_csprng = secrets.SystemRandom()


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


def generate_random_bits(n: int, rng: "np.random.Generator | None" = None) -> list[int]:
    """
    Alice's raw key bits.

    With no ``rng`` the bits come from the Aer QRNG (one shot per bit), unchanged. Passing a
    NumPy generator draws them directly in NumPy instead: the analytic measurement backend uses
    this so that a 1e6-1e7-pulse run does not submit millions of shots to the simulator.
    """
    if rng is not None:
        return rng.integers(0, 2, size=n, dtype=np.int8).tolist()
    return _quantum_random_bits(n)


def generate_random_bases(n: int, rng: "np.random.Generator | None" = None) -> list[str]:
    """
    Generate n truly random measurement bases using a QRNG (or ``rng`` in NumPy, see
    generate_random_bits).

    '+' = Rectilinear (Z-basis): eigenstates |0⟩, |1⟩
    'x' = Diagonal (X-basis):    eigenstates |+⟩, |−⟩
    """
    if rng is not None:
        return ["x" if b else "+" for b in rng.integers(0, 2, size=n, dtype=np.int8).tolist()]
    bits = _quantum_random_bits(n)
    return ["+" if b == 0 else "x" for b in bits]



def matching_basis_indices(alice_bases: list[str], bob_bases: list[str]) -> list[int]:
    """Indices where Alice and Bob chose the same basis (basis sifting, ~50% kept)."""
    return [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]


def choose_sample_indices(n: int, sample_fraction: float = QBER_SAMPLE_FRACTION) -> list[int]:
    """
    Pick the sifted positions that Alice and Bob reveal to estimate the QBER.

    These bits are disclosed over the classical channel and are removed from
    the key afterwards. The positions are drawn from the OS CSPRNG.
    """
    sample_size = max(1, int(n * sample_fraction))
    return sorted(_csprng.sample(range(n), min(sample_size, n)))


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


def toeplitz_seed_bytes(n: int, m: int) -> int:
    """Bytes of seed needed to hash n bits down to m bits with a Toeplitz matrix (n + m - 1 bits)."""
    return (n + m - 1 + 7) // 8


def toeplitz_hash(bits: list[int], seed: bytes, m: int) -> bytes:
    """
    Multiply the n-bit vector `bits` by an m x n binary Toeplitz matrix, over GF(2).

    The matrix is T[i][j] = s[i - j + n - 1], where s is the first n + m - 1 bits
    of `seed` (most significant bit first). A product with a Toeplitz matrix is a
    convolution, so y[i] = (s * bits)[i + n - 1] mod 2. Returns m bits packed into
    bytes, most significant bit first (m must be a multiple of 8).
    """
    n = len(bits)
    if n == 0 or m <= 0 or m % 8:
        raise ValueError("toeplitz_hash needs at least one input bit and a positive multiple of 8 output bits")
    if len(seed) != toeplitz_seed_bytes(n, m):
        raise ValueError(f"Toeplitz seed must be {toeplitz_seed_bytes(n, m)} bytes, got {len(seed)}")
    s = np.unpackbits(np.frombuffer(seed, dtype=np.uint8))[: n + m - 1].astype(np.int64)
    x = np.asarray(bits, dtype=np.int64)
    y = np.convolve(s, x)[n - 1 : n - 1 + m] & 1
    return np.packbits(y.astype(np.uint8)).tobytes()


def privacy_amplification(
    key_bits: list[int],
    target_bits: int = FINAL_KEY_BITS,
    salt: Optional[bytes] = None,
) -> tuple[bytes, bytes]:
    """
    Privacy amplification with a random Toeplitz matrix (a two-universal hash family).

    By the leftover hash lemma, hashing the kept bits down to target_bits with a
    randomly chosen member of a two-universal family leaves Eve's information
    about the result bounded as in core/finite_key.py, provided target_bits is no
    more than the secure length computed there. The caller checks that bound.

    `salt` is the Toeplitz seed. Alice draws it from the OS CSPRNG and sends it
    in the clear; Bob passes the one he received.

    Returns:
        (salt, key) where key is target_bits // 8 bytes.
    """
    if salt is None:
        salt = secrets.token_bytes(toeplitz_seed_bytes(len(key_bits), target_bits))
    return salt, toeplitz_hash(key_bits, salt, target_bits)


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
