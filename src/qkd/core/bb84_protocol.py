"""
BB84 Quantum Key Distribution Protocol Engine.

Implements the full BB84 pipeline with advanced quantum cryptographic techniques:

  1. Random bit & basis generation with decoy-state intensity tagging
  2. Basis sifting (classical channel)
  3. Decoy-state analysis — detects Photon Number Splitting (PNS) attacks
  4. QBER estimation — detects eavesdropping
  5. Information reconciliation — CASCADE-style parity error correction
  6. Privacy amplification — universal hashing to distill a secure key

References:
  - Bennett & Brassard, 1984 (BB84 original)
  - Hwang, 2003 (Decoy-state protocol)
  - Lo, Ma & Chen, 2005 (Decoy-state BB84 security proof)
"""

from __future__ import annotations
import random
import hashlib
import struct
from typing import Optional

from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from qkd.core.config import (
    NUM_QUBITS,
    QBER_SAMPLE_FRACTION,
    QBER_THRESHOLD,
    DECOY_PROBABILITIES,
    DECOY_INTENSITIES,
    PNS_YIELD_THRESHOLD,
    FINAL_KEY_BITS,
)


_qrng_backend = Aer.get_backend("qasm_simulator")

def _quantum_random_bits(n: int) -> list[int]:
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
    return _quantum_random_bits(n)


def generate_random_bases(n: int) -> list[str]:
    """
    Generate n truly random measurement bases using a QRNG.

    '+' = Rectilinear (Z-basis): eigenstates |0⟩, |1⟩
    'x' = Diagonal (X-basis):    eigenstates |+⟩, |−⟩
    """
    bits = _quantum_random_bits(n)
    return ["+" if b == 0 else "x" for b in bits]



def tag_decoy_states(n: int) -> list[str]:
    """
    Assign each pulse a random intensity label.

    Decoy-State Protocol (Hwang, 2003):
      Alice randomly varies the intensity of her laser pulses among
      three levels: signal (μ), decoy (ν), and vacuum.

      After transmission, Alice reveals which pulses were signal,
      decoy, or vacuum. By comparing detection rates across intensity
      levels, they can detect Photon Number Splitting (PNS) attacks.

    PNS Attack:
      Eve splits multi-photon pulses, keeps one photon, and forwards
      the rest. With identical intensities, this is undetectable.
      Decoy states expose PNS because the photon number statistics
      differ: an attacker selectively blocking single-photon pulses
      would cause measurable yield discrepancies between signal and
      decoy intensities.

    Returns a list of labels: 'signal', 'decoy', or 'vacuum'.
    """
    labels = list(DECOY_PROBABILITIES.keys())
    weights = list(DECOY_PROBABILITIES.values())
    return random.choices(labels, weights=weights, k=n)


# ─────────────────────────────────────────────
# 3. Basis Sifting
# ─────────────────────────────────────────────

def sift_keys(
    alice_bits: list[int],
    alice_bases: list[str],
    bob_bits: list[int],
    bob_bases: list[str],
    intensity_tags: list[str],
) -> tuple[list[int], list[int], list[str]]:
    """
    Basis sifting: keep only bits where Alice and Bob chose the same basis.

    In BB84, roughly 50% of bits are discarded because the bases don't match.
    This step is performed over the authenticated classical channel.

    Returns:
        (sifted_alice_bits, sifted_bob_bits, sifted_intensity_tags)
    """
    sifted_alice = []
    sifted_bob = []
    sifted_tags = []

    for a_bit, a_basis, b_bit, b_basis, tag in zip(
        alice_bits, alice_bases, bob_bits, bob_bases, intensity_tags
    ):
        if a_basis == b_basis:
            sifted_alice.append(a_bit)
            sifted_bob.append(b_bit)
            sifted_tags.append(tag)

    return sifted_alice, sifted_bob, sifted_tags


# ─────────────────────────────────────────────
# 4. Decoy-State Analysis
# ─────────────────────────────────────────────

def analyze_decoy_states(
    sifted_alice: list[int],
    sifted_bob: list[int],
    sifted_tags: list[str],
) -> tuple[dict, bool, str]:
    """
    Decoy-state analysis to detect Photon Number Splitting (PNS) attacks.

    Method:
      For each intensity level (signal, decoy, vacuum), compute:
        - Count: number of pulses at that intensity
        - Matches: number of bits where Alice and Bob agree
        - Yield: match_rate = matches / count

      In a PNS attack, Eve selectively blocks single-photon pulses
      (which dominate decoy and vacuum levels) while forwarding
      multi-photon pulses (more common at signal level). This creates
      an abnormal yield difference between intensity levels.

    Security Bound (Lo-Ma-Chen, 2005):
      The single-photon gain Q₁ ≥ (μ·e^μ / (μ·ν - ν²)) ×
        (Q_ν·e^ν - Q_vacuum·e^0 × ν²/μ² - (μ²-ν²)/(μ²) × Q_vacuum)

      We use a simplified check: if the yield difference between
      signal and decoy exceeds PNS_YIELD_THRESHOLD, flag an attack.

    Returns:
        (stats_dict, is_safe, message)
    """
    stats = {}
    for level in ["signal", "decoy", "vacuum"]:
        indices = [i for i, t in enumerate(sifted_tags) if t == level]
        count = len(indices)
        if count > 0:
            matches = sum(
                1 for i in indices if sifted_alice[i] == sifted_bob[i]
            )
            yield_rate = matches / count
        else:
            matches = 0
            yield_rate = 0.0

        stats[level] = {
            "count": count,
            "matches": matches,
            "yield": yield_rate,
            "intensity": DECOY_INTENSITIES[level],
        }

    sig_yield = stats["signal"]["yield"]
    dec_yield = stats["decoy"]["yield"] if stats["decoy"]["count"] > 0 else sig_yield

    yield_diff = abs(sig_yield - dec_yield)

    if yield_diff > PNS_YIELD_THRESHOLD:
        return stats, False, (
            f"⚠ PNS ATTACK DETECTED!\n"
            f"  Signal yield: {sig_yield:.3f}, Decoy yield: {dec_yield:.3f}\n"
            f"  Yield difference: {yield_diff:.3f} > threshold {PNS_YIELD_THRESHOLD}\n"
            f"  Abnormal photon statistics indicate selective blocking."
        )

    return stats, True, (
        f"✓ Decoy-state analysis passed.\n"
        f"  Signal yield: {sig_yield:.3f}, Decoy yield: {dec_yield:.3f}\n"
        f"  Yield difference: {yield_diff:.3f} ≤ threshold {PNS_YIELD_THRESHOLD}"
    )


def estimate_qber(
    sifted_alice: list[int],
    sifted_bob: list[int],
    sample_fraction: float = QBER_SAMPLE_FRACTION,
) -> tuple[float, list[int], list[int]]:
    """
    Quantum Bit Error Rate (QBER) estimation.

    Alice and Bob sacrifice a random subset of their sifted bits
    to estimate the error rate. These bits are revealed over the
    classical channel and can no longer be used for the key.

    QBER Interpretation:
      - QBER ≈ 0%:   No eavesdropper, minimal channel noise
      - QBER < 11%:   Safe — errors from channel noise only
      - QBER ≈ 25%:   Intercept-resend attack detected (Eve)
      - QBER ≈ 50%:   Fully random — complete interception

    The 11% threshold comes from the Shor-Preskill security proof:
    BB84 can distill a secure key if and only if QBER < 11%.

    Returns:
        (qber, remaining_alice_bits, remaining_bob_bits, sample_indices_list)
    """
    n = len(sifted_alice)
    sample_size = max(1, int(n * sample_fraction))

    sample_indices = set(random.sample(range(n), min(sample_size, n)))

    errors = 0
    for i in sample_indices:
        if sifted_alice[i] != sifted_bob[i]:
            errors += 1

    qber = errors / len(sample_indices) if sample_indices else 0.0

    remaining_alice = [sifted_alice[i] for i in range(n) if i not in sample_indices]
    remaining_bob = [sifted_bob[i] for i in range(n) if i not in sample_indices]

    return qber, remaining_alice, remaining_bob, sorted(sample_indices)


# ─────────────────────────────────────────────
# 6. Information Reconciliation
# ─────────────────────────────────────────────

def reconcile_keys(
    alice_bits: list[int],
    bob_bits: list[int],
) -> tuple[list[int], list[int], int]:
    """
    CASCADE-inspired information reconciliation.

    After QBER estimation, Alice and Bob's key bits may still have
    residual errors. Information reconciliation corrects these errors
    using parity checks over the classical channel.

    Simplified CASCADE Protocol:
      1. Divide the key into blocks
      2. For each block, Alice sends the parity (XOR of all bits)
      3. If parities disagree, perform binary search within the block
         to locate and correct the error bit
      4. Repeat with shuffled, larger blocks for multi-pass correction

    This implementation uses a single-pass block parity approach
    for clarity. In production, multiple passes with increasing
    block sizes achieve near-perfect reconciliation.

    Returns:
        (corrected_alice, corrected_bob, errors_corrected)
    """
    n = len(alice_bits)
    corrected_bob = list(bob_bits)
    errors_corrected = 0

    # Block size: √n is a good heuristic for CASCADE
    block_size = max(2, int(n ** 0.5))

    for start in range(0, n, block_size):
        end = min(start + block_size, n)
        block_a = alice_bits[start:end]
        block_b = corrected_bob[start:end]

        parity_a = sum(block_a) % 2
        parity_b = sum(block_b) % 2

        if parity_a != parity_b:
            # Binary search for the error within this block
            lo, hi = 0, len(block_a) - 1
            while lo < hi:
                mid = (lo + hi) // 2
                sub_parity_a = sum(block_a[lo:mid + 1]) % 2
                sub_parity_b = sum(block_b[lo:mid + 1]) % 2
                if sub_parity_a != sub_parity_b:
                    hi = mid
                else:
                    lo = mid + 1

            # Flip the error bit in Bob's key
            idx = start + lo
            corrected_bob[idx] ^= 1
            errors_corrected += 1

    return list(alice_bits), corrected_bob, errors_corrected


def privacy_amplification(
    key_bits: list[int],
    target_bits: int = FINAL_KEY_BITS,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Privacy amplification via universal hashing.

    Even after reconciliation, Eve may have partial information about
    the key. Privacy amplification compresses the key using a hash
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
        A `target_bits // 8` byte key.
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


def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits
