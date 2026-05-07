"""
Configuration constants for the BB84 QKD Secure File Transfer System.

This module defines all tunable parameters for quantum key distribution,
network communication, decoy-state analysis, and security thresholds.
"""

# ─────────────────────────────────────────────
# Network Configuration
# ─────────────────────────────────────────────
ALICE_HOST = "localhost"
BOB_PORT = 65432          # Bob listens here (normal mode)
EVE_PORT = 65433          # Eve's proxy port (Alice connects here in eve-mode)

BUFFER_SIZE = 1 << 20     # 1 MB recv buffer

# ─────────────────────────────────────────────
# Quantum Parameters
# ─────────────────────────────────────────────
NUM_QUBITS = 512          # Total raw qubits sent per round
QBER_SAMPLE_FRACTION = 0.15   # Fraction of sifted bits sacrificed for QBER estimation
QBER_THRESHOLD = 0.11         # Max tolerable QBER (11%) — theoretical BB84 limit

# ─────────────────────────────────────────────
# Decoy-State Protocol Parameters
# ─────────────────────────────────────────────
# Three intensity levels: signal, decoy, vacuum
# Probabilities must sum to 1.0
DECOY_INTENSITIES = {
    "signal": 0.8,    # μ — strong coherent pulses
    "decoy":  0.1,    # ν — weak decoy pulses
    "vacuum": 0.0,    # vacuum (zero photon)
}
DECOY_PROBABILITIES = {
    "signal": 0.60,
    "decoy":  0.30,
    "vacuum": 0.10,
}

# Threshold for anomalous yield difference between signal and decoy
# If |Y_signal - Y_decoy| > PNS_THRESHOLD, suspect PNS attack
PNS_YIELD_THRESHOLD = 0.35

# ─────────────────────────────────────────────
# Depolarizing Noise (Channel Simulation)
# ─────────────────────────────────────────────
NOISE_PROBABILITY = 0.02      # Probability of random bit flip per qubit (2% baseline noise)

# ─────────────────────────────────────────────
# Privacy Amplification
# ─────────────────────────────────────────────
FINAL_KEY_BITS = 256          # AES-256 key length

# ─────────────────────────────────────────────
# File Transfer
# ─────────────────────────────────────────────
CHUNK_SIZE = 4096             # Socket send/recv chunk size for file data
