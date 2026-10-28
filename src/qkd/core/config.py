"""
Configuration constants for the BB84 QKD Secure File Transfer System.

Every tunable can be overridden with an environment variable named
QKD_<NAME>, for example QKD_NUM_QUBITS=256. Values are read once, at import.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


def _env(name: str, default: T, cast: Callable[[str], T]) -> T:
    raw = os.environ.get(f"QKD_{name}")
    if raw is None or raw == "":
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid value for QKD_{name}: {raw!r}") from exc


def _env_dict(name: str, default: dict[str, float]) -> dict[str, float]:
    return _env(name, default, lambda raw: {str(k): float(v) for k, v in json.loads(raw).items()})


# ─────────────────────────────────────────────
# Network Configuration
# ─────────────────────────────────────────────
ALICE_HOST = _env("ALICE_HOST", "localhost", str)
BOB_PORT = _env("BOB_PORT", 65432, int)          # Bob listens here (normal mode)
EVE_PORT = _env("EVE_PORT", 65433, int)          # Eve's proxy port (Alice connects here in eve-mode)

BUFFER_SIZE = _env("BUFFER_SIZE", 1 << 20, int)  # 1 MB recv buffer

# HTTP port of the backend node. Peers are contacted on the port they advertise
# over mDNS; this is the port this node listens on and advertises.
NODE_PORT = _env("NODE_PORT", int(os.environ.get("PORT", 8000)), int)

# ─────────────────────────────────────────────
# Quantum Parameters
# ─────────────────────────────────────────────
NUM_QUBITS = _env("NUM_QUBITS", 128, int)                       # Total raw qubits sent per round
QBER_SAMPLE_FRACTION = _env("QBER_SAMPLE_FRACTION", 0.15, float)  # Fraction of sifted bits sacrificed for QBER estimation
QBER_THRESHOLD = _env("QBER_THRESHOLD", 0.11, float)            # Max tolerable QBER (11%), theoretical BB84 limit

# ─────────────────────────────────────────────
# Decoy-State Protocol Parameters
# ─────────────────────────────────────────────
# Three intensity levels: signal, decoy, vacuum
# Probabilities must sum to 1.0. Override with a JSON object.
DECOY_INTENSITIES = _env_dict("DECOY_INTENSITIES", {
    "signal": 0.8,    # μ — strong coherent pulses
    "decoy":  0.1,    # ν — weak decoy pulses
    "vacuum": 0.0,    # vacuum (zero photon)
})
DECOY_PROBABILITIES = _env_dict("DECOY_PROBABILITIES", {
    "signal": 0.60,
    "decoy":  0.30,
    "vacuum": 0.10,
})

# Threshold for anomalous yield difference between signal and decoy
# If |Y_signal - Y_decoy| > PNS_THRESHOLD, suspect PNS attack
PNS_YIELD_THRESHOLD = _env("PNS_YIELD_THRESHOLD", 0.35, float)

# ─────────────────────────────────────────────
# Depolarizing Noise (Channel Simulation)
# ─────────────────────────────────────────────
NOISE_PROBABILITY = _env("NOISE_PROBABILITY", 0.02, float)  # Probability of random bit flip per qubit (2% baseline noise)

# ─────────────────────────────────────────────
# Privacy Amplification
# ─────────────────────────────────────────────
FINAL_KEY_BITS = _env("FINAL_KEY_BITS", 256, int)  # AES-256 key length

# ─────────────────────────────────────────────
# File Transfer
# ─────────────────────────────────────────────
CHUNK_SIZE = _env("CHUNK_SIZE", 65536, int)  # 64 KB chunk size for streaming file encryption/transfer

# Directory where Bob writes received files (relative paths resolve against the cwd)
OUTPUT_DIR = _env("OUTPUT_DIR", "received", str)

# Transfer history written by the backend node
HISTORY_FILE = _env("HISTORY_FILE", "history.json", str)


@dataclass(frozen=True)
class ProtocolParams:
    """Per-run protocol parameters. Defaults come from the module constants above."""

    num_qubits: int = NUM_QUBITS
    qber_sample_fraction: float = QBER_SAMPLE_FRACTION
    qber_threshold: float = QBER_THRESHOLD
    chunk_size: int = CHUNK_SIZE
