"""
Configuration constants for the BB84 QKD Secure File Transfer System.

Every tunable can be overridden with an environment variable named
QKD_<NAME>, for example QKD_NUM_QUBITS=256. Values are read once, at import.
"""

from __future__ import annotations

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
NODE_NAME = _env("NODE_NAME", "", str)  # display name advertised over mDNS ("" = generated)
NODE_HOST = _env("NODE_HOST", "", str)  # address advertised to peers ("" = auto-detect)

# ─────────────────────────────────────────────
# Quantum Parameters
# ─────────────────────────────────────────────
NUM_QUBITS = _env("NUM_QUBITS", 128, int)                       # Total raw qubits sent per round
QBER_SAMPLE_FRACTION = _env("QBER_SAMPLE_FRACTION", 0.15, float)  # Fraction of sifted bits sacrificed for QBER estimation
QBER_THRESHOLD = _env("QBER_THRESHOLD", 0.11, float)            # Max tolerable QBER (11%), theoretical BB84 limit

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

# ─────────────────────────────────────────────
# Authentication & PQC Configuration
# ─────────────────────────────────────────────
def _validate_auth_mode(raw: str) -> str:
    val = raw.strip().lower()
    if val not in {"none", "sign", "hybrid"}:
        raise ValueError(f"Invalid auth mode: {raw!r}. Allowed: none, sign, hybrid")
    return val


def _cast_tofu(raw: str) -> int:
    val = raw.strip().lower()
    if val in ("1", "true", "yes"):
        return 1
    if val in ("0", "false", "no"):
        return 0
    return int(raw)


AUTH_MODE = _env("AUTH_MODE", "hybrid", _validate_auth_mode)
IDENTITY_DIR = _env("IDENTITY_DIR", "identity", str)
KNOWN_PEERS_FILE = _env("KNOWN_PEERS_FILE", "known_peers.json", str)
TOFU = _env("TOFU", 1, _cast_tofu)

# ─────────────────────────────────────────────
# Resumable transfers (off by default; needs AUTH_MODE sign or hybrid)
# ─────────────────────────────────────────────
RESUME = _env("RESUME", 0, _cast_tofu)  # 1 = runners launched by the node negotiate resume; CLI flag --resume
RESUME_SYNC_CHUNKS = _env("RESUME_SYNC_CHUNKS", 8, int)  # verified chunks between fsync + sidecar updates
STATE_FILE = _env("STATE_FILE", "node_state.json", str)  # interrupted transfers kept by the backend node


@dataclass(frozen=True)
class ProtocolParams:
    """Per-run protocol parameters. Defaults come from the module constants above."""

    num_qubits: int = NUM_QUBITS
    qber_sample_fraction: float = QBER_SAMPLE_FRACTION
    qber_threshold: float = QBER_THRESHOLD
    chunk_size: int = CHUNK_SIZE
