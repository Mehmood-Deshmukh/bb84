"""
Configuration constants for the BB84 QKD Secure File Transfer System.

Every tunable can be overridden with an environment variable named
QKD_<NAME>, for example QKD_NUM_QUBITS=256. Values are read once, at import.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Callable, TypeVar

from qkd.core.channel_model import PRESETS, ChannelParams, preset

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
# 8192 raw qubits is the smallest power of two for which the finite-key bound
# (see core/finite_key.py) gives at least 256 secure bits with the defaults below.
NUM_QUBITS = _env("NUM_QUBITS", 8192, int)                      # Total raw qubits sent per round
QBER_SAMPLE_FRACTION = _env("QBER_SAMPLE_FRACTION", 0.15, float)  # Fraction of sifted bits sacrificed for QBER estimation
QBER_THRESHOLD = _env("QBER_THRESHOLD", 0.11, float)            # Early abort on the point estimate (asymptotic BB84 limit)

# ─────────────────────────────────────────────
# Privacy Amplification
# ─────────────────────────────────────────────
FINAL_KEY_BITS = _env("FINAL_KEY_BITS", 256, int)  # AES-256 key length

# Finite-key security parameters (Tomamichel et al. 2012). EPS_SEC bounds the
# distance of the final key from a perfectly secret one; EPS_COR bounds the
# probability that Alice's and Bob's keys differ without being noticed.
EPS_SEC = _env("EPS_SEC", 1e-10, float)
EPS_COR = _env("EPS_COR", 1e-15, float)

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


# Abort when the finite-key bound gives fewer than FINAL_KEY_BITS secure bits.
# Only tests and experiments that study something else (tampering, timing at
# small sizes) should turn this off; the key is then NOT provably secure.
ENFORCE_FINITE_KEY = bool(_env("ENFORCE_FINITE_KEY", 1, _cast_tofu))

# ─────────────────────────────────────────────
# Quantum channel (core/channel_model.py)
# ─────────────────────────────────────────────
# A named parameter set at a fibre length; any single value can be overridden.
# The default "ideal" channel loses nothing and adds no errors (the original protocol).
CHANNEL_PRESET = _env("CHANNEL_PRESET", "ideal", str)
CHANNEL_LENGTH_KM = _env("CHANNEL_LENGTH_KM", 0.0, float)
FIBER_LOSS_DB_PER_KM = _env("FIBER_LOSS_DB_PER_KM", None, float)  # alpha
DETECTOR_EFFICIENCY = _env("DETECTOR_EFFICIENCY", None, float)  # eta_Bob
DARK_COUNT_PROB = _env("DARK_COUNT_PROB", None, float)  # Y0, per pulse
MISALIGNMENT = _env("MISALIGNMENT", None, float)  # e_d


def _channel() -> ChannelParams:
    if CHANNEL_PRESET not in PRESETS:
        raise ValueError(f"Invalid value for QKD_CHANNEL_PRESET: {CHANNEL_PRESET!r}. Known: {', '.join(PRESETS)}")
    overrides = {name: value for name, value in (
        ("loss_db_per_km", FIBER_LOSS_DB_PER_KM),
        ("detector_efficiency", DETECTOR_EFFICIENCY),
        ("dark_count_prob", DARK_COUNT_PROB),
        ("misalignment", MISALIGNMENT),
    ) if value is not None}
    return replace(preset(CHANNEL_PRESET, CHANNEL_LENGTH_KM), **overrides)


CHANNEL = _channel()


def _validate_reconciliation(raw: str) -> str:
    val = raw.strip().lower()
    if val not in {"none", "cascade"}:
        raise ValueError(f"Invalid reconciliation: {raw!r}. Allowed: none, cascade")
    return val


# Error correction between QBER estimation and privacy amplification (core/cascade.py).
# "none" keeps the original protocol, where any error aborts at key confirmation.
RECONCILIATION = _env("RECONCILIATION", "none", _validate_reconciliation)


# ─────────────────────────────────────────────
# Photon source (core/source.py; decoy numerics in core/decoy.py)
# ─────────────────────────────────────────────
def _validate_source(raw: str) -> str:
    val = raw.strip().lower()
    if val not in {"single", "decoy"}:
        raise ValueError(f"Invalid source: {raw!r}. Allowed: single, decoy")
    return val


def _csv_floats(raw: str) -> tuple:
    try:
        return tuple(float(x) for x in raw.split(","))
    except ValueError as exc:
        raise ValueError(f"expected comma-separated numbers, got {raw!r}") from exc


def validate_decoy_setup(intensities: tuple, probs: tuple) -> None:
    """Check the (signal, decoy, vacuum) intensities and their probabilities are well formed."""
    if len(intensities) != 3 or len(probs) != 3:
        raise ValueError("decoy setup needs exactly 3 intensities and 3 probabilities (signal, decoy, vacuum)")
    mu, nu, vac = intensities
    if not (mu > nu > vac >= 0.0):
        raise ValueError(f"intensities must be strictly decreasing with a non-negative vacuum, got {intensities}")
    if vac != 0.0:
        raise ValueError(f"the third intensity is the vacuum decoy and must be 0.0, got {vac}")
    if any(p < 0 for p in probs) or abs(sum(probs) - 1.0) > 1e-9:
        raise ValueError(f"probabilities must be non-negative and sum to 1, got {probs}")


# "single" keeps the original single-photon-source behaviour (every existing run). "decoy"
# switches Alice to a weak coherent source with three intensities and runs the decoy reveal
# (wire step 2d) and the decoy asymptotic estimate (core/decoy.py).
SOURCE = _env("SOURCE", "single", _validate_source)
# (signal, decoy, vacuum) mean photon numbers and the probability of sending each.
DECOY_INTENSITIES = _env("DECOY_INTENSITIES", (0.48, 0.1, 0.0), _csv_floats)
DECOY_PROBS = _env("DECOY_PROBS", (0.7, 0.2, 0.1), _csv_floats)
validate_decoy_setup(DECOY_INTENSITIES, DECOY_PROBS)

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
    final_key_bits: int = FINAL_KEY_BITS
    eps_sec: float = EPS_SEC
    eps_cor: float = EPS_COR
    enforce_finite_key: bool = ENFORCE_FINITE_KEY
    # Physics, not policy: not negotiated in the hello. Alice's side applies loss and
    # background clicks, Bob's side the misalignment error (see channel_model.py).
    channel: ChannelParams = CHANNEL
    reconciliation: str = RECONCILIATION
    # Photon source: "single" (default) or "decoy". The intensities/probs are the weak
    # coherent source's (signal, decoy, vacuum) means and their probabilities; they are
    # policy (both peers must agree) because Bob counts clicks per intensity label.
    source: str = SOURCE
    intensities: tuple = DECOY_INTENSITIES
    probs: tuple = DECOY_PROBS

    @property
    def decoy_enabled(self) -> bool:
        return self.source == "decoy"

    def security_policy(self) -> dict:
        """
        The values both peers must agree on. Sent in the hello (so they are bound
        into the transcript) and compared on arrival; a mismatch aborts.

        intensities/probs are emitted as lists, not tuples, so a side's own policy still
        compares equal to the peer's after the JSON round trip (JSON has no tuple).
        """
        return {
            "final_key_bits": self.final_key_bits,
            "eps_sec": self.eps_sec,
            "eps_cor": self.eps_cor,
            "qber_threshold": self.qber_threshold,
            "enforce_finite_key": self.enforce_finite_key,
            "reconciliation": self.reconciliation,
            "source": self.source,
            "intensities": list(self.intensities),
            "probs": list(self.probs),
        }
