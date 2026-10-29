"""
Shared helpers for the invariants tests: the wire step list, a generic in-path
proxy driven by it, and the verifier/reporter/context pieces the signed-handshake,
MITM, and tamper tests all use.

The proxy is the single place (besides the use cases and handshake.py) that encodes
the wire order, so a change to the protocol order shows up here too.
"""

from __future__ import annotations

import socket
from typing import Any, Callable, Optional

import pytest

from qkd.core import pqc
from qkd.services import wire
from qkd.services.reporting import NullReporter
from qkd.usecases.common import AuthContext, PeerAuthError

# ── wire order ──────────────────────────────────────────────────────────────
A2B = "A2B"  # Alice -> Bob
B2A = "B2A"  # Bob -> Alice

# (step_id, direction) for every classical message up to the first file chunk.
# After "5-meta" come the encrypted chunks, all Alice -> Bob, until EOF.
WIRE_STEPS: list[tuple[str, str]] = [
    ("0a", A2B),               # Alice's hello
    ("0b", B2A),               # Bob's hello
    ("1", A2B),                # qubits (untracked)
    ("2-bases", B2A),          # Bob's measurement bases
    ("2-matching", A2B),       # matching basis indices
    ("3-sample_indices", A2B),
    ("3-sample_bits", B2A),
    ("3-qber", A2B),
    ("4-salt", A2B),
    ("4b-bob", B2A),           # Bob's finished signature (sign/hybrid)
    ("4b-alice", A2B),         # Alice's finished signature (sign/hybrid)
    ("5-meta", A2B),           # file metadata
]


def proxy(
    sock_from_alice: socket.socket,
    sock_to_bob: socket.socket,
    *,
    tamper_step: Optional[str] = None,
    tamper: Optional[Callable[[Any], Any]] = None,
    stop_after: Optional[str] = None,
) -> None:
    """
    Relay the wire between Alice and Bob, optionally rewriting one step.

    For the step whose id == tamper_step, the JSON payload is decoded, passed to
    `tamper`, re-encoded, and forwarded (so the far side hashes/receives the change).
    Every other step is forwarded byte-for-byte. Forwarding stops after the step
    whose id == stop_after; if stop_after is None it forwards all steps and then
    relays chunk messages (Alice -> Bob) until EOF.

    Both of the proxy's own socket ends are shut down on every return path, so a
    peer still blocked in recv (e.g. Bob waiting for Alice's finished after Alice
    has already failed) unblocks with a ConnectionError instead of hanging.
    """

    def ends(direction: str) -> tuple[socket.socket, socket.socket]:
        return (sock_from_alice, sock_to_bob) if direction == A2B else (sock_to_bob, sock_from_alice)

    try:
        for step_id, direction in WIRE_STEPS:
            src, dst = ends(direction)
            if step_id == tamper_step:
                assert tamper is not None
                wire.send_bytes(dst, wire.encode_json(tamper(wire.decode_json(wire.recv_bytes(src)))))
            else:
                wire.forward_message(src, dst)
            if step_id == stop_after:
                return
        while True:  # encrypted chunks, Alice -> Bob, until Alice closes
            wire.forward_message(sock_from_alice, sock_to_bob)
    except (ConnectionError, OSError):
        return
    finally:
        for sock in (sock_from_alice, sock_to_bob):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


# ── trust, reporting, and context ────────────────────────────────────────────
AUTH_METRICS = {"auth_mode", "peer_fingerprint", "peer_trust", "handshake_ms", "auth_overhead_bytes"}
BB84_METRICS = {"raw_qubits", "sifted_length", "sample_size", "qber", "qber_threshold", "key_bits"}
SIGNED_STAGES = [
    "authentication",
    "quantum_transmission",
    "sifting",
    "qber_estimation",
    "privacy_amplification",
    "key_confirmation",
    "file_transfer",
]


class PinnedVerifier:
    """Accepts exactly one public key, like a trust store with a single pin."""

    def __init__(self, expected: bytes) -> None:
        self.expected = expected

    def check(self, peer_public_key: bytes) -> str:
        if peer_public_key != self.expected:
            raise PeerAuthError("peer public key does not match the pinned key")
        return "pinned"


class RecordingReporter(NullReporter):
    """Captures the stages, metrics, and progress a workflow reports."""

    def __init__(self) -> None:
        self.stages: list[str] = []
        self.metric_events: list[dict[str, Any]] = []
        self.progress_events: list[tuple[int, int, int, int]] = []

    def stage(self, stage: str) -> None:
        self.stages.append(stage)

    def metrics(self, **values: Any) -> None:
        self.metric_events.append(values)

    def progress(self, chunks_done: int, num_chunks: int, bytes_done: int, total_bytes: int) -> None:
        self.progress_events.append((chunks_done, num_chunks, bytes_done, total_bytes))

    def merged(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for event in self.metric_events:
            out.update(event)
        return out

    def auth_metric_counts(self) -> dict[str, int]:
        """How many metrics events carried each auth metric name."""
        return {name: sum(name in e for e in self.metric_events) for name in AUTH_METRICS}

    def chunks_reported(self) -> int:
        """The largest chunks_done seen (0 if no chunk was ever reported complete)."""
        return max((done for done, *_ in self.progress_events), default=0)


@pytest.fixture(scope="module")
def keys() -> dict[str, tuple[bytes, bytes]]:
    return {"alice": pqc.sig_keygen(), "bob": pqc.sig_keygen()}


def context(
    keys: dict[str, tuple[bytes, bytes]], role: str, mode: str, pin: Optional[bytes] = None
) -> Optional[AuthContext]:
    """role's AuthContext pinning the other peer's key (or `pin`); None for mode "none"."""
    if mode == "none":
        return None
    peer = "bob" if role == "alice" else "alice"
    pk, seed = keys[role]
    return AuthContext(mode, pk, seed, PinnedVerifier(pin or keys[peer][0]))


def guarded(fn: Callable[[socket.socket], Any]) -> Callable[[socket.socket], Any]:
    """Run fn(sock) like a runner: return its result or exception, then close the connection."""

    def run(sock: socket.socket) -> Any:
        try:
            return fn(sock)
        except Exception as exc:  # noqa: BLE001 - asserted on by the caller
            return exc
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    return run
