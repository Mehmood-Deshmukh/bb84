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
    ("5-meta", A2B),           # file metadata (AES-GCM ciphertext, not JSON)
]
# Steps whose payload is raw bytes; a tamper function for these gets and returns bytes.
BINARY_STEPS = {"5-meta"}


# The same order with a decoy source: the decoy reveal (step 2d) sits between sifting
# (step 2) and QBER estimation (step 3). Both messages are tracked (JSON).
WIRE_STEPS_DECOY: list[tuple[str, str]] = [
    *WIRE_STEPS[:5],             # 0a, 0b, 1, 2-bases, 2-matching
    ("2d-reveal", A2B),          # Alice's intensity labels + decoy/vacuum bits
    ("2d-gains", B2A),           # Bob's per-intensity gains and QBERs
    *WIRE_STEPS[5:],             # 3-sample_indices ... 5-meta
]


# The same steps when both sides run with resume on (sign/hybrid): the sealed request and grant
# sit between the finished exchange and the metadata.
WIRE_STEPS_RESUME: list[tuple[str, str]] = [
    *WIRE_STEPS[:-1],
    ("4c-resume-request", B2A),  # Bob's sealed resume request
    ("4d-resume-grant", A2B),    # Alice's sealed resume grant
    WIRE_STEPS[-1],
]
# After the chunks, with resume: Bob's sealed receipt. Pass it as final_steps (with chunks=N).
RESUME_FINAL_STEPS: list[tuple[str, str]] = [("6-resume-done", B2A)]


def proxy(
    sock_from_alice: socket.socket,
    sock_to_bob: socket.socket,
    *,
    tamper_step: Optional[str] = None,
    tamper: Optional[Callable[[Any], Any]] = None,
    stop_after: Optional[str] = None,
    steps: Optional[list[tuple[str, str]]] = None,
    max_chunks: Optional[int] = None,
    chunks: Optional[int] = None,
    final_steps: Optional[list[tuple[str, str]]] = None,
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

    `steps` defaults to WIRE_STEPS; pass WIRE_STEPS_RESUME when both sides run with resume on.
    With max_chunks=k only k encrypted chunk messages are relayed before the connection is cut,
    which is how the resume tests interrupt a transfer. With chunks=N exactly N chunk messages are
    relayed (instead of "until EOF") and then final_steps, e.g. RESUME_FINAL_STEPS, which run Bob -> Alice.
    """
    steps = WIRE_STEPS if steps is None else steps

    def ends(direction: str) -> tuple[socket.socket, socket.socket]:
        return (sock_from_alice, sock_to_bob) if direction == A2B else (sock_to_bob, sock_from_alice)

    def relay_step(step_id: str, direction: str) -> None:
        src, dst = ends(direction)
        if step_id == tamper_step:
            assert tamper is not None
            raw = wire.recv_bytes(src)
            if step_id in BINARY_STEPS:
                wire.send_bytes(dst, tamper(raw))
            else:
                wire.send_bytes(dst, wire.encode_json(tamper(wire.decode_json(raw))))
        else:
            wire.forward_message(src, dst)

    try:
        for step_id, direction in steps:
            relay_step(step_id, direction)
            if step_id == stop_after:
                return
        relayed = 0
        limit = max_chunks if max_chunks is not None else chunks
        while limit is None or relayed < limit:  # encrypted chunks, Alice -> Bob, until Alice closes
            wire.forward_message(sock_from_alice, sock_to_bob)
            relayed += 1
        if max_chunks is None:
            for step_id, direction in final_steps or []:
                relay_step(step_id, direction)
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
BB84_METRICS = {"raw_qubits", "sifted_length", "sample_size", "qber", "qber_threshold", "secure_key_bits", "key_bits",
                "sim_ms", "qubit_bytes", "channel_bytes", "file_wire_bytes", "detected"}
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
