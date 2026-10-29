"""
Signed hello/finished handshake around the BB84 exchange (wire steps 0a, 0b, and 4b).

  0a A->B {"hello": {...}}      tracked in the transcript
  0b B->A {"hello": {...}}      tracked
  4b B->A, then A->B {"finished": sig}   untracked; sign and hybrid modes only

The hellos are hashed into the transcript, so the finished signatures over T bind
both identity keys, both nonces, the KEM exchange, and every tracked classical
message up to and including the salt. Tampering is caught by those signatures,
never by KEM decapsulation: ML-KEM's implicit rejection returns a wrong secret
without raising.

Metrics (frozen names) are emitted in three events, with no name repeated:
auth_mode and peer_fingerprint once the peer's hello is parsed, peer_trust once
the trust check passes, then handshake_ms and auth_overhead_bytes after the
finished exchange (in none mode, right after the hellos).
"""

from __future__ import annotations

import base64
import binascii
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional

from qkd.core import pqc
from qkd.core.crypto_utils import derive_session_key
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import AuthContext, PeerAuthError

PROTOCOL_VERSION = 1
NONCE_BYTES = 32
FINISHED_PREFIX = b"qkd-finished-v1|"


@dataclass
class HandshakeState:
    """What one side learned from the handshake, plus its cost so far."""

    mode: str  # "none" | "sign" | "hybrid"
    peer_id_pk: Optional[bytes] = None
    peer_trust: Optional[str] = None  # verifier.check() result
    kem_ss: Optional[bytes] = None  # hybrid only
    elapsed_s: float = 0.0  # wall time of the hello and finished exchanges
    overhead_bytes: int = 0  # framed bytes of hello and finished messages, sent + received

    @property
    def signed(self) -> bool:
        return self.mode != "none"

    @property
    def peer_fingerprint(self) -> Optional[str]:
        return pqc.fingerprint(self.peer_id_pk) if self.peer_id_pk is not None else None


def local_mode(auth: AuthContext | None) -> str:
    return "none" if auth is None else auth.mode


def alice_hello(channel: TranscriptChannel, auth: AuthContext | None, reporter: Reporter) -> HandshakeState:
    """Steps 0a/0b for Alice. Returns only once Bob's identity passed the trust check."""
    state = HandshakeState(local_mode(auth))
    with _cost(channel, state):
        kem_pk = kem_seed = None
        if state.mode == "hybrid":
            kem_pk, kem_seed = pqc.kem_keygen()
        reporter.info(f"Sending hello (mode: {state.mode})...")
        channel.send_json(_hello(state.mode, auth, kem_pk=kem_pk))
        try:
            msg = channel.recv_json()
        except ConnectionError:
            raise PeerAuthError("peer closed connection during authentication") from None
        fields = _hello_fields(msg)
        mismatch = _mismatch(state.mode, fields)
        if mismatch:
            raise PeerAuthError(mismatch)

        kem_ct = None
        if state.signed:
            state.peer_id_pk = _b64_field(fields, "id_pk", "hello")
            _nonce(fields)
            if state.mode == "hybrid":
                kem_ct = _b64_field(fields, "kem_ct", "hello")
        reporter.metrics(auth_mode=state.mode, peer_fingerprint=state.peer_fingerprint)

        if state.signed:
            state.peer_trust = auth.verifier.check(state.peer_id_pk)
            reporter.success(f"Bob's identity {state.peer_fingerprint} accepted ({state.peer_trust})")
        reporter.metrics(peer_trust=state.peer_trust)

        if state.mode == "hybrid":
            state.kem_ss = _kem(lambda: pqc.kem_decaps(kem_seed, kem_ct))
            reporter.success("ML-KEM-768 shared secret decapsulated")
    if not state.signed:
        _report_cost(reporter, state)
    return state


def bob_hello(channel: TranscriptChannel, auth: AuthContext | None, reporter: Reporter) -> HandshakeState:
    """Steps 0a/0b for Bob. Sends his hello only after Alice's identity passed the trust check."""
    state = HandshakeState(local_mode(auth))
    with _cost(channel, state):
        reporter.info("Waiting for Alice's hello...")
        fields = _hello_fields(channel.recv_json())
        mismatch = _mismatch(state.mode, fields)
        if mismatch:
            # Tell Alice what we run, so both sides fail with the same reason
            channel.send_json({"hello": {"v": PROTOCOL_VERSION, "mode": state.mode}})
            raise PeerAuthError(mismatch)

        alice_kem_pk = None
        if state.signed:
            state.peer_id_pk = _b64_field(fields, "id_pk", "hello")
            _nonce(fields)
            if state.mode == "hybrid":
                alice_kem_pk = _b64_field(fields, "kem_pk", "hello")
        reporter.metrics(auth_mode=state.mode, peer_fingerprint=state.peer_fingerprint)

        if state.signed:
            state.peer_trust = auth.verifier.check(state.peer_id_pk)
            reporter.success(f"Alice's identity {state.peer_fingerprint} accepted ({state.peer_trust})")
        reporter.metrics(peer_trust=state.peer_trust)

        kem_ct = None
        if state.mode == "hybrid":
            state.kem_ss, kem_ct = _kem(lambda: pqc.kem_encaps(alice_kem_pk))
            reporter.success("ML-KEM-768 shared secret encapsulated")
        reporter.info(f"Sending hello (mode: {state.mode})...")
        channel.send_json(_hello(state.mode, auth, kem_ct=kem_ct))
    if not state.signed:
        _report_cost(reporter, state)
    return state


def alice_finished(
    channel: TranscriptChannel, auth: AuthContext, state: HandshakeState, transcript_hash: bytes, reporter: Reporter
) -> None:
    """Step 4b for Alice: verify Bob's signature over T first, then send hers."""
    with _cost(channel, state):
        reporter.info("Verifying Bob's signature over the transcript...")
        _verify_finished(channel.recv_untracked(), state.peer_id_pk, b"bob", transcript_hash)
        reporter.success("Bob's finished signature verified")
        channel.send_untracked(_finished(auth.seed, b"alice", transcript_hash))
    _report_cost(reporter, state)


def bob_finished(
    channel: TranscriptChannel, auth: AuthContext, state: HandshakeState, transcript_hash: bytes, reporter: Reporter
) -> None:
    """Step 4b for Bob: send his signature over T, then verify Alice's."""
    with _cost(channel, state):
        channel.send_untracked(_finished(auth.seed, b"bob", transcript_hash))
        reporter.info("Verifying Alice's signature over the transcript...")
        _verify_finished(channel.recv_untracked(), state.peer_id_pk, b"alice", transcript_hash)
        reporter.success("Alice's finished signature verified")
    _report_cost(reporter, state)


def session_key(qkd_key: bytes, state: HandshakeState, transcript_hash: bytes) -> bytes:
    """The file key. In none mode this is derive_aes_key(qkd_key), the pre-handshake key."""
    return derive_session_key(qkd_key, state.kem_ss, transcript_hash, state.mode)


def _hello(mode: str, auth: AuthContext | None, **extra: Optional[bytes]) -> dict:
    fields: dict[str, Any] = {"v": PROTOCOL_VERSION, "mode": mode}
    if mode != "none":
        fields["id_pk"] = _b64(auth.public_key)
        fields["nonce"] = _b64(os.urandom(NONCE_BYTES))
        fields.update({k: _b64(v) for k, v in extra.items() if v is not None})
    return {"hello": fields}


def _hello_fields(msg: Any) -> dict:
    if not isinstance(msg, dict) or not isinstance(msg.get("hello"), dict):
        raise PeerAuthError("malformed hello")
    return msg["hello"]


def _mismatch(local: str, fields: dict) -> Optional[str]:
    if fields.get("v") != PROTOCOL_VERSION:
        return f"version mismatch: local={PROTOCOL_VERSION} peer={fields.get('v')}"
    if fields.get("mode") != local:
        return f"mode mismatch: local={local} peer={fields.get('mode')}"
    return None


def _nonce(fields: dict) -> bytes:
    nonce = _b64_field(fields, "nonce", "hello")
    if len(nonce) != NONCE_BYTES:
        raise PeerAuthError(f"malformed hello: nonce must be {NONCE_BYTES} bytes")
    return nonce


def _kem(op: Callable[[], Any]) -> Any:
    try:
        return op()
    except ValueError as exc:
        raise PeerAuthError(f"malformed hello: {exc}") from None


def _finished(seed: bytes, role: bytes, transcript_hash: bytes) -> dict:
    return {"finished": _b64(pqc.sign(seed, FINISHED_PREFIX + role + b"|" + transcript_hash))}


def _verify_finished(msg: Any, peer_pk: bytes, role: bytes, transcript_hash: bytes) -> None:
    if not isinstance(msg, dict):
        raise PeerAuthError("malformed finished")
    signature = _b64_field(msg, "finished", "finished")
    if not pqc.verify(peer_pk, FINISHED_PREFIX + role + b"|" + transcript_hash, signature):
        raise PeerAuthError(f"{role.decode()} finished signature invalid")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64_field(fields: dict, name: str, what: str) -> bytes:
    if name not in fields:
        raise PeerAuthError(f"malformed {what}: missing {name}")
    try:
        return base64.b64decode(fields[name], validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise PeerAuthError(f"malformed {what}: {name} is not valid base64") from None


@contextmanager
def _cost(channel: TranscriptChannel, state: HandshakeState) -> Iterator[None]:
    """Add the wall time and framed bytes of the enclosed exchange to state."""
    t0 = time.perf_counter()
    bytes0 = channel.bytes_sent + channel.bytes_received
    try:
        yield
    finally:
        state.elapsed_s += time.perf_counter() - t0
        state.overhead_bytes += channel.bytes_sent + channel.bytes_received - bytes0


def _report_cost(reporter: Reporter, state: HandshakeState) -> None:
    reporter.metrics(handshake_ms=round(state.elapsed_s * 1000, 3), auth_overhead_bytes=state.overhead_bytes)
