"""
Signed hello/finished handshake around the BB84 exchange (wire steps 0a, 0b, and 4b).

  0a A->B {"hello": {...}}      tracked in the transcript
  0b B->A {"hello": {...}}      tracked
  4b B->A, then A->B {"finished": sig, "confirm": tag}   untracked; sign and hybrid modes only
      With resume on, each finished also carries "resume": 1, and the signature then also covers
      RESUME_SUFFIX. Stripping or adding the flag in transit therefore fails the signature
      (PeerAuthError at 4b). Without the flag the signed bytes are those of a plain transfer.

Every hello carries the sender's security policy (ProtocolParams.security_policy:
final key length, eps_sec, eps_cor, QBER threshold, finite-key enforcement); the
receiver compares it with its own and aborts on any difference, like a mode
mismatch. The hellos are hashed into the transcript, so the finished signatures
over T bind both identity keys, both nonces, both policies, the KEM exchange, and
every tracked classical message up to and including the salt. Tampering is caught
by those signatures, never by KEM decapsulation: ML-KEM's implicit rejection
returns a wrong secret without raising.

The confirm tag is HMAC-SHA256 under the confirmation subkey of the session key
(crypto_utils.key_schedule) over "qkd-confirm-v1|<role>|" + T. The signature covers
T and the tag. The signature proves who is talking; the tag proves both sides
derived the same key. On a noiseless channel the keys can still differ when an
eavesdropper disturbed bits that the QBER sample missed; the tag catches that
before any file data moves, and it is reported as KeyConfirmationError, not as an
authentication failure.

Metrics (frozen names) are emitted in three events, with no name repeated:
auth_mode and peer_fingerprint once the peer's hello is parsed, peer_trust once
the trust check passes, then handshake_ms and auth_overhead_bytes after the
finished exchange (in none mode, right after the hellos).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.core.crypto_utils import derive_session_key, key_schedule
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import AuthContext, KeyConfirmationError, PeerAuthError

PROTOCOL_VERSION = 3  # 3: qubit message carries pulse indices (channel_model.encode_pulses)
MODES = ("none", "sign", "hybrid")
NONCE_BYTES = 32
ID_PK_BYTES = 1952  # ML-DSA-65 public key
FINISHED_PREFIX = b"qkd-finished-v1|"
RESUME_SUFFIX = b"|resume"  # appended to the signed bytes when the finished carries "resume": 1
CONFIRM_PREFIX = b"qkd-confirm-v1|"
CONFIRM_TAG_BYTES = 32


@dataclass
class HandshakeState:
    """What one side learned from the handshake, plus its cost so far."""

    mode: str  # "none" | "sign" | "hybrid"
    peer_id_pk: Optional[bytes] = None
    peer_trust: Optional[str] = None  # verifier.check() result
    kem_ss: Optional[bytes] = None  # hybrid only
    elapsed_s: float = 0.0  # wall time of the hello and finished exchanges
    overhead_bytes: int = 0  # framed bytes of hello and finished messages, sent + received
    preloss: bool = False  # peer announced an eve-mode pre-loss handoff (Bob reports detections)

    @property
    def signed(self) -> bool:
        return self.mode != "none"

    @property
    def peer_fingerprint(self) -> Optional[str]:
        return pqc.fingerprint(self.peer_id_pk) if self.peer_id_pk is not None else None


def local_mode(auth: AuthContext | None) -> str:
    return "none" if auth is None else auth.mode


def _checked_local_mode(auth: AuthContext | None) -> str:
    """local_mode(auth), or ValueError for a mode this protocol does not know."""
    mode = local_mode(auth)
    if mode not in MODES:
        raise ValueError(f"Invalid auth mode: {mode!r}. Allowed: {', '.join(MODES)}")
    return mode


def alice_hello(
    channel: TranscriptChannel,
    auth: AuthContext | None,
    reporter: Reporter,
    params: ProtocolParams = ProtocolParams(),
    preloss: bool = False,
) -> HandshakeState:
    """
    Steps 0a/0b for Alice. Returns only once Bob's identity passed the trust check.

    `preloss` announces an eve-mode pre-loss handoff in the hello (a non-policy flag), so Bob
    reports his detected pulse indices in step 2 and Alice sifts against his ground truth.
    """
    state = HandshakeState(_checked_local_mode(auth), preloss=preloss)
    policy = params.security_policy()
    with _cost(channel, state):
        kem_pk = kem_seed = None
        if state.mode == "hybrid":
            kem_pk, kem_seed = pqc.kem_keygen()
        reporter.info(f"Sending hello (mode: {state.mode})...")
        channel.send_json(_hello(state.mode, policy, auth, preloss=preloss, kem_pk=kem_pk))
        try:
            msg = channel.recv_json()
        except ConnectionError:
            raise PeerAuthError("peer closed connection during authentication") from None
        fields = _hello_fields(msg)
        mismatch = _mismatch(state.mode, policy, fields)
        if mismatch:
            raise PeerAuthError(mismatch)

        kem_ct = None
        if state.signed:
            state.peer_id_pk = _id_pk(fields)
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


def bob_hello(
    channel: TranscriptChannel,
    auth: AuthContext | None,
    reporter: Reporter,
    params: ProtocolParams = ProtocolParams(),
) -> HandshakeState:
    """Steps 0a/0b for Bob. Sends his hello only after Alice's identity passed the trust check."""
    state = HandshakeState(_checked_local_mode(auth))
    policy = params.security_policy()
    with _cost(channel, state):
        reporter.info("Waiting for Alice's hello...")
        fields = _hello_fields(channel.recv_json())
        mismatch = _mismatch(state.mode, policy, fields)
        if mismatch:
            # Tell Alice what we run, so both sides fail with the same reason
            channel.send_json({"hello": {"v": PROTOCOL_VERSION, "mode": state.mode, "params": policy}})
            raise PeerAuthError(mismatch)

        state.preloss = fields.get("preloss") == 1 and not isinstance(fields.get("preloss"), bool)
        alice_kem_pk = None
        if state.signed:
            state.peer_id_pk = _id_pk(fields)
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
        channel.send_json(_hello(state.mode, policy, auth, kem_ct=kem_ct))
    if not state.signed:
        _report_cost(reporter, state)
    return state


def alice_finished(
    channel: TranscriptChannel,
    auth: AuthContext,
    state: HandshakeState,
    transcript_hash: bytes,
    key: bytes,
    reporter: Reporter,
    offer_resume: bool = False,
) -> bool:
    """
    Step 4b for Alice: check Bob's finished (signature, then key tag) first, then send hers.

    `key` is the session key (session_key()). Raises PeerAuthError on a bad signature and
    KeyConfirmationError on a good signature with a wrong tag.

    Returns True if Bob's finished carried the resume flag (it is only meaningful when
    offer_resume is also True).
    """
    with _cost(channel, state):
        reporter.info("Verifying Bob's signature and key confirmation tag...")
        msg = channel.recv_untracked()
        _verify_finished(msg, state.peer_id_pk, b"bob", transcript_hash, key)
        reporter.success("Bob's finished verified: same transcript, same key")
        channel.send_untracked(_finished(auth.seed, b"alice", transcript_hash, key, offer_resume))
    _report_cost(reporter, state)
    return _resume_flag(msg)


def bob_finished(
    channel: TranscriptChannel,
    auth: AuthContext,
    state: HandshakeState,
    transcript_hash: bytes,
    key: bytes,
    reporter: Reporter,
    offer_resume: bool = False,
) -> bool:
    """
    Step 4b for Bob: send his finished, then check Alice's (signature, then key tag).

    Returns True if Alice's finished carried the resume flag (it is only meaningful when
    offer_resume is also True).
    """
    with _cost(channel, state):
        channel.send_untracked(_finished(auth.seed, b"bob", transcript_hash, key, offer_resume))
        reporter.info("Verifying Alice's signature and key confirmation tag...")
        msg = channel.recv_untracked()
        _verify_finished(msg, state.peer_id_pk, b"alice", transcript_hash, key)
        reporter.success("Alice's finished verified: same transcript, same key")
    _report_cost(reporter, state)
    return _resume_flag(msg)


def confirmation_tag(key: bytes, role: bytes, transcript_hash: bytes) -> bytes:
    """HMAC-SHA256 under the confirmation subkey of `key` over CONFIRM_PREFIX + role + "|" + T."""
    return hmac.new(key_schedule(key).confirm, CONFIRM_PREFIX + role + b"|" + transcript_hash, hashlib.sha256).digest()


def finished_message(role: bytes, transcript_hash: bytes, tag: bytes, resume: bool = False) -> bytes:
    """
    The bytes a finished signature covers: FINISHED_PREFIX + role + "|" + T + tag, plus
    RESUME_SUFFIX when the message carries the resume flag. T and the tag have fixed lengths,
    so the suffix cannot be confused with them.
    """
    return FINISHED_PREFIX + role + b"|" + transcript_hash + tag + (RESUME_SUFFIX if resume else b"")


def session_key(qkd_key: bytes, state: HandshakeState, transcript_hash: bytes) -> bytes:
    """The file key. In none mode this is derive_aes_key(qkd_key), the pre-handshake key."""
    return derive_session_key(qkd_key, state.kem_ss, transcript_hash, state.mode)


def _hello(mode: str, policy: dict, auth: AuthContext | None, preloss: bool = False,
           **extra: Optional[bytes]) -> dict:
    fields: dict[str, Any] = {"v": PROTOCOL_VERSION, "mode": mode, "params": policy}
    if preloss:
        fields["preloss"] = 1  # non-policy flag: eve-mode pre-loss handoff (see alice_hello)
    if mode != "none":
        fields["id_pk"] = _b64(auth.public_key)
        fields["nonce"] = _b64(os.urandom(NONCE_BYTES))
        fields.update({k: _b64(v) for k, v in extra.items() if v is not None})
    return {"hello": fields}


def _hello_fields(msg: Any) -> dict:
    if not isinstance(msg, dict) or not isinstance(msg.get("hello"), dict):
        raise PeerAuthError("malformed hello")
    return msg["hello"]


def _mismatch(local: str, policy: dict, fields: dict) -> Optional[str]:
    if fields.get("v") != PROTOCOL_VERSION:
        return f"version mismatch: local={PROTOCOL_VERSION} peer={fields.get('v')}"
    if fields.get("mode") != local:
        return f"mode mismatch: local={local} peer={fields.get('mode')}"
    if fields.get("params") != policy:
        return f"parameter mismatch: local={policy} peer={fields.get('params')}"
    return None


def _id_pk(fields: dict) -> bytes:
    id_pk = _b64_field(fields, "id_pk", "hello")
    if len(id_pk) != ID_PK_BYTES:
        raise PeerAuthError(f"malformed hello: id_pk must be {ID_PK_BYTES} bytes")
    return id_pk


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


def _finished(seed: bytes, role: bytes, transcript_hash: bytes, key: bytes, resume: bool = False) -> dict:
    tag = confirmation_tag(key, role, transcript_hash)
    signature = pqc.sign(seed, finished_message(role, transcript_hash, tag, resume))
    msg: dict[str, Any] = {"finished": _b64(signature), "confirm": _b64(tag)}
    if resume:
        msg["resume"] = 1
    return msg


def _resume_flag(msg: Any) -> bool:
    """Whether a finished message offers resume. Anything but the integer 1 counts as no."""
    return isinstance(msg, dict) and msg.get("resume") == 1 and not isinstance(msg.get("resume"), bool)


def _verify_finished(msg: Any, peer_pk: bytes, role: bytes, transcript_hash: bytes, key: bytes) -> None:
    """Check the signature first (who), then the tag (same key). See the module docstring."""
    if not isinstance(msg, dict):
        raise PeerAuthError("malformed finished")
    signature = _b64_field(msg, "finished", "finished")
    tag = _b64_field(msg, "confirm", "finished")
    if len(tag) != CONFIRM_TAG_BYTES:
        raise PeerAuthError(f"malformed finished: confirm must be {CONFIRM_TAG_BYTES} bytes")
    # The flag as received decides which bytes must have been signed, so a stripped or added flag fails here
    if not pqc.verify(peer_pk, finished_message(role, transcript_hash, tag, _resume_flag(msg)), signature):
        raise PeerAuthError(f"{role.decode()} finished signature invalid")
    if not hmac.compare_digest(tag, confirmation_tag(key, role, transcript_hash)):
        raise KeyConfirmationError(
            f"key confirmation failed: {role.decode()}'s key differs (channel errors the QBER sample missed)"
        )


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
