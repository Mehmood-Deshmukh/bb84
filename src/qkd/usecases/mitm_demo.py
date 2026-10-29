"""
Mallory: an in-path party for the authenticated-channel demonstration.

Mallory sits between Alice and Bob on the sockets the caller provides, playing Bob
toward Alice (alice_sock) and Alice toward Bob (bob_sock). Both endpoints are local
sockets supplied by the demo runner; this module runs no attack against anything
deployed. It exists to show, in tests and the demo, what the signed handshake does
and does not prevent.

Two strategies:

  own_key    She runs the full receiver protocol against Alice with her own identity,
             and, if she obtains the file, the full sender protocol toward Bob. With
             auth off this relays the file and reveals the plaintext unnoticed; with
             auth on, Alice rejects her key at the hello and she gets nothing.

  relay_hello (sign/hybrid) She forwards Alice's and Bob's real hellos unchanged and
             runs Bob's side of the key exchange against Alice, so her transcript
             matches Alice's. At the finished step she can only sign with her own key,
             so Alice's signature check rejects her. Bob, never sent any qubits, is
             released when she closes his socket.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import socket
import tempfile
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.services import wire
from qkd.services.reporting import NullReporter, Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases import receive_file as bob_flow
from qkd.usecases import send_file as alice_flow
from qkd.usecases.common import AuthContext, PeerAuthError
from qkd.usecases.handshake import FINISHED_PREFIX

Identity = tuple[bytes, bytes]
# Everything a protocol leg can fail with; never lets one propagate out of run_mitm.
_LEG_ERRORS = (PeerAuthError, ConnectionError, OSError, InvalidTag)


class AcceptAnyVerifier:
    """Trusts whatever public key it is shown; Mallory pins nothing."""

    def check(self, peer_public_key: bytes) -> str:
        return "new"


@dataclass(frozen=True)
class MitmResult:
    strategy: str
    mode: str
    plaintext_sha256: Optional[str]  # hex of the file she recovered on leg 1, else None
    plaintext_bytes: int
    alice_error: Optional[str]  # what stopped the Alice-facing leg, else None
    bob_error: Optional[str]  # what stopped the Bob-facing leg, else None
    relayed: bool  # True iff Bob received a file


def run_mitm(
    alice_sock: socket.socket,
    bob_sock: socket.socket,
    reporter: Reporter,
    params: ProtocolParams,
    mode: str,
    strategy: str = "own_key",
    identity: Optional[Identity] = None,
) -> MitmResult:
    """Drive the two already-connected sockets with the chosen strategy."""
    if strategy not in ("own_key", "relay_hello"):
        raise ValueError(f"Unknown strategy: {strategy!r}")
    if strategy == "relay_hello" and mode == "none":
        raise ValueError("relay_hello requires an authenticated mode (sign or hybrid)")
    identity = identity or pqc.sig_keygen()
    try:
        if strategy == "own_key":
            return _own_key(alice_sock, bob_sock, reporter, params, mode, identity)
        return _relay_hello(alice_sock, bob_sock, reporter, params, mode, identity)
    finally:
        # Unblock whichever endpoint is still waiting on us.
        _shutdown(alice_sock, bob_sock)


def _own_key(
    alice_sock: socket.socket,
    bob_sock: socket.socket,
    reporter: Reporter,
    params: ProtocolParams,
    mode: str,
    identity: Identity,
) -> MitmResult:
    reporter.section("Mallory: own-key strategy")
    ctx = _context(mode, identity)
    tmpdir = tempfile.mkdtemp(prefix="mitm-")
    plaintext_sha256: Optional[str] = None
    plaintext_bytes = 0
    alice_error: Optional[str] = None
    bob_error: Optional[str] = None
    relayed = False
    try:
        reporter.info("Leg 1: receiving from Alice, posing as Bob")
        path: Optional[str] = None
        try:
            result = bob_flow.receive_file(alice_sock, tmpdir, NullReporter(), params, ctx)
            if result.output_path is not None:
                path = result.output_path
            else:
                kx = result.key_exchange
                alice_error = f"qber {kx.qber:.2%} >= threshold {kx.threshold:.0%}"
        except _LEG_ERRORS as exc:
            alice_error = _reason(exc)

        if path is not None:
            data = _read(path)
            plaintext_sha256 = hashlib.sha256(data).hexdigest()
            plaintext_bytes = len(data)
            reporter.success(f"Recovered {plaintext_bytes} bytes of plaintext (sha256 {plaintext_sha256[:16]}...)")

            reporter.info("Leg 2: sending to Bob, posing as Alice")
            try:
                alice_flow.send_file(bob_sock, path, NullReporter(), params, _context(mode, identity))
                relayed = True
                reporter.success("Relayed the file to Bob undetected")
            except _LEG_ERRORS as exc:
                bob_error = _reason(exc)
        else:
            reporter.warning("Leg 1 produced no file; not contacting Bob")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return MitmResult("own_key", mode, plaintext_sha256, plaintext_bytes, alice_error, bob_error, relayed)


def _relay_hello(
    alice_sock: socket.socket,
    bob_sock: socket.socket,
    reporter: Reporter,
    params: ProtocolParams,
    mode: str,
    identity: Identity,
) -> MitmResult:
    reporter.section("Mallory: relay-hello strategy")
    _, seed = identity
    alice_error: Optional[str] = None
    channel = TranscriptChannel(alice_sock, "bob")  # hash exactly as Bob would
    try:
        # 0a/0b: forward the real hellos both ways, hashing them into the channel.
        reporter.info("Relaying both hellos unchanged")
        alice_hello = channel.recv_json()  # from Alice (hashed, Alice's direction)
        wire.send_json(bob_sock, alice_hello)  # to Bob (not on the channel)
        bob_hello = wire.recv_json(bob_sock)  # from Bob
        channel.send_json(bob_hello)  # to Alice (hashed, Bob's direction)

        # Be Bob through qubits, sifting, QBER, and salt, against Alice herself.
        reporter.info("Running Bob's key exchange against Alice")
        bob_flow.run_key_exchange(channel, params, NullReporter())
        transcript_hash = channel.digest()

        # 4b: she holds no Bob seed, so she signs with her own key; Alice will reject it.
        reporter.info("Sending a finished signed with Mallory's key")
        signature = pqc.sign(seed, FINISHED_PREFIX + b"bob|" + transcript_hash)  # cf. handshake._finished
        channel.send_untracked({"finished": base64.b64encode(signature).decode()})
        # Wait for Alice's reaction so the finished is delivered before we close.
        try:
            channel.recv_untracked()
        except (ConnectionError, OSError):
            pass
    except _LEG_ERRORS as exc:
        alice_error = _reason(exc)
    return MitmResult("relay_hello", mode, None, 0, alice_error, None, False)


def _context(mode: str, identity: Identity) -> Optional[AuthContext]:
    if mode == "none":
        return None
    pk, seed = identity
    return AuthContext(mode, pk, seed, AcceptAnyVerifier())


def _reason(exc: BaseException) -> str:
    return getattr(exc, "reason", None) or str(exc) or type(exc).__name__


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _shutdown(*socks: socket.socket) -> None:
    for sock in socks:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
