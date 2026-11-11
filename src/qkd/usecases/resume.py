"""
Resume negotiation (wire steps 4c and 4d), between key confirmation and the file metadata.

  4c  B->A {"resume_request": b64(nonce || AES-GCM(request, aad = T | "resume-request"))}
  4d  A->B {"resume_grant":   b64(nonce || AES-GCM(grant,   aad = T | "resume-grant" | SHA-256(request blob)))}

  6   B->A {"resume_done":    b64(nonce || AES-GCM(receipt, aad = T | "resume-done"))}
      sent by Bob once the size and the SHA-256 of the whole file checked out and the file was
      renamed into place; Alice reports success only after reading it. Without it a sender can
      finish writing into its socket buffers while the receiver never got the data.

Both messages are untracked, sealed under HKDF subkeys of the session key (never the file key)
and bound to the transcript digest T, so they can neither be read, altered, nor replayed into
another session. A message that fails authentication is a PeerAuthError: the transfer aborts
before any file data moves.

The two sides enter 4c/4d only if each offered resume in its `finished` message. The flag is
covered by the finished signature, so a network attacker who strips or adds it fails step 4b
(PeerAuthError) and cannot make one side negotiate while the other does not. An attacker can
still stall the exchange until the negotiation timeout; that reveals no data and reuses no key.

Bob asks to continue after the chunks he holds (`next_chunk`), with a hash of those bytes.
Alice decides the offset: `next_chunk` if her file still starts with those bytes, else 0 and a
`reason` (the source changed). A resume is a new session with a fresh key and a fresh base
nonce; the offset only decides which chunk indices are sent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from cryptography.exceptions import InvalidTag

from qkd.core import pqc
from qkd.core.config import RESUME_SYNC_CHUNKS
from qkd.core.crypto_utils import open_resume_message, seal_resume_message
from qkd.services.file_stream import file_sha256
from qkd.services.reporting import Reporter
from qkd.services.resume import (
    TRANSFER_ID,
    ResumeError,
    ResumeState,
    ResumeStore,
    chunk_boundary,
    meta_digest,
)
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import AuthContext, PeerAuthError
from qkd.usecases.handshake import HandshakeState

NEGOTIATION_TIMEOUT = 30.0  # seconds to wait for the peer's resume message
REQUEST_VERSION = 1

# Why Alice sent a transfer from the start instead of continuing
REASON_FILE_CHANGED = "file_changed"  # name or size differs from the interrupted transfer
REASON_CHUNK_SIZE = "chunk_size_changed"
REASON_SOURCE_CHANGED = "source_changed"  # same size, but the bytes already received no longer match


@dataclass(frozen=True)
class ResumeOptions:
    """Turns resume on for one send_file/receive_file call. `transfer_id` names the state on disk."""

    transfer_id: str
    sync_chunks: int = RESUME_SYNC_CHUNKS
    timeout: float = NEGOTIATION_TIMEOUT

    def __post_init__(self) -> None:
        if not TRANSFER_ID.match(self.transfer_id or ""):
            raise ValueError(f"Resume needs a transfer id of 1 to 64 letters, digits, '-' or '_': {self.transfer_id!r}")


@dataclass(frozen=True)
class BobNegotiation:
    store: ResumeStore
    previous: Optional[ResumeState]  # what Bob had on disk before this session
    offset: int  # first chunk index Alice will send
    reason: Optional[str]  # set when Alice restarted from 0 although Bob asked for more


def wants_resume(resume: Optional[ResumeOptions], auth: Optional[AuthContext], reporter: Reporter) -> bool:
    """Resume is available only with an authenticated peer: in mode none there is nothing to bind it to."""
    if resume is None:
        return False
    if auth is None:
        reporter.warning("Resume needs auth mode sign or hybrid: there is no peer identity to bind it to. Continuing without resume.")
        return False
    return True


def bob_negotiate(
    channel: TranscriptChannel,
    key: bytes,
    transcript_hash: bytes,
    handshake: HandshakeState,
    resume: ResumeOptions,
    output_dir: str,
    reporter: Reporter,
) -> BobNegotiation:
    """
    Step 4c/4d for Bob: ask to continue where his verified data ends, and learn the offset.

    Raises PeerAuthError if the peer differs from the one that started the transfer (before the
    partial file is touched) or if the grant fails authentication; ResumeError otherwise.
    """
    reporter.info("Negotiating resume...")
    store = ResumeStore(output_dir, resume.transfer_id)
    previous = store.load()
    next_chunk, prefix = 0, None
    if previous is not None:
        if previous.peer_fingerprint != handshake.peer_fingerprint:
            raise PeerAuthError(
                "resume refused: the authenticated peer's identity differs from the one that started this transfer"
            )
        next_chunk = store.recover(previous)
        prefix = store.prefix_sha256(previous.next_byte)
        reporter.info(f"Holding {previous.next_byte} verified bytes ({next_chunk} chunks) of an interrupted transfer")

    request = {
        "v": REQUEST_VERSION,
        "transfer_id": resume.transfer_id,
        "next_chunk": next_chunk,
        "chunk_size": previous.chunk_size if previous else None,
        "meta_digest": previous.meta_digest if previous else None,
        "prefix_sha256": prefix,
        "alice_fp": handshake.peer_fingerprint,
    }
    blob = seal_resume_message(key, "bob", _dumps(request), transcript_hash + b"|resume-request")
    channel.send_untracked({"resume_request": _b64(blob)})

    with _deadline(channel.sock, resume.timeout):
        msg = _recv(channel, "the sender did not answer the resume request")
    grant = _open(msg, "resume_grant", key, "alice", transcript_hash + b"|resume-grant|" + hashlib.sha256(blob).digest(),
                  "resume grant")
    offset, reason = grant.get("offset"), grant.get("reason")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset not in {0, next_chunk}:
        raise ResumeError(f"the sender granted an offset ({offset!r}) that is neither 0 nor {next_chunk}")
    if reason is not None and not isinstance(reason, str):
        raise ResumeError("malformed resume grant")
    if offset == 0 and next_chunk > 0:
        reporter.warning(f"The sender restarts the transfer from the beginning ({reason or 'no reason given'})")
        reporter.metrics(resume_restart_reason=reason or "restarted")
    elif offset > 0:
        reporter.success(f"Resuming at chunk {offset}")
    return BobNegotiation(store, previous, offset, reason if offset == 0 and next_chunk > 0 else None)


def alice_negotiate(
    channel: TranscriptChannel,
    key: bytes,
    transcript_hash: bytes,
    auth: AuthContext,
    resume: ResumeOptions,
    filepath: str,
    chunk_size: int,
    reporter: Reporter,
) -> tuple[int, Optional[str]]:
    """
    Step 4c/4d for Alice: verify Bob's request, decide the offset, answer. Returns (offset, restart reason).

    Raises PeerAuthError if the request fails authentication or names another sender;
    ResumeError if it belongs to another transfer. Nothing of the file has been sent yet.
    """
    reporter.info("Waiting for Bob's resume request...")
    with _deadline(channel.sock, resume.timeout):
        msg = _recv(channel, "the receiver sent no resume request")
    request_blob = _decode_blob(msg, "resume_request", "resume request")
    request = _open(msg, "resume_request", key, "bob", transcript_hash + b"|resume-request", "resume request")

    if request.get("v") != REQUEST_VERSION:
        raise ResumeError("unsupported resume request version")
    if request.get("transfer_id") != resume.transfer_id:
        raise ResumeError("the resume request belongs to a different transfer")
    if request.get("alice_fp") != pqc.fingerprint(auth.public_key):
        raise PeerAuthError("resume request was addressed to a different sender identity")
    next_chunk = request.get("next_chunk")
    if isinstance(next_chunk, bool) or not isinstance(next_chunk, int) or next_chunk < 0:
        raise ResumeError("malformed resume request")

    offset, reason = next_chunk, None
    if next_chunk > 0:
        name, size = os.path.basename(filepath), os.path.getsize(filepath)
        if request.get("meta_digest") != meta_digest(name, size):
            offset, reason = 0, REASON_FILE_CHANGED
        elif request.get("chunk_size") != chunk_size:
            offset, reason = 0, REASON_CHUNK_SIZE
        elif request.get("prefix_sha256") != file_sha256(filepath, chunk_boundary(next_chunk, chunk_size, size)):
            offset, reason = 0, REASON_SOURCE_CHANGED
    if reason:
        reporter.warning(f"The file changed since the interruption ({reason}): sending it from the beginning")
        reporter.metrics(resume_restart_reason=reason)
    elif offset:
        reporter.success(f"Bob's {offset} chunks still match the file: continuing at chunk {offset}")

    grant = {"offset": offset, "reason": reason}
    aad = transcript_hash + b"|resume-grant|" + hashlib.sha256(request_blob).digest()
    channel.send_untracked({"resume_grant": _b64(seal_resume_message(key, "alice", _dumps(grant), aad))})
    return offset, reason


def bob_send_receipt(channel: TranscriptChannel, key: bytes, transcript_hash: bytes, sha256: str, size: int) -> None:
    """Step 6 for Bob: tell Alice the whole file arrived and verified."""
    receipt = _dumps({"received": True, "sha256": sha256, "size": size})
    blob = seal_resume_message(key, "bob", receipt, transcript_hash + b"|resume-done")
    channel.send_untracked({"resume_done": _b64(blob)})


def alice_await_receipt(channel: TranscriptChannel, key: bytes, transcript_hash: bytes, sha256: str, size: int) -> None:
    """
    Step 6 for Alice: wait for Bob's receipt. ConnectionError (Bob never confirmed) propagates;
    PeerAuthError if the receipt fails authentication; ResumeError if it names another file.
    """
    msg = channel.recv_untracked()
    receipt = _open(msg, "resume_done", key, "bob", transcript_hash + b"|resume-done", "receipt")
    if receipt.get("received") is not True or receipt.get("sha256") != sha256 or receipt.get("size") != size:
        raise ResumeError("the receiver's receipt does not match the file that was sent")


# ── helpers ─────────────────────────────────────────────────────


def _dumps(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _recv(channel: TranscriptChannel, missing: str) -> Any:
    try:
        return channel.recv_untracked()
    except TimeoutError:
        raise ResumeError(f"timed out: {missing}", resumable=True) from None
    except ValueError:  # not JSON (for example raw metadata bytes): the peer is not negotiating
        raise ResumeError(f"{missing} (got something else)", resumable=True) from None


def _decode_blob(msg: Any, name: str, what: str) -> bytes:
    if not isinstance(msg, dict) or not isinstance(msg.get(name), str):
        raise ResumeError(f"malformed {what}" if isinstance(msg, dict) and name in msg else f"the peer sent no {what}", resumable=True)
    try:
        return base64.b64decode(msg[name], validate=True)
    except (binascii.Error, ValueError):
        raise PeerAuthError(f"malformed {what}") from None


def _open(msg: Any, name: str, key: bytes, role: str, aad: bytes, what: str) -> dict:
    blob = _decode_blob(msg, name, what)
    try:
        plaintext = open_resume_message(key, role, blob, aad)
    except InvalidTag:
        raise PeerAuthError(f"{what} failed authentication") from None
    try:
        data = json.loads(plaintext)
    except ValueError:
        raise ResumeError(f"malformed {what}") from None
    if not isinstance(data, dict):
        raise ResumeError(f"malformed {what}")
    return data


@contextmanager
def _deadline(sock: socket.socket, seconds: float) -> Iterator[None]:
    """Bound a blocking receive; the socket's previous timeout is restored afterwards."""
    previous = sock.gettimeout()
    sock.settimeout(seconds)
    try:
        yield
    finally:
        sock.settimeout(previous)
