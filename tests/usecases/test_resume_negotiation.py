"""
Resume negotiation (steps 4c and 4d) on top of a real hello/finished handshake, over socket pairs.

The BB84 exchange is skipped, as in test_handshake.py: a tracked salt message gives both sides a
transcript, and a fixed QKD key stands in for the distilled one. Where a test plays one side by hand
it uses the sealing helpers directly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from qkd.core import pqc
from qkd.core.crypto_utils import open_resume_message, seal_resume_message
from qkd.services.file_stream import describe_file, file_sha256
from qkd.services.reporting import NullReporter
from qkd.services.resume import ResumeError, ResumeStore
from qkd.services.transcript import TranscriptChannel
from qkd.services.wire import send_json
from qkd.usecases.common import AuthContext, PeerAuthError
from qkd.usecases.handshake import alice_finished, alice_hello, bob_finished, bob_hello, session_key
from qkd.usecases.resume import (
    alice_await_receipt,
    bob_send_receipt,
    REASON_CHUNK_SIZE,
    REASON_FILE_CHANGED,
    REASON_SOURCE_CHANGED,
    ResumeOptions,
    alice_negotiate,
    bob_negotiate,
)
from tests.invariants.support import RecordingReporter, context, keys  # noqa: F401 (fixture)

CHUNK = 1000
SIZE = 8 * CHUNK + 50
TID = "xfer1"
QKD_KEY = b"\x07" * 32


class Session:
    """Everything one side of a finished handshake knows when negotiation starts."""

    def __init__(self, ch: TranscriptChannel, state, auth: AuthContext, peer_offers: bool, tag: bytes) -> None:
        self.ch, self.state, self.auth, self.peer_offers = ch, state, auth, peer_offers
        self.T = ch.digest()
        self.key = session_key(QKD_KEY, state, self.T)
        self.salt_tag = tag


def run_pair(keys, alice_step: Callable[[Session], Any], bob_step: Callable[[Session], Any], *,
             alice_offers: bool = True, bob_offers: bool = True, mode: str = "hybrid", salt: str = "00" * 16):
    """Handshake both sides, then run the two steps. Each result is the return value or the exception raised."""
    alice_auth, bob_auth = context(keys, "alice", mode), context(keys, "bob", mode)
    a, b = socket.socketpair()

    def alice(sock: socket.socket):
        ch = TranscriptChannel(sock, "alice")
        state = alice_hello(ch, alice_auth, NullReporter())
        ch.send_json({"salt": salt})
        T = ch.digest()
        peer = alice_finished(ch, alice_auth, state, T, NullReporter(), alice_offers)
        return alice_step(Session(ch, state, alice_auth, peer, b"a"))

    def bob(sock: socket.socket):
        ch = TranscriptChannel(sock, "bob")
        state = bob_hello(ch, bob_auth, NullReporter())
        ch.recv_json()
        T = ch.digest()
        peer = bob_finished(ch, bob_auth, state, T, NullReporter(), bob_offers)
        return bob_step(Session(ch, state, bob_auth, peer, b"b"))

    def guard(fn, sock):
        def run():
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

    import threading

    out: list[Any] = [None, None]
    threads = [threading.Thread(target=lambda i=i, f=f: out.__setitem__(i, f())) for i, f in
               enumerate((guard(alice, a), guard(bob, b)))]
    with a, b:
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
    return out[0], out[1]


@pytest.fixture
def src(tmp_path: Path) -> Path:
    path = tmp_path / "payload.bin"
    path.write_bytes(os.urandom(SIZE))
    return path


def options(timeout: float = 5.0) -> ResumeOptions:
    return ResumeOptions(TID, timeout=timeout)


def interrupted(out_dir: Path, src: Path, chunks: int, fingerprint: Optional[str]) -> ResumeStore:
    """Leave Bob's disk as an interrupted transfer of src would: the first `chunks` chunks verified."""
    store = ResumeStore(str(out_dir), TID)
    meta = describe_file(str(src), CHUNK, with_sha256=True, resume_offset=0)
    state = store.begin(meta, 0, fingerprint, "hybrid")
    Path(store.part_path).write_bytes(src.read_bytes()[: chunks * CHUNK])
    state.next_chunk = chunks
    store.save(state)
    return store


def alice_side(src: Path, chunk: int = CHUNK, resume: Optional[ResumeOptions] = None):
    return lambda s: alice_negotiate(s.ch, s.key, s.T, s.auth, resume or options(), str(src), chunk, NullReporter())


def bob_side(out_dir: Path, resume: Optional[ResumeOptions] = None, reporter=None):
    return lambda s: bob_negotiate(s.ch, s.key, s.T, s.state, resume or options(), str(out_dir), reporter or NullReporter())


# ── honest negotiation ─────────────────────────────────────────


def test_fresh_transfer_negotiates_offset_zero(keys, src: Path, tmp_path: Path) -> None:
    alice, bob = run_pair(keys, alice_side(src), bob_side(tmp_path / "out"))
    assert alice == (0, None)
    assert (bob.offset, bob.previous, bob.reason) == (0, None, None)


def test_interrupted_transfer_continues_at_the_verified_chunk(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    store = interrupted(out, src, 5, pqc.fingerprint(keys["alice"][0]))
    alice, bob = run_pair(keys, alice_side(src), bob_side(out))
    assert alice == (5, None)
    assert bob.offset == 5 and bob.previous.next_chunk == 5
    assert store.load().next_chunk == 5


def test_everything_already_held_is_a_valid_offset(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 9, pqc.fingerprint(keys["alice"][0]))  # 9 chunks = the whole file
    alice, bob = run_pair(keys, alice_side(src), bob_side(out))
    assert alice == (9, None) and bob.offset == 9


# ── a changed source restarts from zero, with a reason ──────────


def change_prefix(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[10] ^= 0xFF
    path.write_bytes(bytes(data))


def change_tail(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[-5] ^= 0xFF
    path.write_bytes(bytes(data))


def grow(path: Path) -> None:
    path.write_bytes(path.read_bytes() + b"more")


@pytest.mark.parametrize(
    "change, chunk, reason",
    [(change_prefix, CHUNK, REASON_SOURCE_CHANGED), (grow, CHUNK, REASON_FILE_CHANGED),
     (lambda p: None, 500, REASON_CHUNK_SIZE)],
    ids=["prefix_bytes_changed", "file_size_changed", "chunk_size_changed"],
)
def test_changed_source_restarts_from_zero(keys, src: Path, tmp_path: Path, change, chunk: int, reason: str) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 5, pqc.fingerprint(keys["alice"][0]))
    change(src)
    bob_rep, alice_rep = RecordingReporter(), RecordingReporter()
    alice, bob = run_pair(
        keys,
        lambda s: alice_negotiate(s.ch, s.key, s.T, s.auth, options(), str(src), chunk, alice_rep),
        lambda s: bob_negotiate(s.ch, s.key, s.T, s.state, options(), str(out), bob_rep),
    )
    assert alice == (0, reason)
    assert (bob.offset, bob.reason) == (0, reason)
    assert alice_rep.merged()["resume_restart_reason"] == reason
    assert bob_rep.merged()["resume_restart_reason"] == reason


def test_a_changed_tail_after_the_received_prefix_still_resumes(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 5, pqc.fingerprint(keys["alice"][0]))
    change_tail(src)  # the bytes Bob holds are intact; the rest is simply new
    alice, bob = run_pair(keys, alice_side(src), bob_side(out))
    assert alice == (5, None) and bob.offset == 5


# ── identity binding ────────────────────────────────────────────


def test_a_different_peer_identity_is_refused_and_leaves_the_partial_file_alone(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    store = interrupted(out, src, 5, "0000-0000-0000-0000-0000-0000-0000-0000")  # started with another sender
    before = (Path(store.part_path).read_bytes(), Path(store.state_path).read_text())
    alice, bob = run_pair(keys, alice_side(src), bob_side(out))
    assert isinstance(bob, PeerAuthError) and "identity differs" in bob.reason
    assert isinstance(alice, ConnectionError), "Bob asked for nothing and closed"
    assert (Path(store.part_path).read_bytes(), Path(store.state_path).read_text()) == before


# ── tampering aborts before any file data ───────────────────────


def sealed_request(s: Session, **overrides) -> tuple[bytes, dict]:
    request = {"v": 1, "transfer_id": TID, "next_chunk": 0, "chunk_size": None, "meta_digest": None,
               "prefix_sha256": None, "alice_fp": s.state.peer_fingerprint, **overrides}
    blob = seal_resume_message(s.key, "bob", json.dumps(request).encode(), s.T + b"|resume-request")
    return blob, request


def send_blob(s: Session, name: str, blob: bytes) -> None:
    s.ch.send_untracked({name: base64.b64encode(blob).decode()})


def flip(blob: bytes) -> bytes:
    return blob[:-1] + bytes([blob[-1] ^ 1])


def test_tampered_request_is_rejected_by_alice(keys, src: Path) -> None:
    def bob(s: Session):
        blob, _ = sealed_request(s)
        send_blob(s, "resume_request", flip(blob))
        return s.ch.recv_untracked()  # Alice must not answer

    alice, bob_got = run_pair(keys, alice_side(src), bob)
    assert isinstance(alice, PeerAuthError) and "failed authentication" in alice.reason
    assert isinstance(bob_got, ConnectionError)


def test_a_request_replayed_from_another_session_is_rejected(keys, src: Path) -> None:
    captured: list[bytes] = []

    def bob_first(s: Session):
        blob, _ = sealed_request(s)
        captured.append(blob)
        send_blob(s, "resume_request", blob)
        return s.ch.recv_untracked()

    first, _ = run_pair(keys, alice_side(src), bob_first, salt="11" * 16)
    assert first == (0, None)

    def bob_replay(s: Session):
        send_blob(s, "resume_request", captured[0])
        return s.ch.recv_untracked()

    alice, _ = run_pair(keys, alice_side(src), bob_replay, salt="22" * 16)  # another transcript, so another T
    assert isinstance(alice, PeerAuthError) and "failed authentication" in alice.reason


def test_tampered_grant_is_rejected_by_bob(keys, src: Path, tmp_path: Path) -> None:
    def alice(s: Session):
        msg = s.ch.recv_untracked()
        grant = seal_resume_message(s.key, "alice", b'{"offset":0,"reason":null}',
                                    s.T + b"|resume-grant|" + hashlib.sha256(base64.b64decode(msg["resume_request"])).digest())
        send_blob(s, "resume_grant", flip(grant))

    _, bob = run_pair(keys, alice, bob_side(tmp_path / "out"))
    assert isinstance(bob, PeerAuthError) and "failed authentication" in bob.reason


def test_a_grant_for_a_different_request_is_rejected(keys, tmp_path: Path) -> None:
    """The grant is bound to the request it answers, so one cannot be spliced onto another."""

    def alice(s: Session):
        s.ch.recv_untracked()
        other = hashlib.sha256(b"some other request").digest()
        send_blob(s, "resume_grant", seal_resume_message(s.key, "alice", b'{"offset":0,"reason":null}',
                                                         s.T + b"|resume-grant|" + other))

    _, bob = run_pair(keys, alice, bob_side(tmp_path / "out"))
    assert isinstance(bob, PeerAuthError)


def test_a_validly_sealed_but_out_of_range_offset_is_rejected(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 3, pqc.fingerprint(keys["alice"][0]))

    def alice(s: Session):
        msg = s.ch.recv_untracked()
        digest = hashlib.sha256(base64.b64decode(msg["resume_request"])).digest()
        send_blob(s, "resume_grant", seal_resume_message(s.key, "alice", b'{"offset":7,"reason":null}',
                                                         s.T + b"|resume-grant|" + digest))

    _, bob = run_pair(keys, alice, bob_side(out))
    assert isinstance(bob, ResumeError) and "granted an offset" in bob.reason


def test_request_for_another_transfer_is_refused(keys, src: Path) -> None:
    def bob(s: Session):
        blob, _ = sealed_request(s, transfer_id="someone-else")
        send_blob(s, "resume_request", blob)
        return s.ch.recv_untracked()

    alice, _ = run_pair(keys, alice_side(src), bob)
    assert isinstance(alice, ResumeError) and "different transfer" in alice.reason and not alice.resumable


def test_request_addressed_to_another_sender_is_refused(keys, src: Path) -> None:
    def bob(s: Session):
        blob, _ = sealed_request(s, alice_fp="1234-" * 7 + "1234")
        send_blob(s, "resume_request", blob)
        return s.ch.recv_untracked()

    alice, _ = run_pair(keys, alice_side(src), bob)
    assert isinstance(alice, PeerAuthError) and "different sender" in alice.reason


@pytest.mark.parametrize("bad", [-1, "3", None, True, 1.5])
def test_malformed_next_chunk_is_refused(keys, src: Path, bad) -> None:
    def bob(s: Session):
        blob, _ = sealed_request(s, next_chunk=bad)
        send_blob(s, "resume_request", blob)
        return s.ch.recv_untracked()

    alice, _ = run_pair(keys, alice_side(src), bob)
    assert isinstance(alice, ResumeError) and "malformed" in alice.reason


# ── the capability flag ─────────────────────────────────────────


@pytest.mark.parametrize("alice_offers, bob_offers", [(True, True), (True, False), (False, True), (False, False)])
def test_each_side_sees_the_others_offer(keys, alice_offers: bool, bob_offers: bool) -> None:
    alice_peer, bob_peer = run_pair(keys, lambda s: s.peer_offers, lambda s: s.peer_offers,
                                    alice_offers=alice_offers, bob_offers=bob_offers)
    assert (alice_peer, bob_peer) == (bob_offers, alice_offers)


def test_a_missing_or_odd_flag_counts_as_no_offer(keys) -> None:
    from qkd.usecases.handshake import _resume_flag

    assert _resume_flag({"finished": "x", "resume": 1}) is True
    for msg in ({"finished": "x"}, {"finished": "x", "resume": 0}, {"finished": "x", "resume": True},
                {"finished": "x", "resume": "1"}, "resume", None):
        assert _resume_flag(msg) is False


# ── a peer that does not answer ─────────────────────────────────


def test_silent_sender_times_out_with_the_state_intact(keys, tmp_path: Path, src: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 4, pqc.fingerprint(keys["alice"][0]))
    alice_got = []

    def alice(s: Session):
        alice_got.append(s.ch.recv_untracked())  # reads the request, never answers
        import time
        time.sleep(1.0)

    _, bob = run_pair(keys, alice, bob_side(out, options(timeout=0.3)))
    assert isinstance(bob, ResumeError) and bob.resumable
    assert ResumeStore(str(out), TID).load().next_chunk == 4


def test_metadata_instead_of_a_grant_is_not_taken_for_one(keys, tmp_path: Path, src: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 4, pqc.fingerprint(keys["alice"][0]))

    def alice(s: Session):
        s.ch.recv_untracked()
        send_json(s.ch.sock, describe_file(str(src), CHUNK).to_message())  # a sender that ignores the request

    _, bob = run_pair(keys, alice, bob_side(out))
    assert isinstance(bob, ResumeError) and bob.resumable
    assert ResumeStore(str(out), TID).load().next_chunk == 4, "the interrupted state must survive a stripped flag"


def test_silent_receiver_times_out_on_alice(keys, src: Path) -> None:
    def bob(s: Session):
        import time
        time.sleep(1.0)

    alice, _ = run_pair(keys, alice_side(src, resume=options(timeout=0.3)), bob)
    assert isinstance(alice, ResumeError) and alice.resumable


def test_prefix_hash_in_the_request_is_the_hash_of_the_partial_file(keys, src: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    interrupted(out, src, 5, pqc.fingerprint(keys["alice"][0]))
    seen: list[dict] = []

    def alice(s: Session):
        msg = s.ch.recv_untracked()
        seen.append(json.loads(open_resume_message(s.key, "bob", base64.b64decode(msg["resume_request"]),
                                                   s.T + b"|resume-request")))

    run_pair(keys, alice, bob_side(out, options(timeout=0.5)))
    assert seen[0]["prefix_sha256"] == file_sha256(str(src), 5 * CHUNK)
    assert seen[0]["next_chunk"] == 5 and seen[0]["transfer_id"] == TID


# ── the receipt (step 6) ────────────────────────────────────────

DIGEST = hashlib.sha256(b"the file").hexdigest()


def test_receipt_roundtrip(keys) -> None:
    alice, bob = run_pair(keys, lambda s: alice_await_receipt(s.ch, s.key, s.T, DIGEST, 1234),
                          lambda s: bob_send_receipt(s.ch, s.key, s.T, DIGEST, 1234))
    assert alice is None and bob is None


@pytest.mark.parametrize("sha, size", [(hashlib.sha256(b"other").hexdigest(), 1234), (DIGEST, 999)],
                         ids=["other_hash", "other_size"])
def test_a_validly_sealed_receipt_for_another_file_is_not_accepted(keys, sha: str, size: int) -> None:
    alice, _ = run_pair(keys, lambda s: alice_await_receipt(s.ch, s.key, s.T, DIGEST, 1234),
                        lambda s: bob_send_receipt(s.ch, s.key, s.T, sha, size))
    assert isinstance(alice, ResumeError) and "does not match" in alice.reason


def test_a_receipt_that_says_not_received_is_not_accepted(keys) -> None:
    def bob(s: Session) -> None:
        blob = seal_resume_message(s.key, "bob", json.dumps({"received": False, "sha256": DIGEST, "size": 1234}).encode(),
                                   s.T + b"|resume-done")
        send_blob(s, "resume_done", blob)

    alice, _ = run_pair(keys, lambda s: alice_await_receipt(s.ch, s.key, s.T, DIGEST, 1234), bob)
    assert isinstance(alice, ResumeError)


def test_a_receipt_from_another_session_is_rejected(keys) -> None:
    captured: list[Any] = []

    def bob_first(s: Session) -> None:
        bob_send_receipt(s.ch, s.key, s.T, DIGEST, 1234)

    def alice_first(s: Session) -> None:
        captured.append(s.ch.recv_untracked())

    run_pair(keys, alice_first, bob_first, salt="11" * 16)

    def bob_replay(s: Session) -> None:
        s.ch.send_untracked(captured[0])

    alice, _ = run_pair(keys, lambda s: alice_await_receipt(s.ch, s.key, s.T, DIGEST, 1234), bob_replay, salt="22" * 16)
    assert isinstance(alice, PeerAuthError)
