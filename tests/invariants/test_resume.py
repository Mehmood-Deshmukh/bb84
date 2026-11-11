"""
Resumable transfer, exercised with the real Alice/Bob workflows on the Aer simulator (64 qubits).

Every resume is a NEW full session: hello, BB84, key confirmation, then the sealed resume
negotiation (steps 4c/4d), the metadata and the remaining chunks, then Bob's sealed receipt (step 6).
An in-path proxy cuts the connection after k chunks, tampers with single steps, or relays cleanly.
"""

from __future__ import annotations

import base64
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pytest

from qkd.core import pqc
from qkd.core.config import ProtocolParams
from qkd.services.resume import ResumeStore
from qkd.usecases.common import AuthContext, KeyConfirmationError, PeerAuthError, TransferInterrupted
from qkd.usecases.eavesdrop_demo import run_eavesdrop
from qkd.usecases.mitm_demo import AcceptAnyVerifier, run_mitm
from qkd.usecases.receive_file import receive_file
from qkd.usecases.resume import ResumeOptions
from qkd.usecases.send_file import send_file
from qkd.services.reporting import NullReporter
from tests.invariants.support import (
    RESUME_FINAL_STEPS,
    SIGNED_STAGES,
    WIRE_STEPS,
    WIRE_STEPS_RESUME,
    RecordingReporter,
    context,
    guarded,
    keys,  # noqa: F401 (fixture)
    proxy,
)

CHUNK = 1000
SIZE = 11 * CHUNK + 321  # 12 chunks, the last one short
CHUNKS = 12
PARAMS = ProtocolParams(num_qubits=64, chunk_size=CHUNK, enforce_finite_key=False)
TID = "xfer1"
OPTS = ResumeOptions(TID)


class Reporter(RecordingReporter):
    def __init__(self) -> None:
        super().__init__()
        self.warnings: list[str] = []

    def warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class Run:
    alice: Any
    bob: Any
    alice_rep: Reporter
    bob_rep: Reporter


@pytest.fixture
def src(tmp_path: Path) -> Path:
    path = tmp_path / "payload.bin"
    path.write_bytes(os.urandom(SIZE))
    return path


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return tmp_path / "received"


def transfer(
    keys,
    parallel,
    src: Path,
    out: Path,
    *,
    mode: str = "hybrid",
    alice_resume: Optional[ResumeOptions] = OPTS,
    bob_resume: Optional[ResumeOptions] = OPTS,
    chunks: Optional[int] = CHUNKS,
    max_chunks: Optional[int] = None,
    tamper_step: Optional[str] = None,
    tamper=None,
    final: bool = True,
    alice_ctx: Optional[AuthContext] = None,
    bob_ctx: Optional[AuthContext] = None,
) -> Run:
    """One session through the proxy. `chunks` is how many chunk messages Alice will send this session."""
    negotiated = mode != "none" and alice_resume is not None and bob_resume is not None
    if negotiated:
        steps = WIRE_STEPS_RESUME
    elif mode == "none":
        steps = WIRE_STEPS[: [i for i, (step, _) in enumerate(WIRE_STEPS) if step == "4-salt"][0] + 1]  # no finished in none mode
    else:
        steps = WIRE_STEPS
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    with alice_end, proxy_a, proxy_b, bob_end:
        alice, bob, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, PARAMS, alice_ctx or context(keys, "alice", mode),
                                                alice_resume))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out), bob_rep, PARAMS, bob_ctx or context(keys, "bob", mode),
                                                   bob_resume))(bob_end),
            lambda: proxy(proxy_a, proxy_b, steps=steps, chunks=chunks,
                          max_chunks=max_chunks, tamper_step=tamper_step, tamper=tamper,
                          final_steps=RESUME_FINAL_STEPS if (negotiated and final) else None),
        )
    assert alice is not None and bob is not None, "a side never finished: parallel() returns None for a hung thread"
    return Run(alice, bob, alice_rep, bob_rep)


def final_file(out: Path) -> Path:
    return out / "received_payload.bin"


def state_files(out: Path) -> list[str]:
    d = out / ".resume"
    return sorted(os.listdir(d)) if d.exists() else []


def flip(name: str):
    def tamper(msg: dict) -> dict:
        blob = bytearray(base64.b64decode(msg[name]))
        blob[len(blob) // 2] ^= 1
        return {name: base64.b64encode(bytes(blob)).decode()}

    return tamper


def interrupt_after(keys, parallel, src: Path, out: Path, k: int, **kw) -> Run:
    run = transfer(keys, parallel, src, out, max_chunks=k, **kw)
    assert isinstance(run.bob, TransferInterrupted), run.bob
    assert isinstance(run.alice, TransferInterrupted), run.alice
    assert run.bob.bytes_verified == k * CHUNK
    assert not final_file(out).exists(), "a partial file must never appear under the final name"
    return run


# ── honest runs ─────────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["sign", "hybrid"])
def test_resumable_transfer_without_interruption(mode: str, keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, mode=mode)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert final_file(out).read_bytes() == src.read_bytes()
    assert state_files(out) == [], "no partial state is left once the file is complete"
    for rep in (run.alice_rep, run.bob_rep):
        assert rep.stages == SIGNED_STAGES, "negotiation runs inside key_confirmation: no new stage"
        assert rep.merged()["resumed_from_bytes"] == 0 and rep.merged()["bytes_total"] == SIZE
    assert run.bob.resumed_from_bytes == 0


def test_drop_after_k_chunks_then_resume_sends_only_the_rest(keys, parallel, src: Path, out: Path) -> None:
    first = interrupt_after(keys, parallel, src, out, 5)
    assert first.bob_rep.progress_events[-1][0] == 5
    assert state_files(out) == [f"{TID}.json", f"{TID}.part"]
    assert (out / ".resume" / f"{TID}.part").read_bytes() == src.read_bytes()[: 5 * CHUNK]

    second = transfer(keys, parallel, src, out, chunks=CHUNKS - 5)
    assert not isinstance(second.alice, Exception) and not isinstance(second.bob, Exception), (second.alice, second.bob)
    assert final_file(out).read_bytes() == src.read_bytes()
    assert state_files(out) == []
    assert second.bob.resumed_from_bytes == 5 * CHUNK
    for rep in (second.alice_rep, second.bob_rep):
        assert rep.merged()["resumed_from_bytes"] == 5 * CHUNK and rep.merged()["bytes_total"] == SIZE
        assert rep.progress_events[0] == (5, CHUNKS, 5 * CHUNK, SIZE), "progress starts at the offset"
        assert rep.progress_events[-1] == (CHUNKS, CHUNKS, SIZE, SIZE)
        assert len(rep.progress_events) == 1 + (CHUNKS - 5), "only the missing chunks travel"


def test_a_resume_is_a_new_session_with_a_new_key(keys, parallel, src: Path, out: Path, monkeypatch) -> None:
    from qkd.core import crypto_utils
    from qkd.usecases import handshake

    seen: list[tuple[bytes, bytes]] = []
    real = crypto_utils.derive_session_key

    def spy(qkd_key, kem_ss, transcript_hash, mode):
        key = real(qkd_key, kem_ss, transcript_hash, mode)
        seen.append((key, transcript_hash))
        return key

    monkeypatch.setattr(handshake, "derive_session_key", spy)
    interrupt_after(keys, parallel, src, out, 5)
    transfer(keys, parallel, src, out, chunks=CHUNKS - 5)
    keys_used = [k for k, _ in seen]
    assert len(keys_used) == 4 and len(set(keys_used[:2])) == 1 and len(set(keys_used[2:])) == 1
    assert keys_used[0] != keys_used[2], "the resumed session derived its own key"
    assert seen[0][1] != seen[2][1], "and its own transcript (fresh nonces, fresh KEM key)"


def test_resuming_twice(keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 3)
    second = transfer(keys, parallel, src, out, max_chunks=4, chunks=CHUNKS - 3)
    assert isinstance(second.bob, TransferInterrupted) and second.bob.bytes_verified == 7 * CHUNK
    third = transfer(keys, parallel, src, out, chunks=CHUNKS - 7)
    assert not isinstance(third.bob, Exception), third.bob
    assert final_file(out).read_bytes() == src.read_bytes()


# ── the sender never claims success the receiver did not confirm ─


def test_sender_is_not_done_until_the_receiver_confirms(keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, final=False)  # the receipt never reaches Alice
    assert not isinstance(run.bob, Exception), "Bob has the whole file"
    assert isinstance(run.alice, TransferInterrupted)
    assert final_file(out).read_bytes() == src.read_bytes()


def test_tampered_receipt_is_rejected_by_the_sender(keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, tamper_step="6-resume-done", tamper=flip("resume_done"))
    assert isinstance(run.alice, PeerAuthError) and "receipt" in run.alice.reason


# ── tampering aborts before any file data ───────────────────────


def test_tampered_resume_request_aborts_before_any_file_data(keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, tamper_step="4c-resume-request", tamper=flip("resume_request"))
    assert isinstance(run.alice, PeerAuthError) and "failed authentication" in run.alice.reason
    assert isinstance(run.bob, ConnectionError)
    assert run.bob_rep.progress_events == [] and run.alice_rep.progress_events == []
    assert not final_file(out).exists() and state_files(out) == []


def test_tampered_resume_grant_aborts_before_any_file_data(keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, tamper_step="4d-resume-grant", tamper=flip("resume_grant"))
    assert isinstance(run.bob, PeerAuthError) and "failed authentication" in run.bob.reason
    assert run.bob_rep.progress_events == []
    assert not final_file(out).exists() and state_files(out) == []


def test_tampered_metadata_fails_to_decrypt_and_keeps_nothing(keys, parallel, src: Path, out: Path) -> None:
    """The metadata is AES-GCM ciphertext now, so a changed byte fails its tag before any chunk is read."""
    run = transfer(keys, parallel, src, out, tamper_step="5-meta", tamper=lambda raw: raw[:20] + bytes([raw[20] ^ 1]) + raw[21:])
    assert isinstance(run.bob, Exception)
    assert not final_file(out).exists() and not (out / "received_other.bin").exists()
    part = out / ".resume" / f"{TID}.part"
    assert not part.exists() or part.stat().st_size == 0


def test_metadata_with_a_forged_resume_offset_is_refused(keys, parallel, src: Path, out: Path, monkeypatch) -> None:
    """An authenticated sender that streams from another chunk than the one granted is refused."""
    from dataclasses import replace

    import qkd.usecases.send_file as send_module

    interrupt_after(keys, parallel, src, out, 5)
    before = (out / ".resume" / f"{TID}.part").read_bytes()
    real = send_module.send_encrypted_file

    def forged(sock, path, key, meta, on_progress=None, start_chunk=0):
        return real(sock, path, key, replace(meta, resume_offset=2), on_progress, start_chunk=2)

    monkeypatch.setattr(send_module, "send_encrypted_file", forged)
    run = transfer(keys, parallel, src, out, chunks=CHUNKS - 2)
    assert isinstance(run.bob, Exception) and not isinstance(run.bob, TransferInterrupted)
    assert "offset" in str(run.bob)
    assert (out / ".resume" / f"{TID}.part").read_bytes() == before, "the verified prefix survives a forged offset"


# ── binding to the original transfer ───────────────────────────


def test_resume_with_a_different_sender_identity_is_refused(keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 5)
    part = out / ".resume" / f"{TID}.part"
    before = (part.read_bytes(), (out / ".resume" / f"{TID}.json").read_text())

    stranger = pqc.sig_keygen()  # Bob trusts anyone here (TOFU), so the handshake itself succeeds
    bob_ctx = AuthContext("hybrid", *keys["bob"], AcceptAnyVerifier())
    alice_ctx = AuthContext("hybrid", stranger[0], stranger[1], context(keys, "alice", "hybrid").verifier)
    run = transfer(keys, parallel, src, out, alice_ctx=alice_ctx, bob_ctx=bob_ctx, chunks=CHUNKS - 5)

    assert isinstance(run.bob, PeerAuthError) and "identity differs" in run.bob.reason
    assert not isinstance(run.alice, type(None)) and isinstance(run.alice, Exception), "Alice did not complete either"
    assert run.bob_rep.progress_events == []
    assert (part.read_bytes(), (out / ".resume" / f"{TID}.json").read_text()) == before
    assert not final_file(out).exists()


# ── a changed source ───────────────────────────────────────────


def test_changed_prefix_restarts_from_zero_with_an_explicit_event(keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 5)
    data = bytearray(src.read_bytes())
    data[3] ^= 0xFF
    src.write_bytes(bytes(data))

    run = transfer(keys, parallel, src, out, chunks=CHUNKS)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert run.alice_rep.merged()["resume_restart_reason"] == "source_changed"
    assert run.bob_rep.merged()["resume_restart_reason"] == "source_changed"
    assert any("changed" in w for w in run.alice_rep.warnings) and any("beginning" in w for w in run.bob_rep.warnings)
    assert run.bob.resumed_from_bytes == 0
    assert run.bob_rep.progress_events[0][0] == 0
    assert final_file(out).read_bytes() == src.read_bytes(), "the new content, not a mix of old and new"


def test_changed_tail_still_resumes_and_yields_the_new_file(keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 5)
    data = bytearray(src.read_bytes())
    data[-3] ^= 0xFF
    src.write_bytes(bytes(data))

    run = transfer(keys, parallel, src, out, chunks=CHUNKS - 5)
    assert not isinstance(run.bob, Exception), run.bob
    assert run.bob.resumed_from_bytes == 5 * CHUNK
    assert final_file(out).read_bytes() == src.read_bytes()


def test_resized_file_restarts_from_zero(keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 5)
    src.write_bytes(src.read_bytes() + os.urandom(2500))
    run = transfer(keys, parallel, src, out, chunks=CHUNKS + 2)
    assert not isinstance(run.bob, Exception), run.bob
    assert run.alice_rep.merged()["resume_restart_reason"] == "file_changed"
    assert final_file(out).read_bytes() == src.read_bytes()


# ── integrity on the receiving side ────────────────────────────


def test_a_corrupted_chunk_mid_stream_leaves_only_verified_bytes(keys, parallel, src: Path, out: Path) -> None:
    # Relay six chunks cleanly, then corrupt the seventh (index 6) and carry on.
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()

    def corrupting_proxy() -> None:
        from qkd.services import wire as w

        try:
            for _step, direction in WIRE_STEPS_RESUME:
                s, d = (proxy_a, proxy_b) if direction == "A2B" else (proxy_b, proxy_a)
                w.forward_message(s, d)
            for i in range(CHUNKS):
                data = w.recv_bytes(proxy_a)
                if i == 6:
                    data = data[:30] + bytes([data[30] ^ 1]) + data[31:]
                w.send_bytes(proxy_b, data)
        except OSError:
            pass
        finally:
            for sock in (proxy_a, proxy_b):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    with alice_end, proxy_a, proxy_b, bob_end:
        alice, bob, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, PARAMS, context(keys, "alice", "hybrid"), OPTS))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out), bob_rep, PARAMS, context(keys, "bob", "hybrid"), OPTS))(bob_end),
            corrupting_proxy,
        )
    assert isinstance(bob, TransferInterrupted) and bob.bytes_verified == 6 * CHUNK
    assert (out / ".resume" / f"{TID}.part").read_bytes() == src.read_bytes()[: 6 * CHUNK]
    assert ResumeStore(str(out), TID).load().next_chunk == 6
    assert not final_file(out).exists()

    run = transfer(keys, parallel, src, out, chunks=CHUNKS - 6)
    assert not isinstance(run.bob, Exception), run.bob
    assert final_file(out).read_bytes() == src.read_bytes()


# ── capability mismatch and auth none ──────────────────────────


@pytest.mark.parametrize("alice_on, bob_on", [(True, False), (False, True)], ids=["only_alice", "only_bob"])
def test_one_sided_resume_falls_back_to_a_plain_transfer(alice_on: bool, bob_on: bool, keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, alice_resume=OPTS if alice_on else None,
                   bob_resume=OPTS if bob_on else None, chunks=None)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert final_file(out).read_bytes() == src.read_bytes()
    assert state_files(out) == [], "a plain transfer keeps no resume state"
    offering = run.alice_rep if alice_on else run.bob_rep
    assert any("does not offer resume" in w for w in offering.warnings)


def test_resume_is_ignored_without_authentication(keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, mode="none", chunks=None)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert final_file(out).read_bytes() == src.read_bytes()
    assert state_files(out) == []
    for rep in (run.alice_rep, run.bob_rep):
        assert any("auth mode sign or hybrid" in w for w in rep.warnings)
        assert "resumed_from_bytes" not in rep.merged()


# ── Eve and Mallory with resume on ─────────────────────────────

EVE_PARAMS = ProtocolParams(num_qubits=64, chunk_size=CHUNK, qber_sample_fraction=1.0, qber_threshold=0.01, enforce_finite_key=False)


def test_eve_still_ends_in_a_qber_abort_with_resume_on(keys, parallel, src: Path, out: Path) -> None:
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, eve_a = socket.socketpair()
    eve_b, bob_end = socket.socketpair()
    with alice_end, eve_a, eve_b, bob_end:
        sent, got, eve = parallel(
            lambda: send_file(alice_end, str(src), alice_rep, EVE_PARAMS, context(keys, "alice", "hybrid"), OPTS),
            lambda: receive_file(bob_end, str(out), bob_rep, EVE_PARAMS, context(keys, "bob", "hybrid"), OPTS),
            lambda: run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=EVE_PARAMS.qber_threshold),
        )
    assert sent.aborted and got.key_exchange.aborted and eve.aborted
    assert not out.exists()


def eve_then_close(eve_a: socket.socket, eve_b: socket.socket, params: ProtocolParams):
    """run_eavesdrop, then drop both connections like the qkd-eve runner does when it exits."""
    try:
        return run_eavesdrop(eve_a, eve_b, NullReporter(), threshold=params.qber_threshold)
    finally:
        for sock in (eve_a, eve_b):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def test_eve_is_caught_by_key_confirmation_before_the_resume_negotiation(keys, parallel, src: Path, out: Path) -> None:
    """With a threshold that never trips, Eve's relay runs on, but her measurements made the keys differ."""
    lenient = ProtocolParams(num_qubits=64, chunk_size=CHUNK, qber_threshold=1.01, enforce_finite_key=False)
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, eve_a = socket.socketpair()
    eve_b, bob_end = socket.socketpair()
    with alice_end, eve_a, eve_b, bob_end:
        alice, bob, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, lenient, context(keys, "alice", "hybrid"), OPTS))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out), bob_rep, lenient, context(keys, "bob", "hybrid"), OPTS))(bob_end),
            lambda: eve_then_close(eve_a, eve_b, lenient),
        )
    assert alice is not None and bob is not None
    assert isinstance(alice, KeyConfirmationError) and isinstance(bob, Exception), (alice, bob)  # Bob sees the close
    assert alice_rep.stages[-1] == "key_confirmation"
    assert not final_file(out).exists() and state_files(out) == []


def test_mallory_relaying_the_hellos_is_still_caught_at_key_confirmation(keys, parallel, src: Path, out: Path) -> None:
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, mallory_a = socket.socketpair()
    mallory_b, bob_end = socket.socketpair()
    with alice_end, mallory_a, mallory_b, bob_end:
        alice, bob, mitm = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, PARAMS, context(keys, "alice", "hybrid"), OPTS))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out), bob_rep, PARAMS, context(keys, "bob", "hybrid"), OPTS))(bob_end),
            lambda: run_mitm(mallory_a, mallory_b, NullReporter(), PARAMS, "hybrid", "relay_hello"),
        )
    assert alice is not None and bob is not None
    assert isinstance(alice, PeerAuthError) and "signature" in alice.reason
    assert alice_rep.stages[-1] == "key_confirmation", "Alice never reached the resume negotiation or any file data"
    assert not mitm.relayed and not out.exists()


# ── the resume flag is signed ───────────────────────────────────


def _strip_flag(msg: dict) -> dict:
    return {k: v for k, v in msg.items() if k != "resume"}


def _add_flag(msg: dict) -> dict:
    return {**msg, "resume": 1}


@pytest.mark.parametrize("step", ["4b-bob", "4b-alice"])
def test_stripping_the_resume_flag_fails_the_finished_signature(step: str, keys, parallel, src: Path, out: Path) -> None:
    interrupt_after(keys, parallel, src, out, 6)
    run = transfer(keys, parallel, src, out, tamper_step=step, tamper=_strip_flag)
    victim = run.alice if step == "4b-bob" else run.bob
    assert isinstance(victim, PeerAuthError), victim
    assert isinstance(run.alice, Exception) and isinstance(run.bob, Exception), "no side may report success"
    assert not final_file(out).exists()
    assert ResumeStore(str(out), TID).load().next_chunk == 6, "the interrupted state must survive"


@pytest.mark.parametrize("step, alice_on, bob_on", [("4b-bob", True, False), ("4b-alice", False, True)])
def test_adding_the_resume_flag_fails_the_finished_signature(step: str, alice_on: bool, bob_on: bool,
                                                             keys, parallel, src: Path, out: Path) -> None:
    run = transfer(keys, parallel, src, out, alice_resume=OPTS if alice_on else None,
                   bob_resume=OPTS if bob_on else None, chunks=None, tamper_step=step, tamper=_add_flag)
    victim = run.alice if step == "4b-bob" else run.bob
    assert isinstance(victim, PeerAuthError), victim
    assert not final_file(out).exists()


def test_the_plain_finished_signature_is_unchanged_without_the_flag() -> None:
    from qkd.usecases.handshake import FINISHED_PREFIX, RESUME_SUFFIX, finished_message

    t, tag = b"\x01" * 32, b"\x02" * 32
    assert finished_message(b"bob", t, tag) == FINISHED_PREFIX + b"bob|" + t + tag
    assert finished_message(b"bob", t, tag, True) == finished_message(b"bob", t, tag) + RESUME_SUFFIX


# ── a peer that goes silent without closing the connection ──────


def _stalling_run(keys, parallel, src: Path, out: Path, relay_chunks: int, forward_receipt: bool = False) -> Run:
    """Like transfer(), but after relay_chunks chunks the proxy stops forwarding and keeps both connections open."""
    import threading

    from qkd.services import wire

    opts = ResumeOptions(TID, stall_timeout=0.5)
    done = threading.Event()
    alice_rep, bob_rep = Reporter(), Reporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()

    def silent_proxy() -> None:
        try:
            for _, direction in WIRE_STEPS_RESUME:
                src_sock, dst_sock = (proxy_a, proxy_b) if direction == "A2B" else (proxy_b, proxy_a)
                wire.forward_message(src_sock, dst_sock)
            for _ in range(relay_chunks):
                wire.forward_message(proxy_a, proxy_b)
            if forward_receipt:
                wire.forward_message(proxy_b, proxy_a)
        except (ConnectionError, OSError):
            pass
        done.wait(20)  # hold both connections open and silent: no FIN, no RST

    def side(fn):
        def run():
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - asserted on by the caller
                return exc
        return run

    def both() -> tuple[Any, Any]:
        try:
            a, b = parallel(
                side(lambda: send_file(alice_end, str(src), alice_rep, PARAMS, context(keys, "alice", "hybrid"), opts)),
                side(lambda: receive_file(bob_end, str(out), bob_rep, PARAMS, context(keys, "bob", "hybrid"), opts)),
            )
            return a, b
        finally:
            done.set()

    with alice_end, proxy_a, proxy_b, bob_end:
        (alice, bob), _ = parallel(both, silent_proxy)
    assert alice is not None and bob is not None, "a side hung: the stall timeout did not fire"
    return Run(alice, bob, alice_rep, bob_rep)


def test_a_silent_network_mid_stream_interrupts_both_sides_and_can_be_resumed(keys, parallel, src: Path, out: Path) -> None:
    run = _stalling_run(keys, parallel, src, out, relay_chunks=5)
    assert isinstance(run.bob, TransferInterrupted), run.bob
    assert isinstance(run.alice, TransferInterrupted), run.alice
    assert run.bob.bytes_verified == 5 * CHUNK
    assert not final_file(out).exists()
    assert ResumeStore(str(out), TID).load().next_chunk == 5

    run = transfer(keys, parallel, src, out, chunks=CHUNKS - 5)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert final_file(out).read_bytes() == src.read_bytes()


def test_a_swallowed_receipt_interrupts_the_sender_instead_of_hanging(keys, parallel, src: Path, out: Path) -> None:
    run = _stalling_run(keys, parallel, src, out, relay_chunks=CHUNKS)
    assert not isinstance(run.bob, Exception), run.bob
    assert final_file(out).read_bytes() == src.read_bytes()
    assert isinstance(run.alice, TransferInterrupted), run.alice
    assert "silent" in run.alice.reason


def test_the_stall_timeout_does_not_disturb_an_honest_transfer(keys, parallel, src: Path, out: Path) -> None:
    run = _stalling_run(keys, parallel, src, out, relay_chunks=CHUNKS, forward_receipt=True)
    assert not isinstance(run.alice, Exception) and not isinstance(run.bob, Exception), (run.alice, run.bob)
    assert final_file(out).read_bytes() == src.read_bytes()
