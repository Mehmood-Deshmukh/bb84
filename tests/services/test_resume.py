"""
Resumable receive: the .part/sidecar store and the offset-aware chunk stream.

No qiskit here. Each session uses a fresh key and a fresh base nonce, exactly as a resume
(a new full handshake) does in the real protocol.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest
from cryptography.exceptions import InvalidTag

from qkd.core.crypto_utils import derive_chunk_nonce, derive_session_key, encrypt_chunk
from qkd.services import file_stream, resume as resume_module, wire
from qkd.services.file_stream import (
    FileMeta,
    describe_file,
    file_sha256,
    metadata_aad,
    receive_file_meta,
    received_path,
    send_encrypted_file,
)
from qkd.services.resume import (
    ResumeError,
    ResumeStore,
    meta_digest,
    receive_encrypted_file_resumable,
    validate_meta,
)

CHUNK = 1000
SIZE = 9 * CHUNK + 123  # 10 chunks, the last one short
FP = "aaaa-bbbb"


def session_key() -> bytes:
    return derive_session_key(os.urandom(32), None, os.urandom(32), "sign")


@pytest.fixture
def src(tmp_path: Path) -> Path:
    path = tmp_path / "payload.bin"
    path.write_bytes(os.urandom(SIZE))
    return path


@pytest.fixture
def store(tmp_path: Path) -> ResumeStore:
    return ResumeStore(str(tmp_path / "out"), "t1")


def run_session(
    src: Path,
    store: ResumeStore,
    *,
    start_chunk: int = 0,
    forward: Optional[int] = None,
    flip_chunk: Optional[int] = None,
    key: Optional[bytes] = None,
    sync_every: int = 8,
    meta_edit=None,
    progress: Optional[list] = None,
):
    """
    One session through a relay. forward=k relays only k chunks and then drops the connection;
    flip_chunk flips a bit in that (absolute) chunk. Returns the received size or raises like the receiver.
    """
    key = key or session_key()
    meta = describe_file(str(src), CHUNK, with_sha256=True, resume_offset=start_chunk)
    if meta_edit:
        meta = meta_edit(meta)
    sender, relay_in = socket.socketpair()
    relay_out, receiver = socket.socketpair()
    remaining = meta.num_chunks - start_chunk
    count = remaining if forward is None else forward

    def send() -> None:
        try:
            send_encrypted_file(sender, str(src), key, meta, start_chunk=start_chunk)
        except OSError:
            pass  # the relay dropped the connection

    def relay() -> None:
        try:
            wire.forward_message(relay_in, relay_out)
            for k in range(count):
                data = wire.recv_bytes(relay_in)
                if flip_chunk == start_chunk + k:
                    data = data[:20] + bytes([data[20] ^ 1]) + data[21:]
                wire.send_bytes(relay_out, data)
        except OSError:
            pass
        finally:
            for s in (relay_in, relay_out):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    threads = [threading.Thread(target=send), threading.Thread(target=relay)]
    for t in threads:
        t.start()
    try:
        got = receive_file_meta(receiver)
        previous = store.load()
        state = store.begin(got, start_chunk, FP, "sign", previous)
        return receive_encrypted_file_resumable(
            receiver, got, store, state, key, start_chunk,
            on_progress=(lambda *a: progress.append(a)) if progress is not None else None,
            sync_every=sync_every,
        )
    finally:
        for t in threads:
            t.join(10)
        for s in (sender, relay_in, relay_out, receiver):
            s.close()


def final(store: ResumeStore, src: Path) -> str:
    return received_path(store.output_dir, src.name)


def resume_point(store: ResumeStore) -> int:
    """What Bob would request: the chunks the recovered .part really holds."""
    state = store.load()
    assert state is not None
    return store.recover(state)


# ── the happy paths ─────────────────────────────────────────────


def test_uninterrupted_transfer_leaves_only_the_final_file(src: Path, store: ResumeStore) -> None:
    assert run_session(src, store) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()
    assert not os.path.exists(store.part_path) and not os.path.exists(store.state_path)


def test_drop_after_k_chunks_then_resume_is_byte_identical(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    assert not os.path.exists(final(store, src)), "a partial file must never appear under the final name"
    assert Path(store.part_path).read_bytes() == src.read_bytes()[: 4 * CHUNK]
    assert store.load().next_chunk == 4

    offset = resume_point(store)
    assert offset == 4
    assert run_session(src, store, start_chunk=offset) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()
    assert not os.path.exists(store.part_path) and not os.path.exists(store.state_path)


def test_resume_several_times(src: Path, store: ResumeStore) -> None:
    done = 0
    for step, expected in ((2, 2), (3, 5), (1, 6)):
        with pytest.raises(ConnectionError):
            run_session(src, store, start_chunk=done, forward=step)
        done = resume_point(store)
        assert done == expected
    assert run_session(src, store, start_chunk=done) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()


def test_progress_starts_at_the_offset(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=3)
    events: list = []
    run_session(src, store, start_chunk=3, progress=events)
    assert events[0] == (4, 10, 4 * CHUNK)
    assert events[-1] == (10, 10, SIZE)


def test_crash_after_the_last_chunk_resumes_with_nothing_to_send(src: Path, store: ResumeStore) -> None:
    """All chunks were verified and written, but the process died before the final check and rename."""
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    state = store.load()
    Path(store.part_path).write_bytes(src.read_bytes())
    state.next_chunk = state.num_chunks
    store.save(state)

    assert resume_point(store) == 10
    events: list = []
    assert run_session(src, store, start_chunk=10, progress=events) == SIZE
    assert events == [], "no chunk is sent or reported"
    assert Path(final(store, src)).read_bytes() == src.read_bytes()


def test_corrupted_prefix_on_disk_is_caught_by_the_whole_file_hash(src: Path, store: ResumeStore) -> None:
    """Disk corruption between sessions: the chunks verified once, the file as a whole must still check out."""
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    with open(store.part_path, "r+b") as f:
        f.write(b"\x00\x01\x02")
    with pytest.raises(ResumeError, match="SHA-256"):
        run_session(src, store, start_chunk=resume_point(store))
    assert not os.path.exists(final(store, src))
    assert not os.path.exists(store.part_path)


# ── integrity: only verified bytes stay on disk ─────────────────


def test_invalid_tag_mid_stream_leaves_only_verified_bytes(src: Path, store: ResumeStore) -> None:
    with pytest.raises(InvalidTag):
        run_session(src, store, flip_chunk=6, sync_every=100)  # no periodic sync: the error path must flush
    assert not os.path.exists(final(store, src))
    assert Path(store.part_path).read_bytes() == src.read_bytes()[: 6 * CHUNK]
    assert store.load().next_chunk == 6
    # and the verified prefix is usable
    assert run_session(src, store, start_chunk=resume_point(store)) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()


def test_flipped_first_chunk_leaves_nothing_verified(src: Path, store: ResumeStore) -> None:
    with pytest.raises(InvalidTag):
        run_session(src, store, flip_chunk=0)
    assert os.path.getsize(store.part_path) == 0
    assert not os.path.exists(final(store, src))


def test_stream_cut_one_chunk_short_never_completes(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=9)
    assert not os.path.exists(final(store, src))
    assert store.load().next_chunk == 9
    assert os.path.getsize(store.part_path) == 9 * CHUNK


def test_whole_file_hash_mismatch_discards_everything(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ResumeError, match="SHA-256"):
        run_session(src, store, meta_edit=lambda m: replace(m, sha256="0" * 64))
    assert not os.path.exists(final(store, src))
    assert not os.path.exists(store.part_path) and not os.path.exists(store.state_path)


def test_metadata_claiming_a_different_size_is_rejected_before_streaming(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ResumeError, match="num_chunks"):
        run_session(src, store, meta_edit=lambda m: replace(m, total_size=m.total_size + CHUNK))
    assert not os.path.exists(final(store, src))


def test_authenticated_chunk_of_the_wrong_length_is_rejected(tmp_path: Path) -> None:
    """A chunk can pass its tag and still contradict the metadata (buggy or malicious sender)."""
    store = ResumeStore(str(tmp_path / "out"), "t2")
    body = os.urandom(2 * CHUNK)
    meta = FileMeta("w.bin", 2 * CHUNK, CHUNK, 2, os.urandom(8), sha256=__import__("hashlib").sha256(body).hexdigest(),
                    resume_offset=0)
    msg = meta.to_message()
    key = session_key()
    sender, receiver = socket.socketpair()
    receiver.settimeout(5)  # if the length check regresses the receiver would wait for chunk 1 forever
    with sender, receiver:
        wire.send_json(sender, msg)
        short, tag = encrypt_chunk(body[: CHUNK - 100], key, derive_chunk_nonce(meta.base_nonce, 0), metadata_aad(msg))
        wire.send_bytes(sender, tag + short)
        got = receive_file_meta(receiver)
        state = store.begin(got, 0, FP, "sign")
        with pytest.raises(ResumeError, match="wrong length"):
            receive_encrypted_file_resumable(receiver, got, store, state, key, 0)
    assert os.path.getsize(store.part_path) == 0
    assert not os.path.exists(received_path(store.output_dir, "w.bin"))


def test_torn_write_is_cut_back_to_the_last_verified_chunk(src: Path, store: ResumeStore, monkeypatch) -> None:
    """The disk fills up half way through a chunk: only whole verified chunks may remain."""
    real_open = open

    class Torn:
        def __init__(self, f) -> None:
            self.f, self.writes = f, 0

        def write(self, data: bytes) -> int:
            self.writes += 1
            if self.writes == 4:  # the fourth chunk is written only in part
                self.f.write(data[: len(data) // 2])
                raise OSError("No space left on device")
            return self.f.write(data)

        def __getattr__(self, name):
            return getattr(self.f, name)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            self.f.close()

    def fake_open(path, mode="r", *a, **kw):
        f = real_open(path, mode, *a, **kw)
        return Torn(f) if str(path).endswith(".part") and "r+" in mode else f

    monkeypatch.setattr(resume_module, "open", fake_open, raising=False)
    with pytest.raises(OSError, match="No space"):
        run_session(src, store)
    monkeypatch.undo()
    assert Path(store.part_path).read_bytes() == src.read_bytes()[: 3 * CHUNK]
    assert store.load().next_chunk == 3
    assert run_session(src, store, start_chunk=resume_point(store)) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()


# ── the store ───────────────────────────────────────────────────


def test_recover_drops_bytes_beyond_the_sidecar(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    with open(store.part_path, "ab") as f:
        f.write(b"verified-but-unrecorded or torn")
    assert resume_point(store) == 4
    assert Path(store.part_path).read_bytes() == src.read_bytes()[: 4 * CHUNK]


def test_recover_lowers_the_offset_when_the_part_is_short(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    with open(store.part_path, "r+b") as f:
        f.truncate(2 * CHUNK + 17)
    assert resume_point(store) == 2
    assert os.path.getsize(store.part_path) == 2 * CHUNK
    assert store.load().next_chunk == 2


def test_begin_refuses_to_continue_past_a_short_part(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    with open(store.part_path, "r+b") as f:
        f.truncate(CHUNK)
    meta = describe_file(str(src), CHUNK, with_sha256=True, resume_offset=4)
    with pytest.raises(ResumeError, match="shorter"):
        store.begin(meta, 4, FP, "sign", store.load())


def test_prefix_hash_matches_the_source(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    assert store.prefix_sha256(4 * CHUNK) == file_sha256(str(src), 4 * CHUNK)
    assert store.prefix_sha256(0) == file_sha256(str(src), 0)


def test_equal_base_nonce_is_refused_on_resume(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    previous = store.load()
    same = replace(describe_file(str(src), CHUNK, with_sha256=True, resume_offset=4),
                   base_nonce=bytes.fromhex(previous.base_nonce))
    with pytest.raises(ResumeError, match="base nonce"):
        store.begin(same, 4, FP, "sign", previous)


def test_resume_of_a_different_file_is_refused(src: Path, store: ResumeStore, tmp_path: Path) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    other = tmp_path / "other.bin"
    other.write_bytes(os.urandom(SIZE))
    meta = describe_file(str(other), CHUNK, with_sha256=True, resume_offset=4)
    with pytest.raises(ResumeError, match="does not describe"):
        store.begin(meta, 4, FP, "sign", store.load())


def test_restart_from_zero_discards_the_old_part(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    assert run_session(src, store, start_chunk=0) == SIZE
    assert Path(final(store, src)).read_bytes() == src.read_bytes()


def test_unreadable_or_foreign_sidecars_are_ignored(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4)
    good = json.loads(Path(store.state_path).read_text())

    def write(data) -> None:
        Path(store.state_path).write_text(data if isinstance(data, str) else json.dumps(data))

    for bad in ("not json", "[]", {**good, "transfer_id": "other"}, {**good, "version": 99},
                {**good, "next_chunk": 999}, {**good, "chunk_size": 0}, {**good, "meta_digest": "x"},
                {**good, "next_chunk": "4"}, {k: v for k, v in good.items() if k != "auth_mode"}):
        write(bad)
        assert store.load() is None, bad
    write(good)
    assert store.load().next_chunk == 4


def test_save_is_atomic_and_leaves_no_temp_file(src: Path, store: ResumeStore) -> None:
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=2)
    assert sorted(os.listdir(store.dir)) == [f"{store.transfer_id}.json", f"{store.transfer_id}.part"]


@pytest.mark.parametrize("bad_id", ["", "../x", "a/b", "a b", "x" * 65])
def test_transfer_ids_that_are_not_safe_file_names_are_rejected(tmp_path: Path, bad_id: str) -> None:
    with pytest.raises(ValueError):
        ResumeStore(str(tmp_path), bad_id)


def test_validate_meta_rules(src: Path) -> None:
    good = describe_file(str(src), CHUNK, with_sha256=True, resume_offset=0)
    validate_meta(good)
    for bad in (replace(good, sha256=None), replace(good, sha256="xyz"), replace(good, resume_offset=None),
                replace(good, resume_offset=11), replace(good, resume_offset=-1),
                replace(good, num_chunks=9), replace(good, chunk_size=0), replace(good, base_nonce=b"\0" * 7)):
        with pytest.raises(ResumeError):
            validate_meta(bad)


# ── metadata and offsets ────────────────────────────────────────


def test_metadata_without_resume_fields_is_unchanged(src: Path) -> None:
    assert set(describe_file(str(src), CHUNK).to_message()) == {"filename", "total_size", "chunk_size", "num_chunks", "base_nonce"}
    full = describe_file(str(src), CHUNK, with_sha256=True, resume_offset=3).to_message()
    assert full["sha256"] == file_sha256(str(src)) and full["resume_offset"] == 3


def test_start_chunk_is_checked(src: Path) -> None:
    meta = describe_file(str(src), CHUNK, resume_offset=2)
    a, b = socket.socketpair()
    with a, b:
        for bad in (-1, 11, 3):  # 3 disagrees with the metadata's resume_offset
            with pytest.raises(ValueError):
                send_encrypted_file(a, str(src), session_key(), meta, start_chunk=bad)


def test_chunk_counter_overflow_is_refused(src: Path, monkeypatch) -> None:
    monkeypatch.setattr(os.path, "getsize", lambda _p: 2**32 + 1)
    with pytest.raises(ValueError, match="chunks"):
        describe_file(str(src), chunk_size=1)


# ── no (key, nonce) pair is used twice across a resume ──────────


def test_original_and_resumed_sessions_never_share_a_key_nonce_pair(src: Path, store: ResumeStore, monkeypatch) -> None:
    used: list[tuple[bytes, bytes]] = []
    real = file_stream.encrypt_chunk

    def spy(plaintext, key, nonce, aad=None):
        used.append((key, nonce))
        return real(plaintext, key, nonce, aad)

    monkeypatch.setattr(file_stream, "encrypt_chunk", spy)
    key1, key2 = session_key(), session_key()
    with pytest.raises(ConnectionError):
        run_session(src, store, forward=4, key=key1)
    original = [p for p in used]
    used.clear()
    run_session(src, store, start_chunk=resume_point(store), key=key2)
    resumed = list(used)

    assert len(set(original)) == len(original) and len(set(resumed)) == len(resumed)
    assert not set(original) & set(resumed)
    # even ignoring the key, the nonces differ: a fresh base nonce per session
    assert not {n for _, n in original} & {n for _, n in resumed}
    assert {k for k, _ in original} == {key1} and {k for k, _ in resumed} == {key2}
    # counters continue where the verified data ends and never go back
    assert [int.from_bytes(n[8:], "big") for _, n in resumed] == list(range(4, 10))


def test_every_session_draws_a_fresh_base_nonce(src: Path) -> None:
    nonces = {describe_file(str(src), CHUNK).base_nonce for _ in range(200)}
    assert len(nonces) == 200


def test_meta_digest_depends_on_name_and_size() -> None:
    assert meta_digest("a", 1) != meta_digest("a", 2) != meta_digest("b", 2)
    assert meta_digest("a", 1) == meta_digest("a", 1)
