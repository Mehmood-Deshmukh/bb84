"""
Receiver-side state for resumable transfers.

Bob keeps, per transfer id, under <output_dir>/.resume/:

    <id>.part   bytes that passed AES-GCM, in order, and nothing else
    <id>.json   sidecar: what the .part is a prefix of, and how far it goes

The state is keyed by transfer id (not file name) because Bob has to find it before the
metadata message arrives. The final file `received_<name>` is created only by an atomic
rename after every chunk verified, the size matches and the SHA-256 of the whole file
equals the one in the AAD-bound metadata. Nothing here imports qiskit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Optional

from qkd.core.config import RESUME_SYNC_CHUNKS
from qkd.core.crypto_utils import decrypt_chunk, derive_chunk_nonce
from qkd.services.file_stream import MAX_CHUNKS, TAG_SIZE, FileMeta, ProgressCallback, file_sha256, received_path
from qkd.services.wire import recv_bytes

STATE_DIRNAME = ".resume"
SIDECAR_VERSION = 1
TRANSFER_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class ResumeError(Exception):
    """
    A resume cannot continue (inconsistent metadata, state, or whole-file hash). `reason` is for humans.

    resumable is True when the interrupted state is intact and a later attempt may succeed
    (for example the peer never answered the resume request); False when this transfer is broken.
    """

    def __init__(self, reason: str, resumable: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.resumable = resumable


def meta_digest(filename: str, total_size: int) -> str:
    """SHA-256 (hex) of the canonical JSON of the two fields that identify the original file."""
    canonical = json.dumps({"filename": filename, "total_size": total_size}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def chunk_boundary(chunks: int, chunk_size: int, total_size: int) -> int:
    """Byte offset after the first `chunks` chunks."""
    return min(chunks * chunk_size, total_size)


def validate_meta(meta: FileMeta) -> None:
    """Reject metadata a resumable receive cannot trust (raises ResumeError)."""
    if meta.chunk_size <= 0 or meta.total_size < 0:
        raise ResumeError("metadata has a non-positive chunk size or a negative size")
    if meta.num_chunks != (meta.total_size + meta.chunk_size - 1) // meta.chunk_size:
        raise ResumeError("metadata num_chunks does not match total_size and chunk_size")
    if meta.num_chunks > MAX_CHUNKS:
        raise ResumeError("metadata has more chunks than the nonce counter allows")
    if len(meta.base_nonce) != 8:
        raise ResumeError("metadata base_nonce must be 8 bytes")
    if not isinstance(meta.sha256, str) or not _SHA256_HEX.match(meta.sha256):
        raise ResumeError("metadata lacks the SHA-256 of the whole file")
    if not isinstance(meta.resume_offset, int) or not 0 <= meta.resume_offset <= meta.num_chunks:
        raise ResumeError("metadata resume_offset is out of range")


@dataclass
class ResumeState:
    """The sidecar. `next_chunk` chunks are verified and on disk in the .part."""

    transfer_id: str
    filename: str
    total_size: int
    chunk_size: int
    num_chunks: int
    meta_digest: str
    next_chunk: int
    base_nonce: str  # hex; the base nonce of the session that wrote the .part last
    peer_fingerprint: Optional[str]
    auth_mode: str
    version: int = SIDECAR_VERSION

    @property
    def next_byte(self) -> int:
        return chunk_boundary(self.next_chunk, self.chunk_size, self.total_size)


def _valid_state(raw: object, transfer_id: str) -> Optional[ResumeState]:
    if not isinstance(raw, dict) or raw.get("version") != SIDECAR_VERSION or raw.get("transfer_id") != transfer_id:
        return None
    try:
        state = ResumeState(**raw)
    except TypeError:
        return None
    ints = (state.total_size, state.chunk_size, state.num_chunks, state.next_chunk)
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in ints):
        return None
    if not (isinstance(state.filename, str) and isinstance(state.meta_digest, str)
            and isinstance(state.base_nonce, str) and isinstance(state.auth_mode, str)):
        return None
    if state.peer_fingerprint is not None and not isinstance(state.peer_fingerprint, str):
        return None
    if state.chunk_size <= 0 or state.total_size < 0 or state.num_chunks > MAX_CHUNKS:
        return None
    if state.num_chunks != (state.total_size + state.chunk_size - 1) // state.chunk_size:
        return None
    if not 0 <= state.next_chunk <= state.num_chunks:
        return None
    if state.meta_digest != meta_digest(state.filename, state.total_size):
        return None
    return state


class ResumeStore:
    """The .part and sidecar of one transfer."""

    def __init__(self, output_dir: str, transfer_id: str) -> None:
        if not TRANSFER_ID.match(transfer_id or ""):
            raise ValueError(f"Invalid transfer id for resume: {transfer_id!r}")
        self.output_dir = output_dir
        self.transfer_id = transfer_id
        self.dir = os.path.join(output_dir, STATE_DIRNAME)
        self.part_path = os.path.join(self.dir, f"{transfer_id}.part")
        self.state_path = os.path.join(self.dir, f"{transfer_id}.json")

    # ── sidecar ────────────────────────────────────────────────

    def load(self) -> Optional[ResumeState]:
        """The recorded state, or None if there is none or it is unreadable (then start fresh)."""
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                return _valid_state(json.load(f), self.transfer_id)
        except (OSError, ValueError):
            return None

    def save(self, state: ResumeState) -> None:
        """Write the sidecar atomically: temp file, fsync, rename."""
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        _fsync_dir(self.dir)

    def discard(self) -> None:
        """Delete the .part and the sidecar."""
        for path in (self.part_path, self.state_path, self.state_path + ".tmp"):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    # ── the .part ──────────────────────────────────────────────

    def recover(self, state: ResumeState) -> int:
        """
        Make the .part agree with the sidecar and return how many chunks it really holds.

        Bytes beyond the sidecar's next_chunk are dropped (they were verified but not recorded).
        If the .part is shorter than the sidecar says, the count drops to the chunks it still has.
        """
        try:
            size = os.path.getsize(self.part_path)
        except OSError:
            size = 0
        held = min(state.next_chunk, size // state.chunk_size)
        if state.next_chunk >= state.num_chunks and size >= state.total_size:
            held = state.num_chunks
        boundary = chunk_boundary(held, state.chunk_size, state.total_size)
        if size != boundary:
            _truncate(self.part_path, boundary)
        if held != state.next_chunk:
            state.next_chunk = held
            self.save(state)
        return held

    def prefix_sha256(self, nbytes: int) -> str:
        """SHA-256 (hex) of the first nbytes of the .part."""
        return file_sha256(self.part_path, nbytes) if nbytes else hashlib.sha256(b"").hexdigest()

    def begin(
        self,
        meta: FileMeta,
        start_chunk: int,
        peer_fingerprint: Optional[str],
        auth_mode: str,
        previous: Optional[ResumeState] = None,
    ) -> ResumeState:
        """
        Record that a session starts writing this file at start_chunk, and cut the .part to that point.

        start_chunk > 0 continues `previous`, which must describe the same file, and the session
        must use a base nonce different from the one it continues. start_chunk == 0 starts over.
        """
        validate_meta(meta)
        digest = meta_digest(meta.filename, meta.total_size)
        if start_chunk > 0:
            if previous is None or previous.meta_digest != digest or previous.chunk_size != meta.chunk_size:
                raise ResumeError("cannot resume: the metadata does not describe the interrupted file")
            if start_chunk > previous.next_chunk:
                raise ResumeError("cannot resume: the sender starts beyond the verified data")
            if previous.base_nonce == meta.base_nonce.hex():
                raise ResumeError("cannot resume: the sender reused the base nonce of the interrupted session")
        state = ResumeState(
            transfer_id=self.transfer_id,
            filename=meta.filename,
            total_size=meta.total_size,
            chunk_size=meta.chunk_size,
            num_chunks=meta.num_chunks,
            meta_digest=digest,
            next_chunk=start_chunk,
            base_nonce=meta.base_nonce.hex(),
            peer_fingerprint=peer_fingerprint,
            auth_mode=auth_mode,
        )
        os.makedirs(self.dir, exist_ok=True)
        boundary = chunk_boundary(start_chunk, meta.chunk_size, meta.total_size)
        _truncate(self.part_path, boundary)
        if os.path.getsize(self.part_path) != boundary:  # shorter than the resume point: writing on would leave a hole
            raise ResumeError("cannot resume: the partial file is shorter than the resume point")
        self.save(state)
        return state


def receive_encrypted_file_resumable(
    sock,
    meta: FileMeta,
    store: ResumeStore,
    state: ResumeState,
    aes_key: bytes,
    start_chunk: int,
    on_progress: Optional[ProgressCallback] = None,
    sync_every: int = RESUME_SYNC_CHUNKS,
) -> int:
    """
    Receive chunks start_chunk..num_chunks-1 into the store's .part and finish the file. Returns its size.

    `state` comes from store.begin(). Only chunks that passed AES-GCM (and have the expected length) are
    written. On any error, including InvalidTag and a dropped connection, the .part is cut to the last
    verified chunk boundary, the sidecar records it, and the error is re-raised, so a caller can resume.
    The final file appears only after the size and the whole-file SHA-256 check out; a mismatch there
    discards the state (the data is bad) and raises ResumeError.
    """
    sync_every = max(1, sync_every)
    verified = start_chunk
    since_sync = 0
    with open(store.part_path, "r+b") as f:
        f.seek(chunk_boundary(start_chunk, meta.chunk_size, meta.total_size))
        try:
            for i in range(start_chunk, meta.num_chunks):
                data = recv_bytes(sock)
                tag, ciphertext = data[:TAG_SIZE], data[TAG_SIZE:]
                plaintext = decrypt_chunk(ciphertext, aes_key, derive_chunk_nonce(meta.base_nonce, i), tag, meta.aad)
                if len(plaintext) != chunk_boundary(i + 1, meta.chunk_size, meta.total_size) - chunk_boundary(i, meta.chunk_size, meta.total_size):
                    raise ResumeError(f"chunk {i} has the wrong length")
                f.write(plaintext)
                verified = i + 1
                since_sync += 1
                if since_sync >= sync_every:
                    f.flush()
                    os.fsync(f.fileno())
                    state.next_chunk = verified
                    store.save(state)
                    since_sync = 0
                if on_progress:
                    on_progress(verified, meta.num_chunks, chunk_boundary(verified, meta.chunk_size, meta.total_size))
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            try:
                f.flush()
                f.truncate(chunk_boundary(verified, meta.chunk_size, meta.total_size))
                os.fsync(f.fileno())
                state.next_chunk = verified
                store.save(state)
            except OSError:
                pass
            raise

    state.next_chunk = meta.num_chunks
    store.save(state)
    if os.path.getsize(store.part_path) != meta.total_size:
        store.discard()
        raise ResumeError("received size does not match the metadata")
    if file_sha256(store.part_path) != meta.sha256:
        store.discard()
        raise ResumeError("SHA-256 of the received file does not match the sender's")
    os.makedirs(store.output_dir, exist_ok=True)
    os.replace(store.part_path, received_path(store.output_dir, meta.filename))
    _fsync_dir(store.output_dir)
    store.discard()
    return meta.total_size


def _truncate(path: str, size: int) -> None:
    """Create the file if needed and cut it to at most `size` bytes. It is never extended."""
    with open(path, "ab"):
        pass
    if os.path.getsize(path) > size:
        with open(path, "r+b") as f:
            f.truncate(size)
            f.flush()
            os.fsync(f.fileno())


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
