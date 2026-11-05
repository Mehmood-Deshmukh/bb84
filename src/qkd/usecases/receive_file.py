"""
Bob's workflow: authenticate Alice, measure her qubits, finish the BB84 key
exchange, confirm the transcript, then receive and decrypt the chunked file.
Message order matches send_file.py.

With resume on (auth sign or hybrid) the data goes to a .part under <output_dir>/.resume/ instead
of straight to the final name; see services/resume.py and usecases/resume.py.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from qkd.core.bb84_protocol import discard_indices, generate_random_bases, privacy_amplification
from qkd.core.config import ProtocolParams
from qkd.core.quantum_channel import measure_qubits
from qkd.services.file_stream import receive_encrypted_file, receive_file_meta, received_path
from qkd.services.reporting import Reporter
from qkd.services.resume import ResumeError, chunk_boundary, receive_encrypted_file_resumable, validate_meta
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import (
    AuthContext,
    KeyExchangeResult,
    TransferInterrupted,
    report_qber_verdict,
    report_summary,
)
from qkd.usecases.handshake import bob_finished, bob_hello, session_key
from qkd.usecases.resume import BobNegotiation, ResumeOptions, bob_negotiate, bob_send_receipt, wants_resume


@dataclass(frozen=True)
class ReceiveResult:
    key_exchange: KeyExchangeResult
    output_path: Optional[str] = None
    bytes_written: int = 0
    resumed_from_bytes: int = 0  # bytes already on disk from an interrupted session (resume only)


def _measure(channel: TranscriptChannel, reporter: Reporter) -> tuple[int, list[int], list[str]]:
    reporter.info("Receiving qubits from quantum channel...")
    qasm_strings = channel.recv_untracked()
    reporter.success(f"Received {len(qasm_strings)} qubits")
    reporter.metrics(raw_qubits=len(qasm_strings))

    reporter.info("Generating random measurement bases...")
    bases = generate_random_bases(len(qasm_strings))

    reporter.info("Measuring qubits (collapsing quantum states)...")
    t0 = time.time()
    bits = measure_qubits(qasm_strings, bases)
    reporter.success(f"Measured {len(bits)} qubits in {time.time() - t0:.2f}s")
    return len(qasm_strings), bits, bases


def _sift(channel: TranscriptChannel, raw: int, bits: list[int], bases: list[str], reporter: Reporter) -> list[int]:
    reporter.stage("sifting")
    reporter.section("Phase 2: Classical Channel (Basis Exchange)")
    reporter.info("Sending measurement bases to Alice...")
    channel.send_json(bases)

    reporter.info("Receiving matching indices from Alice...")
    matching = channel.recv_json()

    reporter.section("Phase 3: Key Sifting & QBER Estimation")
    sifted = [bits[i] for i in matching]
    reporter.success(f"Sifted key: {len(sifted)} bits (from {raw} raw qubits)")
    reporter.info(f"Sift rate: {len(sifted) / raw * 100:.1f}%")
    reporter.metrics(raw_qubits=raw, sifted_length=len(sifted))
    return sifted


def _answer_qber_sample(channel: TranscriptChannel, sifted: list[int], reporter: Reporter) -> tuple[float, list[int]]:
    reporter.stage("qber_estimation")
    reporter.info("Waiting for QBER sample indices from Alice...")
    sample_indices = channel.recv_json()["sample_indices"]

    reporter.info("Sending sample bits back to Alice for calculation...")
    channel.send_json({"sample_bits": [sifted[i] for i in sample_indices]})

    reporter.info("Waiting for QBER result from Alice...")
    return channel.recv_json()["qber"], sample_indices


def run_key_exchange(channel: TranscriptChannel, params: ProtocolParams, reporter: Reporter) -> KeyExchangeResult:
    """Bob's side of BB84 up to and including privacy amplification (steps 1 to 4)."""
    reporter.stage("quantum_transmission")
    reporter.section("Phase 1: Quantum Key Distribution (BB84)")
    raw, bits, bases = _measure(channel, reporter)
    sifted = _sift(channel, raw, bits, bases, reporter)
    qber, sample_indices = _answer_qber_sample(channel, sifted, reporter)

    result = dict(raw_qubits=raw, sifted_length=len(sifted), sample_size=len(sample_indices),
                  qber=qber, threshold=params.qber_threshold)
    if report_qber_verdict(qber, params.qber_threshold, len(sample_indices), reporter):
        return KeyExchangeResult(key=None, **result)

    reporter.stage("privacy_amplification")
    reporter.section("Phase 4: Key Distillation")
    # No reconciliation: the channel is noiseless, so the remaining bits already match Alice's.
    reporter.info("Aligning keys...")
    remaining = discard_indices(sifted, sample_indices)

    reporter.info("Receiving privacy amplification salt...")
    salt = bytes.fromhex(channel.recv_json()["salt"])
    reporter.info("Privacy amplification (SHA-256 universal hashing)...")
    _, key = privacy_amplification(remaining, salt=salt)
    reporter.success(f"Final key: {len(key) * 8}-bit AES key derived")
    reporter.metrics(key_bits=len(key) * 8)
    return KeyExchangeResult(key=key, **result)


def receive_file(
    sock: socket.socket,
    output_dir: str,
    reporter: Reporter,
    params: ProtocolParams = ProtocolParams(),
    auth: AuthContext | None = None,
    resume: Optional[ResumeOptions] = None,
) -> ReceiveResult:
    """
    Authenticate Alice, run the key exchange and, unless it aborts, receive the file into output_dir.

    Raises PeerAuthError if the hello or finished exchange fails; nothing is
    decrypted or written before Alice's finished signature verifies.
    Raises cryptography.exceptions.InvalidTag if a chunk fails authentication.

    With `resume` (and auth sign or hybrid) verified chunks are kept in a .part so a new session can
    continue after them, and a lost connection or failed chunk raises TransferInterrupted instead.
    A different peer identity than the one that started the transfer raises PeerAuthError.
    """
    offer_resume = wants_resume(resume, auth, reporter)
    channel = TranscriptChannel(sock, "bob")
    reporter.stage("authentication")
    reporter.section("Phase 0: Authentication (Hello Exchange)")
    handshake = bob_hello(channel, auth, reporter)

    kx = run_key_exchange(channel, params, reporter)
    if kx.aborted:
        return ReceiveResult(kx)

    transcript_hash = channel.digest()
    negotiate = False
    if handshake.signed:
        reporter.stage("key_confirmation")
        reporter.section("Key Confirmation (Signed Transcript)")
        peer_resume = bob_finished(channel, auth, handshake, transcript_hash, reporter, offer_resume)
        negotiate = offer_resume and peer_resume
        if offer_resume and not peer_resume:
            reporter.warning("The sender does not offer resume. Receiving the whole file without it.")

    key = session_key(kx.key, handshake, transcript_hash)
    if negotiate:
        return _receive_resumable(sock, channel, key, transcript_hash, handshake, kx, output_dir, reporter, resume)

    reporter.stage("file_transfer")
    reporter.section("Phase 5: Secure File Reception (Chunked Streaming)")
    reporter.info("Receiving encrypted file metadata...")
    meta = receive_file_meta(sock)
    reporter.info(f"File: {meta.filename} ({meta.total_size} bytes, {meta.num_chunks} chunks of {meta.chunk_size // 1024} KB)")

    os.makedirs(output_dir, exist_ok=True)
    output_path = received_path(output_dir, meta.filename)
    reporter.info(f"Receiving and decrypting {meta.num_chunks} chunks...")
    reporter.progress(0, meta.num_chunks, 0, meta.total_size)

    def on_progress(done: int, total: int, written: int) -> None:
        reporter.progress(done, total, written, meta.total_size)
        if done % 100 == 0 or done == total:
            reporter.info(f"  Decrypted chunk {done}/{total} ({done / total * 100:.1f}%)")

    written = receive_encrypted_file(sock, meta, output_path, key, on_progress)
    reporter.success(f"File decrypted and saved as '{output_path}' ({written} bytes)")
    reporter.success(f"All {meta.num_chunks} chunk authentication tags verified!")

    reporter.section("Transfer Complete")
    reporter.success("File securely received via BB84 QKD + AES-256-GCM")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return ReceiveResult(kx, output_path, written)


def _receive_resumable(
    sock: socket.socket,
    channel: TranscriptChannel,
    key: bytes,
    transcript_hash: bytes,
    handshake,
    kx: KeyExchangeResult,
    output_dir: str,
    reporter: Reporter,
    resume: ResumeOptions,
) -> ReceiveResult:
    """Steps 4c/4d and 5 with a .part: only verified chunks reach the disk, and the file appears at the end."""
    negotiation: Optional[BobNegotiation] = None
    held = 0  # bytes of verified data on disk, for the interruption report
    try:
        negotiation = bob_negotiate(channel, key, transcript_hash, handshake, resume, output_dir, reporter)

        reporter.stage("file_transfer")
        reporter.section("Phase 5: Secure File Reception (Chunked Streaming)")
        reporter.info("Receiving encrypted file metadata...")
        meta = receive_file_meta(sock)
        validate_meta(meta)
        if meta.resume_offset != negotiation.offset:
            raise ResumeError("the file metadata does not carry the granted resume offset")
        reporter.info(f"File: {meta.filename} ({meta.total_size} bytes, {meta.num_chunks} chunks of {meta.chunk_size // 1024} KB)")

        state = negotiation.store.begin(meta, negotiation.offset, handshake.peer_fingerprint, handshake.mode,
                                        negotiation.previous)
        held = state.next_byte
        reporter.metrics(resumed_from_bytes=held, bytes_total=meta.total_size)
        reporter.info(f"Receiving and decrypting chunks {negotiation.offset}..{meta.num_chunks - 1}...")
        reporter.progress(negotiation.offset, meta.num_chunks, held, meta.total_size)

        def on_progress(done: int, total: int, written: int) -> None:
            nonlocal held
            held = written
            reporter.progress(done, total, written, meta.total_size)
            if done % 100 == 0 or done == total:
                reporter.info(f"  Decrypted chunk {done}/{total} ({done / total * 100:.1f}%)")

        written = receive_encrypted_file_resumable(
            sock, meta, negotiation.store, state, key, negotiation.offset, on_progress, resume.sync_chunks
        )
    except (ConnectionError, InvalidTag, OSError) as exc:
        # Everything verified so far is on disk and recorded; a new session can continue after it.
        has_state = negotiation is not None and negotiation.store.load() is not None
        if has_state:
            raise TransferInterrupted(f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__, held) from exc
        raise
    except ResumeError as exc:
        if exc.resumable and negotiation is not None and negotiation.store.load() is not None:
            raise TransferInterrupted(exc.reason, held) from exc
        raise

    output_path = received_path(output_dir, meta.filename)
    try:
        bob_send_receipt(channel, key, transcript_hash, meta.sha256, meta.total_size)
    except OSError:  # the file is complete and in place; the sender will just have to ask again
        reporter.warning("Could not send the receipt: the sender is gone")
    reporter.success(f"File decrypted, verified and saved as '{output_path}' ({written} bytes)")
    reporter.success("All chunk authentication tags and the SHA-256 of the whole file verified!")

    reporter.section("Transfer Complete")
    reporter.success("File securely received via BB84 QKD + AES-256-GCM")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return ReceiveResult(kx, output_path, written, chunk_boundary(negotiation.offset, meta.chunk_size, meta.total_size))
