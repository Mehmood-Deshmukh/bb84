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

import numpy as np
from cryptography.exceptions import InvalidTag

from qkd.core.bb84_protocol import (
    discard_indices,
    generate_random_bases,
    generate_random_bits,
    privacy_amplification,
)
from qkd.core.config import ProtocolParams
from qkd.core.channel_model import ChannelParams, decode_pulses, misalignment_flips
from qkd.core.quantum_channel import measure_qubits
from qkd.services.file_stream import receive_encrypted_file, receive_file_meta, received_path
from qkd.services.reporting import Reporter
from qkd.services.resume import ResumeError, chunk_boundary, receive_encrypted_file_resumable, validate_meta
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import (
    AuthContext,
    KeyExchangeResult,
    TransferInterrupted,
    decoy_asymptotic_verdict,
    finite_key_verdict,
    report_qber_verdict,
    report_summary,
)
from qkd.usecases.decoy_reveal import bob_decoy_reveal
from qkd.usecases.handshake import bob_finished, bob_hello, session_key
from qkd.usecases.reconcile import bob_reconcile
from qkd.usecases.resume import BobNegotiation, ResumeOptions, bob_negotiate, bob_send_receipt, wants_resume


@dataclass(frozen=True)
class ReceiveResult:
    key_exchange: KeyExchangeResult
    output_path: Optional[str] = None
    bytes_written: int = 0
    resumed_from_bytes: int = 0  # bytes already on disk from an interrupted session (resume only)


def _measure(
    channel: TranscriptChannel, link: ChannelParams, reporter: Reporter
) -> tuple[int, list[int], list[str]]:
    """
    Step 1 for Bob: receive the pulses that clicked, measure them, return
    (pulses sent, bits, bases) with one bit and basis per clicked pulse.

    Bob's detector is emulated here: photons are measured in a random basis and the
    result is flipped with the misalignment probability; a click from background alone
    (a null qubit) gives a uniformly random bit.
    """
    reporter.info("Receiving qubits from quantum channel...")
    n, _index, qubits = decode_pulses(channel.recv_untracked())
    m = len(qubits)
    photons = [i for i, q in enumerate(qubits) if q is not None]
    reporter.success(f"{m} of {n} pulses clicked ({len(photons)} photons, {m - len(photons)} background)")
    reporter.metrics(raw_qubits=n, detected=m)

    reporter.info("Generating random measurement bases...")
    t_sim = time.perf_counter()
    bases = generate_random_bases(m)

    reporter.info("Measuring qubits (collapsing quantum states)...")
    t0 = time.perf_counter()
    measured = measure_qubits([qubits[i] for i in photons], [bases[i] for i in photons])
    flips = misalignment_flips(len(photons), link, np.random.default_rng())
    bits = generate_random_bits(m)  # background clicks keep these random bits
    for i, bit, flip in zip(photons, measured, flips):
        bits[i] = bit ^ int(flip)
    reporter.success(f"Measured {len(photons)} qubits in {time.perf_counter() - t0:.2f}s")
    # Time spent in the simulator (QRNG and measurement), kept apart from protocol cost
    reporter.metrics(sim_ms=round((time.perf_counter() - t_sim) * 1000, 3))
    return n, bits, bases


def _sift(channel: TranscriptChannel, raw: int, bits: list[int], bases: list[str],
          reporter: Reporter) -> tuple[list[int], list[int]]:
    reporter.stage("sifting")
    reporter.section("Phase 2: Classical Channel (Basis Exchange)")
    reporter.info("Sending measurement bases to Alice...")
    channel.send_json(bases)

    reporter.info("Receiving matching indices from Alice...")
    matching = channel.recv_json()

    reporter.section("Phase 3: Key Sifting & QBER Estimation")
    sifted = [bits[i] for i in matching]
    reporter.success(f"Sifted key: {len(sifted)} bits (from {len(bits)} detected of {raw} pulses)")
    reporter.info(f"Sift rate: {len(sifted) / max(1, len(bits)) * 100:.1f}% of detected pulses")
    reporter.metrics(sifted_length=len(sifted))
    return sifted, matching


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
    raw, bits, bases = _measure(channel, params.channel, reporter)
    sifted, matching = _sift(channel, raw, bits, bases, reporter)

    # With a decoy source, read the intensity labels (step 2d) and keep only the signal
    # intensity for the key; decoy and vacuum bits are revealed and used only for estimation.
    est = None
    if params.decoy_enabled:
        key_bits, est = bob_decoy_reveal(channel, bits, matching, params, reporter)
    else:
        key_bits = sifted
    qber, sample_indices = _answer_qber_sample(channel, key_bits, reporter)

    result = dict(raw_qubits=raw, sifted_length=len(key_bits), sample_size=len(sample_indices),
                  qber=qber, threshold=params.qber_threshold)
    if report_qber_verdict(qber, params.qber_threshold, len(sample_indices), reporter):
        reason = f"QBER {qber:.2%} >= threshold {params.qber_threshold:.0%}"
        return KeyExchangeResult(key=None, abort_reason=reason, **result)

    # Without reconciliation the kept bits must already match Alice's; any difference
    # is caught by key confirmation (4b) or the file tag. With "cascade" Bob corrects them.
    kept = discard_indices(key_bits, sample_indices)
    # Count distinct positions, so a repeated index cannot inflate the sample size
    sample_size = len(set(sample_indices))
    leaked = 0
    if params.reconciliation == "cascade":
        rec = bob_reconcile(channel, kept, qber, sample_size, reporter)
        kept, leaked = rec.bits, rec.leaked_bits
    if params.decoy_enabled:
        secure, reason = decoy_asymptotic_verdict(len(kept), est, params, reporter, leaked)
    else:
        secure, reason = finite_key_verdict(len(kept), sample_size, qber, params, reporter, leaked)
    if reason is not None:
        return KeyExchangeResult(key=None, secure_bits=secure, abort_reason=reason, **result)

    reporter.stage("privacy_amplification")
    reporter.section("Phase 4: Key Distillation")
    reporter.info("Receiving privacy amplification seed...")
    salt = bytes.fromhex(channel.recv_json()["salt"])
    reporter.info(f"Privacy amplification (Toeplitz hashing, {len(kept)} -> {params.final_key_bits} bits)...")
    _, key = privacy_amplification(kept, params.final_key_bits, salt=salt)
    reporter.success(f"Final key: {len(key) * 8}-bit AES key derived")
    reporter.metrics(key_bits=len(key) * 8)
    return KeyExchangeResult(key=key, secure_bits=secure, **result)


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

    Raises PeerAuthError if the hello or finished signature check fails, and
    KeyConfirmationError if Alice's signature is valid but her key differs from
    Bob's; nothing is decrypted or written before both checks pass.
    Raises cryptography.exceptions.InvalidTag if a chunk fails authentication,
    and file_stream.MetadataError if the metadata is malformed or its chunk
    count does not match its sizes (checked before any file is created).

    With `resume` (and auth sign or hybrid) verified chunks are kept in a .part so a new session can
    continue after them, and a lost connection or failed chunk raises TransferInterrupted instead.
    A different peer identity than the one that started the transfer raises PeerAuthError.
    """
    offer_resume = wants_resume(resume, auth, reporter)
    channel = TranscriptChannel(sock, "bob")
    reporter.stage("authentication")
    reporter.section("Phase 0: Authentication (Hello Exchange)")
    handshake = bob_hello(channel, auth, reporter, params)

    kx = run_key_exchange(channel, params, reporter)
    if kx.aborted:
        return ReceiveResult(kx)

    transcript_hash = channel.digest()
    key = session_key(kx.key, handshake, transcript_hash)
    negotiate = False
    if handshake.signed:
        reporter.stage("key_confirmation")
        reporter.section("Key Confirmation (Signed Transcript + Key Tag)")
        peer_resume = bob_finished(channel, auth, handshake, transcript_hash, key, reporter, offer_resume)
        negotiate = offer_resume and peer_resume
        if offer_resume and not peer_resume:
            reporter.warning("The sender does not offer resume. Receiving the whole file without it.")

    if negotiate:
        return _receive_resumable(sock, channel, key, transcript_hash, handshake, kx, output_dir, reporter, resume)

    reporter.stage("file_transfer")
    reporter.section("Phase 5: Secure File Reception (Chunked Streaming)")
    reporter.info("Receiving encrypted file metadata...")
    meta = receive_file_meta(sock, key)
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
        meta = receive_file_meta(sock, key)
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
