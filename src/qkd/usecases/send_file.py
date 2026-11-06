"""
Alice's workflow: BB84 key exchange, then chunked AES-256-GCM file streaming.

Message order on the socket (must match receive_file.py and eavesdrop_demo.py):
  0a -> {"hello"}              0b <- {"hello"}          (both abort on mode mismatch)
  1  -> {"n","index","qubits"}: the pulses that clicked at Bob (untracked; channel_model.encode_pulses)
  2  <- Bob's bases            -> matching indices
  3  -> {"sample_indices"}     <- {"sample_bits"}       -> {"qber"}   (both abort if qber >= threshold)
     both abort if the finite-key secure length is below final_key_bits (no message)
  4  -> {"salt"} (Toeplitz seed) T = transcript digest
  4b <- {"finished","confirm"} -> {"finished","confirm"} (untracked; sign and hybrid only)
  5  -> encrypted file metadata, then one message per chunk (metadata bound as GCM AAD)
"""

from __future__ import annotations

import socket
import time

import numpy as np

from qkd.core.bb84_protocol import (
    choose_sample_indices,
    compute_qber,
    discard_indices,
    generate_random_bases,
    generate_random_bits,
    matching_basis_indices,
    privacy_amplification,
)
from qkd.core.channel_model import ChannelParams, encode_pulses, sample_clicks
from qkd.core.config import ProtocolParams
from qkd.core.quantum_channel import prepare_qubits
from qkd.services.file_stream import describe_file, send_encrypted_file
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import (
    AuthContext,
    KeyExchangeResult,
    finite_key_verdict,
    report_qber_verdict,
    report_summary,
)
from qkd.usecases.handshake import alice_finished, alice_hello, session_key


def _transmit_qubits(
    channel: TranscriptChannel, n: int, link: ChannelParams, reporter: Reporter
) -> tuple[list[int], list[str]]:
    """
    Send n pulses through the simulated channel; return Alice's bits and bases for the
    pulses that clicked at Bob, in the order they appear in the qubit message.

    The fibre and Bob's detector efficiency and background are emulated here, on the
    sending side: only clicked pulses are simulated (channel_model.sample_clicks, exact in
    distribution). A click from background alone is sent as null, since its photon never
    arrived. Alice's protocol logic still learns which pulses clicked only from Bob's
    bases in step 2. On the ideal channel every pulse clicks.
    """
    reporter.metrics(raw_qubits=n)
    t_sim = time.perf_counter()
    clicks = sample_clicks(n, link, np.random.default_rng())
    m = len(clicks)
    reporter.info(f"Channel: {m} of {n} pulses click at Bob "
                  f"({int(clicks.signal.sum())} photons, {m - int(clicks.signal.sum())} background)")
    reporter.info(f"Generating {m} random bits and bases...")
    bits = generate_random_bits(m)
    bases = generate_random_bases(m)

    reporter.info("Preparing qubits (encoding bits in quantum states)...")
    photons = [i for i in range(m) if clicks.signal[i]]
    prepared = prepare_qubits([bits[i] for i in photons], [bases[i] for i in photons])
    qubits: list[str | None] = [None] * m
    for i, q in zip(photons, prepared):
        qubits[i] = q
    reporter.success(f"Prepared {len(photons)} qubits")
    # Time spent in the simulator (channel, QRNG, state preparation), kept apart from protocol cost
    sim_ms = (time.perf_counter() - t_sim) * 1000

    reporter.info("Sending qubits over quantum channel...")
    sent_before = channel.bytes_sent
    channel.send_untracked(encode_pulses(n, clicks.index.tolist(), qubits))
    reporter.success("Qubits transmitted")
    reporter.metrics(sim_ms=round(sim_ms, 3), qubit_bytes=channel.bytes_sent - sent_before, detected=m)
    return bits, bases


def _sift(channel: TranscriptChannel, bits: list[int], bases: list[str], reporter: Reporter) -> list[int]:
    reporter.stage("sifting")
    reporter.section("Phase 2: Classical Channel (Basis Exchange)")
    reporter.info("Waiting for Bob's measurement bases...")
    bob_bases = channel.recv_json()
    reporter.success(f"Received Bob's bases ({len(bob_bases)} entries)")

    reporter.section("Phase 3: Key Sifting & QBER Estimation")
    matching = matching_basis_indices(bases, bob_bases)
    sifted = [bits[i] for i in matching]
    reporter.success(f"Sifted key: {len(sifted)} bits")
    reporter.info(f"Sift rate: {len(sifted) / len(bits) * 100:.1f}%")
    reporter.metrics(sifted_length=len(sifted))  # raw_qubits (pulses sent) was reported at step 1

    reporter.info("Sending matching indices to Bob...")
    channel.send_json(matching)
    return sifted


def _estimate_qber(channel: TranscriptChannel, sifted: list[int], params: ProtocolParams, reporter: Reporter) -> tuple[float, list[int]]:
    reporter.stage("qber_estimation")
    reporter.info("Estimating Quantum Bit Error Rate (QBER)...")
    sample_indices = choose_sample_indices(len(sifted), params.qber_sample_fraction)

    reporter.info("Sending sample indices to Bob for QBER estimation...")
    channel.send_json({"sample_indices": sample_indices})

    reporter.info("Waiting for Bob's sample bits...")
    bob_sample = channel.recv_json()["sample_bits"]
    qber = compute_qber([sifted[i] for i in sample_indices], bob_sample)

    channel.send_json({"qber": qber})
    return qber, sample_indices


def run_key_exchange(channel: TranscriptChannel, params: ProtocolParams, reporter: Reporter) -> KeyExchangeResult:
    """Alice's side of BB84 up to and including privacy amplification (steps 1 to 4)."""
    reporter.stage("quantum_transmission")
    reporter.section("Phase 1: Quantum Key Distribution (BB84)")
    bits, bases = _transmit_qubits(channel, params.num_qubits, params.channel, reporter)
    sifted = _sift(channel, bits, bases, reporter)
    qber, sample_indices = _estimate_qber(channel, sifted, params, reporter)

    result = dict(raw_qubits=params.num_qubits, sifted_length=len(sifted), sample_size=len(sample_indices),
                  qber=qber, threshold=params.qber_threshold)
    if report_qber_verdict(qber, params.qber_threshold, len(sample_indices), reporter):
        reason = f"QBER {qber:.2%} >= threshold {params.qber_threshold:.0%}"
        return KeyExchangeResult(key=None, abort_reason=reason, **result)

    kept = discard_indices(sifted, sample_indices)
    secure, reason = finite_key_verdict(len(kept), len(sample_indices), qber, params, reporter)
    if reason is not None:
        return KeyExchangeResult(key=None, secure_bits=secure, abort_reason=reason, **result)

    reporter.stage("privacy_amplification")
    reporter.section("Phase 4: Key Distillation")
    reporter.info(f"Privacy amplification (Toeplitz hashing, {len(kept)} -> {params.final_key_bits} bits)...")
    salt, key = privacy_amplification(kept, params.final_key_bits)
    reporter.success(f"Final key: {len(key) * 8}-bit AES key derived")
    reporter.metrics(key_bits=len(key) * 8)
    channel.send_json({"salt": salt.hex()})
    return KeyExchangeResult(key=key, secure_bits=secure, **result)


def send_file(
    sock: socket.socket,
    filepath: str,
    reporter: Reporter,
    params: ProtocolParams = ProtocolParams(),
    auth: AuthContext | None = None,
) -> KeyExchangeResult:
    """
    Authenticate Bob, run the key exchange and, unless it aborts, stream the encrypted file.

    Raises PeerAuthError if the hello or finished signature check fails (no qubits
    are sent unless Bob's identity passed auth.verifier), and KeyConfirmationError
    if Bob's signature is valid but his key differs from Alice's.
    """
    t_start = time.perf_counter()
    channel = TranscriptChannel(sock, "alice")
    reporter.stage("authentication")
    reporter.section("Phase 0: Authentication (Hello Exchange)")
    handshake = alice_hello(channel, auth, reporter, params)

    kx = run_key_exchange(channel, params, reporter)
    if kx.aborted:
        return kx

    transcript_hash = channel.digest()
    key = session_key(kx.key, handshake, transcript_hash)
    if handshake.signed:
        reporter.stage("key_confirmation")
        reporter.section("Key Confirmation (Signed Transcript + Key Tag)")
        alice_finished(channel, auth, handshake, transcript_hash, key, reporter)

    # Everything that went through the transcript channel: hellos, qubits, BB84, finished
    reporter.metrics(channel_bytes=channel.bytes_sent + channel.bytes_received)
    reporter.stage("file_transfer")
    reporter.section("Phase 5: Secure File Transfer (Chunked Streaming)")
    meta = describe_file(filepath, params.chunk_size)
    reporter.info(f"File: {meta.filename} ({meta.total_size} bytes)")
    reporter.info(f"Streaming as {meta.num_chunks} chunk(s) of {meta.chunk_size // 1024} KB")
    reporter.progress(0, meta.num_chunks, 0, meta.total_size)

    def on_progress(done: int, total: int, sent: int) -> None:
        reporter.progress(done, total, sent, meta.total_size)
        if done % 100 == 0 or done == total:
            reporter.info(f"  Sent chunk {done}/{total} ({done / total * 100:.1f}%)")

    file_wire_bytes = send_encrypted_file(sock, filepath, key, meta, on_progress)
    reporter.metrics(file_wire_bytes=file_wire_bytes)
    reporter.success(f"Encrypted file '{meta.filename}' streamed to Bob ({meta.num_chunks} chunks)")

    reporter.section("Transfer Complete")
    reporter.success("File securely transferred using BB84 QKD + AES-256-GCM")
    reporter.info(f"Total time elapsed: {time.perf_counter() - t_start:.4f}s")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return kx
