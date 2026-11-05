"""
Alice's workflow: BB84 key exchange, then chunked AES-256-GCM file streaming.

Message order on the socket (must match receive_file.py and eavesdrop_demo.py):
  0a -> {"hello"}              0b <- {"hello"}          (both abort on mode mismatch)
  1  -> qubits (QASM list, untracked)
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

from qkd.core.bb84_protocol import (
    choose_sample_indices,
    compute_qber,
    discard_indices,
    generate_random_bases,
    generate_random_bits,
    matching_basis_indices,
    privacy_amplification,
)
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


def _transmit_qubits(channel: TranscriptChannel, n: int, reporter: Reporter) -> tuple[list[int], list[str]]:
    reporter.metrics(raw_qubits=n)
    reporter.info(f"Generating {n} random bits and bases...")
    t0 = time.perf_counter()
    bits = generate_random_bits(n)
    bases = generate_random_bases(n)
    reporter.info(f"Generated in {time.perf_counter() - t0:.4f}s")

    reporter.info("Preparing qubits (encoding bits in quantum states)...")
    t0 = time.perf_counter()
    qasm_strings = prepare_qubits(bits, bases)
    reporter.success(f"Prepared {n} qubits in {time.perf_counter() - t0:.4f}s")

    # Qubits are transmitted noiselessly in this simplified protocol
    reporter.info("Sending qubits over quantum channel...")
    channel.send_untracked(qasm_strings)
    reporter.success("Qubits transmitted")
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
    reporter.metrics(raw_qubits=len(bits), sifted_length=len(sifted))

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
    bits, bases = _transmit_qubits(channel, params.num_qubits, reporter)
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

    send_encrypted_file(sock, filepath, key, meta, on_progress)
    reporter.success(f"Encrypted file '{meta.filename}' streamed to Bob ({meta.num_chunks} chunks)")

    reporter.section("Transfer Complete")
    reporter.success("File securely transferred using BB84 QKD + AES-256-GCM")
    reporter.info(f"Total time elapsed: {time.perf_counter() - t_start:.4f}s")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return kx
