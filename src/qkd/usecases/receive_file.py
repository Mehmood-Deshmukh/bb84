"""
Bob's workflow: authenticate Alice, measure her qubits, finish the BB84 key
exchange, confirm the transcript, then receive and decrypt the chunked file.
Message order matches send_file.py.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

from qkd.core.bb84_protocol import discard_indices, generate_random_bases, privacy_amplification
from qkd.core.config import ProtocolParams
from qkd.core.quantum_channel import measure_qubits
from qkd.services.file_stream import receive_encrypted_file, receive_file_meta, received_path
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import AuthContext, KeyExchangeResult, report_qber_verdict, report_summary
from qkd.usecases.handshake import bob_finished, bob_hello, session_key


@dataclass(frozen=True)
class ReceiveResult:
    key_exchange: KeyExchangeResult
    output_path: Optional[str] = None
    bytes_written: int = 0


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
) -> ReceiveResult:
    """
    Authenticate Alice, run the key exchange and, unless it aborts, receive the file into output_dir.

    Raises PeerAuthError if the hello or finished exchange fails; nothing is
    decrypted or written before Alice's finished signature verifies.
    Raises cryptography.exceptions.InvalidTag if a chunk fails authentication.
    """
    channel = TranscriptChannel(sock, "bob")
    reporter.stage("authentication")
    reporter.section("Phase 0: Authentication (Hello Exchange)")
    handshake = bob_hello(channel, auth, reporter)

    kx = run_key_exchange(channel, params, reporter)
    if kx.aborted:
        return ReceiveResult(kx)

    transcript_hash = channel.digest()
    if handshake.signed:
        reporter.stage("key_confirmation")
        reporter.section("Key Confirmation (Signed Transcript)")
        bob_finished(channel, auth, handshake, transcript_hash, reporter)

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

    key = session_key(kx.key, handshake, transcript_hash)
    written = receive_encrypted_file(sock, meta, output_path, key, on_progress)
    reporter.success(f"File decrypted and saved as '{output_path}' ({written} bytes)")
    reporter.success(f"All {meta.num_chunks} chunk authentication tags verified!")

    reporter.section("Transfer Complete")
    reporter.success("File securely received via BB84 QKD + AES-256-GCM")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return ReceiveResult(kx, output_path, written)
