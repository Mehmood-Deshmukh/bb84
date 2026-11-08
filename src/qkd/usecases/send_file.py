"""
Alice's workflow: BB84 key exchange, then chunked AES-256-GCM file streaming.

Message order on the socket (must match receive_file.py and eavesdrop_demo.py):
  0a -> {"hello"}              0b <- {"hello"}          (both abort on mode mismatch)
  1  -> {"n","index","qubits"}: the pulses that clicked at Bob (untracked; channel_model.encode_pulses)
  2  <- Bob's bases            -> matching indices
  3  -> {"sample_indices"}     <- {"sample_bits"}       -> {"qber"}   (both abort if qber >= threshold)
  3c (reconciliation "cascade" only) -> {"cascade_seed"}, then <- {"cascade"} / -> {"parities"} rounds
     until Bob sends an empty {"cascade": []} (usecases/reconcile.py)
     both abort if the finite-key secure length (charged for the revealed parities) is below
     final_key_bits (no message)
  4  -> {"salt"} (Toeplitz seed) T = transcript digest
  4b <- {"finished","confirm"} -> {"finished","confirm"} (untracked; sign and hybrid only)
  4c <- {"resume_request"}     4d -> {"resume_grant"}   (only if resume is on and both finished carried "resume": 1)
  5  -> encrypted file metadata, then one message per chunk (metadata bound as GCM AAD)
  6  <- {"resume_done"}        (resume only: Bob's sealed receipt after the whole file verified)
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional

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
from qkd.core.source import SIGNAL, sample_clicks_decoy, sample_photon_numbers
from qkd.services.file_stream import describe_file, send_encrypted_file
from qkd.services.reporting import Reporter
from qkd.services.resume import ResumeError, chunk_boundary
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
from qkd.usecases.decoy_reveal import alice_decoy_reveal
from qkd.usecases.handshake import alice_finished, alice_hello, session_key
from qkd.usecases.reconcile import alice_reconcile
from qkd.usecases.resume import ResumeOptions, alice_await_receipt, alice_negotiate, wants_resume


@dataclass
class _AliceTx:
    """
    Alice's per-pulse transmission data, indexed to match the pulses Bob will sift.

    Without pre-loss handoff, bits/bases/labels hold one entry per pulse that clicked at Bob,
    in qubit-message order (the detected set is Alice's own sampling). With pre-loss handoff
    (eve-mode weak-coherent source) they hold one entry per PULSE SENT, indexed by global pulse
    number: the detected set is not known until Bob reports it in step 2, so the per-detected
    arrays are built there. `labels`/`sent` are None for the single-photon source.
    """

    bits: list[int]
    bases: list[str]
    labels: Optional[list[int]]
    sent: Optional[list[int]]
    preloss: bool


def _transmit_qubits(
    channel: TranscriptChannel, params: ProtocolParams, reporter: Reporter, preloss: bool
) -> _AliceTx:
    """
    Send n pulses through the simulated channel and return Alice's per-pulse data (see _AliceTx).

    Normal path: the fibre and Bob's detector efficiency and background are emulated here, on
    the sending side; only clicked pulses are simulated (exact in distribution), a background
    click is sent as null, and Alice learns which pulses clicked only from Bob's bases in step 2.
    With a weak-coherent source each clicked pulse also carries an intensity label and photon
    number. The step-1 qubit message is unchanged and carries no labels (Eve reads it).

    Pre-loss handoff (eve-mode, weak-coherent): a photon-number-splitting Eve replaces the fibre,
    so she must see every pulse before the loss. Alice generates ALL n pulses (label, Poisson
    photon number, bit, basis), prepares a qubit for each pulse with n >= 1, and sends the whole
    pre-loss stream over an untracked message to the Eve proxy INSTEAD of the step-1 qubit
    message; Eve forwards a post-loss step-1 message to Bob. Alice keeps the full per-pulse arrays
    and learns which pulses reached Bob from his detected-index report in step 2.
    """
    n, link = params.num_qubits, params.channel
    reporter.metrics(raw_qubits=n)
    t_sim = time.perf_counter()
    rng = np.random.default_rng()

    if preloss:
        tx = _transmit_preloss(channel, params, reporter, rng, t_sim)
        return tx

    if params.weak_coherent:
        mix_i, mix_p = params.source_mix()
        clicks = sample_clicks_decoy(n, mix_i, mix_p, link, rng)
        labels: Optional[list[int]] = clicks.label.tolist()
        sent: Optional[list[int]] = clicks.sent.tolist()
    else:
        clicks = sample_clicks(n, link, rng)
        labels = sent = None
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
    return _AliceTx(bits, bases, labels, sent, preloss=False)


def _transmit_preloss(channel: TranscriptChannel, params: ProtocolParams, reporter: Reporter,
                      rng: np.random.Generator, t_sim: float) -> _AliceTx:
    """Generate the full pre-loss pulse stream and hand it to the Eve proxy (see _transmit_qubits)."""
    n = params.num_qubits
    mix_i, mix_p = params.source_mix()
    label_arr, photon_arr, sent_arr = sample_photon_numbers(n, mix_i, mix_p, rng)
    labels = label_arr.tolist()
    photons = photon_arr.tolist()
    bits = generate_random_bits(n)
    bases = generate_random_bases(n)

    reporter.info(f"Eve-mode pre-loss handoff: generating all {n} pulses "
                  f"({int((photon_arr >= 1).sum())} with a photon)...")
    with_photon = [i for i in range(n) if photons[i] >= 1]
    prepared = prepare_qubits([bits[i] for i in with_photon], [bases[i] for i in with_photon])
    sim_ms = (time.perf_counter() - t_sim) * 1000

    sent_before = channel.bytes_sent
    channel.send_untracked({"preloss": {
        "n": n,
        "index": with_photon,
        "labels": "".join(str(labels[i]) for i in with_photon),
        "photons": [photons[i] for i in with_photon],
        "qubits": prepared,
    }})
    reporter.success(f"Handed {len(with_photon)} pre-loss pulses to Eve")
    reporter.metrics(sim_ms=round(sim_ms, 3), qubit_bytes=channel.bytes_sent - sent_before)
    # Detected count (metric) and the per-detected arrays are set once Bob reports in step 2.
    return _AliceTx(bits, bases, labels, sent_arr.tolist(), preloss=True)


def _sift(channel: TranscriptChannel, tx: _AliceTx,
          reporter: Reporter) -> tuple[list[int], list[int], list[int], Optional[list[int]]]:
    """
    Step 2 for Alice. Returns (sifted bits, matching indices, per-detected bits, per-detected
    labels). The last two are in detected-pulse order and feed the decoy reveal (step 2d); labels
    is None for the single-photon source.
    """
    reporter.stage("sifting")
    reporter.section("Phase 2: Classical Channel (Basis Exchange)")
    reporter.info("Waiting for Bob's measurement bases...")
    reply = channel.recv_json()

    if tx.preloss:
        # Ground truth from Bob: he reports the global indices he detected, so Alice sifts
        # against the pulses that actually reached him (a PNS Eve changed the detected set).
        bob_bases = reply["bases"]
        detected = reply["detected"]
        if not isinstance(detected, list) or len(detected) != len(bob_bases):
            raise ValueError("step 2: detected indices must match the bases count")
        if any(not isinstance(g, int) or isinstance(g, bool) or not 0 <= g < len(tx.bits) for g in detected):
            raise ValueError("step 2: detected index out of range")
        det_bits = [tx.bits[g] for g in detected]
        det_bases = [tx.bases[g] for g in detected]
        det_labels: Optional[list[int]] = [tx.labels[g] for g in detected] if tx.labels is not None else None
        reporter.metrics(detected=len(detected))
    else:
        bob_bases = reply
        det_bits, det_bases, det_labels = tx.bits, tx.bases, tx.labels
    reporter.success(f"Received Bob's bases ({len(bob_bases)} entries)")

    reporter.section("Phase 3: Key Sifting & QBER Estimation")
    matching = matching_basis_indices(det_bases, bob_bases)
    sifted = [det_bits[i] for i in matching]
    reporter.success(f"Sifted key: {len(sifted)} bits")
    reporter.info(f"Sift rate: {len(sifted) / max(1, len(det_bits)) * 100:.1f}%")
    reporter.metrics(sifted_length=len(sifted))  # raw_qubits (pulses sent) was reported at step 1

    reporter.info("Sending matching indices to Bob...")
    channel.send_json(matching)
    return sifted, matching, det_bits, det_labels


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


def run_key_exchange(channel: TranscriptChannel, params: ProtocolParams, reporter: Reporter,
                     preloss: bool = False) -> KeyExchangeResult:
    """
    Alice's side of BB84 up to and including privacy amplification (steps 1 to 4).

    `preloss` (eve-mode, weak-coherent source) makes Alice hand the full pre-loss pulse stream to
    the Eve proxy and take Bob's reported detections as the ground truth for sifting and gains.
    """
    reporter.stage("quantum_transmission")
    reporter.section("Phase 1: Quantum Key Distribution (BB84)")
    tx = _transmit_qubits(channel, params, reporter, preloss)
    sifted, matching, det_bits, det_labels = _sift(channel, tx, reporter)

    # With a decoy source, reveal the intensity labels (step 2d) and keep only the signal
    # intensity for the key; decoy and vacuum bits are fully revealed and discarded.
    est = None
    if params.decoy_enabled:
        key_bits, est = alice_decoy_reveal(channel, det_bits, matching,
                                           det_labels, tx.sent, params, reporter)
    else:
        key_bits = sifted
    qber, sample_indices = _estimate_qber(channel, key_bits, params, reporter)

    result = dict(raw_qubits=params.num_qubits, sifted_length=len(key_bits), sample_size=len(sample_indices),
                  qber=qber, threshold=params.qber_threshold)
    if report_qber_verdict(qber, params.qber_threshold, len(sample_indices), reporter):
        reason = f"QBER {qber:.2%} >= threshold {params.qber_threshold:.0%}"
        return KeyExchangeResult(key=None, abort_reason=reason, **result)

    kept = discard_indices(key_bits, sample_indices)
    leaked = 0
    if params.reconciliation == "cascade":
        leaked = alice_reconcile(channel, kept, reporter).leaked_bits
    if params.decoy_enabled:
        secure, reason = decoy_asymptotic_verdict(len(kept), est, params, reporter, leaked)
    else:
        secure, reason = finite_key_verdict(len(kept), len(sample_indices), qber, params, reporter, leaked)
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
    resume: Optional[ResumeOptions] = None,
    eve_mode: bool = False,
) -> KeyExchangeResult:
    """
    Authenticate Bob, run the key exchange and, unless it aborts, stream the encrypted file.

    Raises PeerAuthError if the hello or finished signature check fails (no qubits
    are sent unless Bob's identity passed auth.verifier), and KeyConfirmationError
    if Bob's signature is valid but his key differs from Alice's.

    With `resume` (and auth sign or hybrid) Alice offers to continue an interrupted transfer: Bob
    says how much he holds, and only the rest is sent, under this session's new key. If the
    connection then drops, TransferInterrupted is raised. Without it the behaviour is unchanged.

    `eve_mode` with a weak-coherent source (wcp/decoy) turns on the pre-loss handoff: Alice sends
    the whole pulse stream, before channel loss, to an Eve proxy and uses Bob's reported
    detections as ground truth. With the single-photon source it has no effect here (the Eve the
    proxy runs is the intercept-resend one, which reads Alice's post-loss qubits unchanged).
    """
    t_start = time.perf_counter()
    preloss = eve_mode and params.weak_coherent
    offer_resume = wants_resume(resume, auth, reporter)
    channel = TranscriptChannel(sock, "alice")
    reporter.stage("authentication")
    reporter.section("Phase 0: Authentication (Hello Exchange)")
    handshake = alice_hello(channel, auth, reporter, params, preloss=preloss)

    kx = run_key_exchange(channel, params, reporter, preloss=preloss)
    if kx.aborted:
        return kx

    transcript_hash = channel.digest()
    key = session_key(kx.key, handshake, transcript_hash)
    negotiate = False
    if handshake.signed:
        reporter.stage("key_confirmation")
        reporter.section("Key Confirmation (Signed Transcript + Key Tag)")
        peer_resume = alice_finished(channel, auth, handshake, transcript_hash, key, reporter, offer_resume)
        negotiate = offer_resume and peer_resume
        if offer_resume and not peer_resume:
            reporter.warning("The receiver does not offer resume. Sending the whole file.")

    offset = 0
    try:
        if negotiate:
            offset, _ = alice_negotiate(channel, key, transcript_hash, auth, resume, filepath, params.chunk_size, reporter)
    except ResumeError as exc:
        if exc.resumable:
            raise TransferInterrupted(exc.reason) from exc
        raise
    except (ConnectionError, OSError) as exc:
        raise TransferInterrupted(f"connection lost during resume negotiation: {exc}") from exc

    # Everything that went through the transcript channel: hellos, qubits, BB84, finished
    reporter.metrics(channel_bytes=channel.bytes_sent + channel.bytes_received)
    reporter.stage("file_transfer")
    reporter.section("Phase 5: Secure File Transfer (Chunked Streaming)")
    meta = describe_file(filepath, params.chunk_size, with_sha256=negotiate, resume_offset=offset if negotiate else None)
    reporter.info(f"File: {meta.filename} ({meta.total_size} bytes)")
    if negotiate:
        reporter.metrics(resumed_from_bytes=chunk_boundary(offset, meta.chunk_size, meta.total_size), bytes_total=meta.total_size)
    reporter.info(f"Streaming as {meta.num_chunks} chunk(s) of {meta.chunk_size // 1024} KB"
                  + (f", from chunk {offset}" if offset else ""))
    reporter.progress(offset, meta.num_chunks, chunk_boundary(offset, meta.chunk_size, meta.total_size), meta.total_size)

    def on_progress(done: int, total: int, sent: int) -> None:
        reporter.progress(done, total, sent, meta.total_size)
        if done % 100 == 0 or done == total:
            reporter.info(f"  Sent chunk {done}/{total} ({done / total * 100:.1f}%)")

    try:
        file_wire_bytes = send_encrypted_file(sock, filepath, key, meta, on_progress, start_chunk=offset)
        reporter.metrics(file_wire_bytes=file_wire_bytes)
        if negotiate:
            reporter.info("Waiting for the receiver to confirm the whole file...")
            alice_await_receipt(channel, key, transcript_hash, meta.sha256, meta.total_size)
    except (ConnectionError, OSError) as exc:
        if negotiate:
            raise TransferInterrupted(f"connection lost before the receiver confirmed the file: {exc}") from exc
        raise
    reporter.success(f"Encrypted file '{meta.filename}' streamed to Bob ({meta.num_chunks} chunks)")

    reporter.section("Transfer Complete")
    reporter.success("File securely transferred using BB84 QKD + AES-256-GCM")
    reporter.info(f"Total time elapsed: {time.perf_counter() - t_start:.4f}s")
    report_summary(kx, meta.num_chunks, meta.chunk_size, reporter)
    return kx
