"""
Eve's workflow: intercept-resend attack on the quantum channel, transparent
forwarding of the classical channel.

Eve parses the first messages of the wire protocol (qubits, bases, matching
indices, QBER sample exchange, QBER verdict) and then blindly forwards the rest.
Because she must measure each qubit in a guessed basis, she disturbs about 25%
of the sifted bits, which pushes the QBER over the threshold.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass

from qkd.core.bb84_protocol import qber_exceeds_threshold
from qkd.core.config import QBER_THRESHOLD
from qkd.core.quantum_channel import eve_intercept_resend
from qkd.services.reporting import Reporter
from qkd.services.wire import forward_message, recv_json, send_json


@dataclass(frozen=True)
class EavesdropResult:
    sifted_length: int
    bits_known: int  # sifted positions where Eve's basis matched Bob's
    qber: float
    aborted: bool


def _intercept_qubits(alice: socket.socket, bob: socket.socket, reporter: Reporter) -> list[str]:
    reporter.section("Phase 1: Intercepting Quantum Channel")
    reporter.info("Intercepting qubits from Alice...")
    qasm_strings = recv_json(alice)
    reporter.info(f"Captured {len(qasm_strings)} qubits from Alice")

    reporter.info("Performing intercept-resend attack...")
    reporter.info("  → Measuring each qubit in random basis (destroying original state)")
    reporter.info("  → Re-preparing new qubits based on measurement results")
    t0 = time.time()
    modified_qasm, eve_bits, eve_bases = eve_intercept_resend(qasm_strings)
    reporter.info(f"Attack complete in {time.time() - t0:.2f}s")
    reporter.info(f"Eve's intercepted bits: {eve_bits[:20]}... ({len(eve_bits)} total)")
    reporter.info(f"Eve's bases used:       {eve_bases[:20]}...")

    reporter.info("Forwarding modified qubits to Bob...")
    send_json(bob, modified_qasm)
    reporter.info("Modified qubits sent to Bob (state has been disturbed)")
    return eve_bases


def _forward_sifting(alice: socket.socket, bob: socket.socket, reporter: Reporter) -> tuple[list[str], list[int]]:
    reporter.section("Phase 2: Forwarding Classical Channel (Transparent)")
    reporter.info("Forwarding Bob's bases to Alice...")
    bob_bases = json.loads(forward_message(bob, alice))
    reporter.info(f"Bob's bases forwarded ({len(bob_bases)} entries)")

    reporter.info("Forwarding matching indices to Bob...")
    matching = json.loads(forward_message(alice, bob))
    reporter.info(f"Matching indices forwarded ({len(matching)} entries)")

    reporter.info("Forwarding sample indices to Bob...")
    forward_message(alice, bob)
    reporter.info("Sample indices forwarded")

    reporter.info("Forwarding Bob's sample bits to Alice...")
    forward_message(bob, alice)
    reporter.info("Bob's sample bits forwarded")
    return bob_bases, matching


def _report_knowledge(eve_bases: list[str], bob_bases: list[str], matching: list[int], reporter: Reporter) -> int:
    reporter.section("Eve's Intelligence Gathering")
    # Alice's bases are never sent; at matching indices they equal Bob's.
    known = sum(1 for i in matching if eve_bases[i] == bob_bases[i])
    pct = known / len(matching) * 100 if matching else 0.0
    reporter.info(f"Eve's exact knowledge of final key bits: {known}/{len(matching)} ({pct:.1f}%)")
    reporter.info("Eve knows ~50% of the sifted key bits (where all 3 bases align)")
    reporter.info("But her interception has introduced ~25% QBER in the channel!")
    return known


def _forward_rest(alice: socket.socket, bob: socket.socket) -> None:
    """Forward Alice's remaining messages (salt, file metadata, chunks) until she disconnects."""
    try:
        while True:
            forward_message(alice, bob)
    except (ConnectionError, OSError):
        pass


def run_eavesdrop(alice: socket.socket, bob: socket.socket, reporter: Reporter, threshold: float = QBER_THRESHOLD) -> EavesdropResult:
    """Run the intercept-resend attack between connected Alice and Bob sockets."""
    eve_bases = _intercept_qubits(alice, bob, reporter)
    bob_bases, matching = _forward_sifting(alice, bob, reporter)
    known = _report_knowledge(eve_bases, bob_bases, matching, reporter)

    reporter.section("Phase 3: Waiting for Protocol Outcome")
    reporter.info("Forwarding QBER analysis result...")
    qber = json.loads(forward_message(alice, bob))["qber"]
    aborted = qber_exceeds_threshold(qber, threshold)

    if aborted:
        reporter.info(f"QBER = {qber*100:.2f}% — Alice detected eavesdropping!")
        reporter.section("ATTACK FAILED")
        reporter.info("Alice and Bob have ABORTED the key exchange.")
        reporter.info("The quantum channel disturbance revealed Eve's presence.")
        reporter.info("No file will be transferred.")
        reporter.info("This demonstrates the fundamental security of BB84:")
        reporter.info("  • No-Cloning Theorem prevents copying quantum states")
        reporter.info("  • Measurement Disturbance makes interception detectable")
        reporter.info("  • QBER estimation catches the introduced errors")
    else:
        reporter.info(f"QBER = {qber*100:.2f}% — Surprisingly low! Continuing...")
        _forward_rest(alice, bob)

    return EavesdropResult(sifted_length=len(matching), bits_known=known, qber=qber, aborted=aborted)
