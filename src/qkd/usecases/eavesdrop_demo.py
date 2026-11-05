"""
Eve's workflow: intercept-resend attack on the quantum channel, transparent
forwarding of the classical channel.

Eve forwards both hellos unchanged (steps 0a/0b; she reads the mode from Alice's),
then parses the next messages of the wire protocol (qubits, bases, matching
indices, QBER sample exchange, QBER verdict) and blindly forwards the rest.
Because she must measure each qubit in a guessed basis, she disturbs about 25%
of the sifted bits, which pushes the QBER over the threshold. The QBER abort at
step 3 happens before the finished exchange (4b), so in sign and hybrid modes the
run still ends in a QBER abort, not an authentication failure.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from typing import Optional

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


def _forward_hellos(alice: socket.socket, bob: socket.socket, reporter: Reporter) -> bool:
    """Forward steps 0a and 0b unchanged. Returns True when the peers run a signed mode."""
    reporter.section("Phase 0: Forwarding Authentication Hellos (Unchanged)")
    mode = json.loads(forward_message(alice, bob))["hello"]["mode"]   # 0a
    forward_message(bob, alice)                                       # 0b
    reporter.info(f"Hellos forwarded (mode: {mode})")
    return mode != "none"


def _intercept_qubits(alice: socket.socket, bob: socket.socket, reporter: Reporter, fraction: float) -> list[Optional[str]]:
    reporter.section("Phase 1: Intercepting Quantum Channel")
    reporter.info("Intercepting qubits from Alice...")
    qasm_strings = recv_json(alice)
    reporter.info(f"Captured {len(qasm_strings)} qubits from Alice")

    reporter.info(f"Performing intercept-resend attack on {fraction:.0%} of the qubits...")
    reporter.info("  → Measuring each attacked qubit in a random basis (destroying original state)")
    reporter.info("  → Re-preparing new qubits based on measurement results")
    t0 = time.time()
    modified_qasm, eve_bits, eve_bases = eve_intercept_resend(qasm_strings, fraction)
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


def _report_knowledge(eve_bases: list[Optional[str]], bob_bases: list[str], matching: list[int], reporter: Reporter) -> int:
    reporter.section("Eve's Intelligence Gathering")
    # Alice's bases are never sent; at matching indices they equal Bob's.
    known = sum(1 for i in matching if eve_bases[i] == bob_bases[i])
    pct = known / len(matching) * 100 if matching else 0.0
    reporter.info(f"Eve's exact knowledge of final key bits: {known}/{len(matching)} ({pct:.1f}%)")
    reporter.info("Of the bits she attacked, Eve knows ~50% exactly (where all 3 bases align)")
    reporter.info("Each attacked sifted bit is wrong for Bob with probability 1/4, which the QBER sample can see")
    return known


def _forward_rest(alice: socket.socket, bob: socket.socket, signed: bool) -> None:
    """Forward the salt, the finished exchange (signed modes), then file metadata and chunks until Alice disconnects."""
    try:
        forward_message(alice, bob)        # 4: salt
        if signed:
            forward_message(bob, alice)    # 4b: Bob's finished
            forward_message(alice, bob)    # 4b: Alice's finished
        while True:
            forward_message(alice, bob)
    except (ConnectionError, OSError):
        pass


def run_eavesdrop(
    alice: socket.socket,
    bob: socket.socket,
    reporter: Reporter,
    threshold: float = QBER_THRESHOLD,
    fraction: float = 1.0,
) -> EavesdropResult:
    """
    Run the intercept-resend attack between connected Alice and Bob sockets.

    `fraction` is the share of qubits Eve attacks (1.0 = all). `aborted` reflects
    only the QBER threshold; a later finite-key or key confirmation abort shows up
    as the peers closing the connection while she forwards the rest.
    """
    signed = _forward_hellos(alice, bob, reporter)
    eve_bases = _intercept_qubits(alice, bob, reporter, fraction)
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
        _forward_rest(alice, bob, signed)

    return EavesdropResult(sifted_length=len(matching), bits_known=known, qber=qber, aborted=aborted)
