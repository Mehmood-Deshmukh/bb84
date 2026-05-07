#!/usr/bin/env python3
"""
Eve — Eavesdropper / Man-in-the-Middle in the BB84 QKD System.

Eve acts as a TCP proxy between Alice and Bob, intercepting the
quantum channel to perform an intercept-resend attack.

Intercept-Resend Attack:
  1. Eve receives qubits from Alice
  2. Eve measures each qubit in a random basis (collapsing the state)
  3. Eve re-prepares new qubits based on her measurement results
  4. Eve forwards the modified qubits to Bob

Due to the No-Cloning Theorem, Eve cannot copy the qubits without
measuring them. Her measurement disturbs the quantum states, introducing
approximately 25% QBER — well above the 11% security threshold.

This causes Alice and Bob to detect the eavesdropping and abort
the key exchange, demonstrating the security of BB84.

Usage:
    Terminal 1: python bob.py
    Terminal 2: python eve.py
    Terminal 3: python alice.py test_file.txt --eve-mode
"""

import json
import struct
import socket
import threading
import time

from config import (
    ALICE_HOST,
    BOB_PORT,
    EVE_PORT,
    BUFFER_SIZE,
)
from quantum_channel import eve_intercept_resend


# ─────────────────────────────────────────────
# Pretty Printing
# ─────────────────────────────────────────────

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"
    MAGENTA = "\033[35m"


def banner():
    print(f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║       👁  BB84 QKD — EVE (Eavesdropper / MITM)  👁     ║
║              ━━━ Intercept-Resend Attack ━━━             ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}""")


def eve_status(msg):
    print(f"  {Colors.RED}☠{Colors.END} {msg}")


def eve_success(msg):
    print(f"  {Colors.MAGENTA}▸{Colors.END} {msg}")


def section(title):
    print(f"\n{Colors.BOLD}{Colors.RED}{'─' * 58}{Colors.END}")
    print(f"  {Colors.BOLD}{Colors.RED}{title}{Colors.END}")
    print(f"{Colors.RED}{'─' * 58}{Colors.END}")


def send_json(sock, data):
    """Send JSON data with a 4-byte length prefix."""
    encoded = json.dumps(data).encode()
    sock.sendall(struct.pack(">I", len(encoded)))
    sock.sendall(encoded)


def recv_json(sock):
    """Receive JSON data with a 4-byte length prefix."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed")
    msg_len = struct.unpack(">I", raw_len)[0]
    data = _recv_exact(sock, msg_len)
    return json.loads(data.decode())


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed during receive")
        data += chunk
    return data


def forward_raw(src, dst):
    """Forward a length-prefixed message from src to dst unchanged."""
    raw_len = _recv_exact(src, 4)
    msg_len = struct.unpack(">I", raw_len)[0]
    data = _recv_exact(src, msg_len)
    dst.sendall(raw_len + data)
    return data


# ─────────────────────────────────────────────
# Main MITM Proxy
# ─────────────────────────────────────────────

def main():
    banner()

    # ── Setup: Listen for Alice, connect to Bob ──
    section("Setting up Man-in-the-Middle Proxy")

    # Connect to Bob first
    eve_status(f"Connecting to Bob at {ALICE_HOST}:{BOB_PORT}...")
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect((ALICE_HOST, BOB_PORT))
    eve_success(f"Connected to Bob")

    # Listen for Alice
    eve_status(f"Listening for Alice on port {EVE_PORT}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", EVE_PORT))
    server.listen(1)

    alice_sock, addr = server.accept()
    eve_success(f"Alice connected from {addr}")

    # ── Phase 1: Intercept Quantum Channel ──
    section("Phase 1: Intercepting Quantum Channel")

    eve_status("Intercepting qubits from Alice...")
    qasm_strings = recv_json(alice_sock)
    eve_success(f"Captured {len(qasm_strings)} qubits from Alice")

    eve_status("Performing intercept-resend attack...")
    eve_status("  → Measuring each qubit in random basis (destroying original state)")
    eve_status("  → Re-preparing new qubits based on measurement results")
    t0 = time.time()
    modified_qasm, eve_bits, eve_bases = eve_intercept_resend(qasm_strings)
    t1 = time.time()
    eve_success(f"Attack complete in {t1-t0:.2f}s")
    eve_success(f"Eve's intercepted bits: {eve_bits[:20]}... ({len(eve_bits)} total)")
    eve_success(f"Eve's bases used:       {eve_bases[:20]}...")

    # Count how many bases match (Eve's knowledge)
    eve_status("Forwarding modified qubits to Bob...")
    send_json(bob_sock, modified_qasm)
    eve_success("Modified qubits sent to Bob (state has been disturbed)")

    # ── Phase 2: Forward Classical Channel (transparent) ──
    section("Phase 2: Forwarding Classical Channel (Transparent)")

    eve_status("Forwarding Bob's bases to Alice...")
    data = forward_raw(bob_sock, alice_sock)
    bob_bases = json.loads(data.decode())
    eve_success(f"Bob's bases forwarded ({len(bob_bases)} entries)")

    eve_status("Forwarding Alice's bases to Bob...")
    data = forward_raw(alice_sock, bob_sock)
    alice_bases = json.loads(data.decode())
    eve_success(f"Alice's bases forwarded ({len(alice_bases)} entries)")

    eve_status("Forwarding decoy-state tags...")
    forward_raw(alice_sock, bob_sock)
    eve_success("Decoy tags forwarded")

    eve_status("Forwarding Bob's measured bits to Alice...")
    forward_raw(bob_sock, alice_sock)
    eve_success("Bob's bits forwarded")

    # ── Eve's Analysis ──
    section("Eve's Intelligence Gathering")

    # Count matching bases between Eve and Alice
    eve_alice_match = sum(1 for e, a in zip(eve_bases, alice_bases) if e == a)
    eve_bob_match = sum(1 for e, b in zip(eve_bases, bob_bases) if e == b)

    eve_success(f"Eve-Alice basis matches: {eve_alice_match}/{len(eve_bases)} "
                f"({eve_alice_match/len(eve_bases)*100:.1f}%)")
    eve_success(f"Eve-Bob basis matches:   {eve_bob_match}/{len(eve_bases)} "
                f"({eve_bob_match/len(eve_bases)*100:.1f}%)")
    eve_status("Eve knows ~25% of the sifted key bits (where all 3 bases align)")
    eve_status("But her interception has introduced ~25% QBER in the channel!")

    # ── Phase 3: Forward remaining protocol messages ──
    section("Phase 3: Waiting for Protocol Outcome")

    eve_status("Forwarding QBER analysis result...")
    data = forward_raw(alice_sock, bob_sock)
    qber_result = json.loads(data.decode())
    qber = qber_result["qber"]
    abort = qber_result["abort"]

    if abort:
        eve_status(f"QBER = {qber*100:.2f}% — Alice detected eavesdropping!")
        section("ATTACK FAILED ✗")
        eve_status("Alice and Bob have ABORTED the key exchange.")
        eve_status("The quantum channel disturbance revealed Eve's presence.")
        eve_status("No file will be transferred.")
        eve_status("")
        eve_status("This demonstrates the fundamental security of BB84:")
        eve_status("  • No-Cloning Theorem prevents copying quantum states")
        eve_status("  • Measurement Disturbance makes interception detectable")
        eve_status("  • QBER estimation catches the introduced errors")
    else:
        eve_success(f"QBER = {qber*100:.2f}% — Surprisingly low! Continuing...")
        # Forward remaining messages transparently
        try:
            while True:
                forward_raw(alice_sock, bob_sock)
        except Exception:
            pass

    alice_sock.close()
    bob_sock.close()
    server.close()


if __name__ == "__main__":
    main()
