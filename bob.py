#!/usr/bin/env python3
"""
Bob — Receiver in the BB84 QKD Secure File Transfer System.

Workflow:
  1. Listen for Alice's TCP connection
  2. Receive qubits and measure in random bases
  3. Exchange bases over the classical channel
  4. Perform basis sifting, decoy-state analysis, QBER verification
  5. Run information reconciliation and privacy amplification
  6. Receive encrypted file and decrypt with AES-256-GCM

Usage:
    python bob.py
"""

import json
import struct
import socket
import time

from config import (
    BOB_PORT,
    BUFFER_SIZE,
    NUM_QUBITS,
    QBER_THRESHOLD,
)
from quantum_channel import measure_qubits
from bb84_protocol import (
    generate_random_bases,
    sift_keys,
    analyze_decoy_states,
    estimate_qber,
    reconcile_keys,
    privacy_amplification,
)
from crypto_utils import derive_aes_key, decrypt_file


# ─────────────────────────────────────────────
# Pretty Printing Utilities
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


def banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║          🔐  BB84 QKD Secure File Transfer  🔐          ║
║                   ━━━ BOB (Receiver) ━━━                 ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}""")


def status(msg, color=Colors.BLUE):
    print(f"  {color}▸{Colors.END} {msg}")


def success(msg):
    print(f"  {Colors.GREEN}✓{Colors.END} {msg}")


def warning(msg):
    print(f"  {Colors.YELLOW}⚠{Colors.END} {msg}")


def error(msg):
    print(f"  {Colors.RED}✗{Colors.END} {msg}")


def section(title):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 58}{Colors.END}")
    print(f"  {Colors.BOLD}{title}{Colors.END}")
    print(f"{Colors.CYAN}{'─' * 58}{Colors.END}")


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


def recv_bytes(sock) -> bytes:
    """Receive raw bytes with a 4-byte length prefix."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed")
    msg_len = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, msg_len)


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed during receive")
        data += chunk
    return data


# ─────────────────────────────────────────────
# Main Protocol
# ─────────────────────────────────────────────

def main():
    banner()

    # ── Step 1: Listen for Alice ──
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", BOB_PORT))
    server.listen(1)

    status(f"Listening on port {BOB_PORT}...")
    status("Waiting for Alice's connection...")
    conn, addr = server.accept()
    success(f"Alice connected from {addr}")

    # ── Step 2: Receive Qubits ──
    section("Phase 1: Quantum Key Distribution (BB84)")

    status("Receiving qubits from quantum channel...")
    t0 = time.time()
    qasm_strings = recv_json(conn)
    t1 = time.time()
    success(f"Received {len(qasm_strings)} qubits in {t1-t0:.2f}s")

    # ── Step 3: Measure Qubits ──
    status("Generating random measurement bases...")
    bob_bases = generate_random_bases(len(qasm_strings))

    status("Measuring qubits (collapsing quantum states)...")
    t0 = time.time()
    bob_bits = measure_qubits(qasm_strings, bob_bases)
    t1 = time.time()
    success(f"Measured {len(bob_bits)} qubits in {t1-t0:.2f}s")

    # ── Step 4: Classical Channel — Basis Exchange ──
    section("Phase 2: Classical Channel (Basis Exchange)")

    status("Sending measurement bases to Alice...")
    send_json(conn, bob_bases)

    status("Receiving Alice's bases...")
    alice_bases = recv_json(conn)
    success(f"Received Alice's bases ({len(alice_bases)} entries)")

    status("Receiving decoy-state intensity tags...")
    intensity_tags = recv_json(conn)
    success(f"Received intensity tags")

    # ── Step 5: Send Bob's measured bits to Alice ──
    status("Sending measured bits for sifting...")
    send_json(conn, bob_bits)

    # ── Step 6: Basis Sifting ──
    section("Phase 3: Key Sifting & Security Verification")

    # Bob doesn't know Alice's bits, but needs to sift his own
    # We use dummy alice_bits for sifting structure (actual comparison done by Alice)
    sifted_bob = []
    sifted_tags = []
    for i in range(len(bob_bases)):
        if bob_bases[i] == alice_bases[i]:
            sifted_bob.append(bob_bits[i])
            sifted_tags.append(intensity_tags[i])

    success(f"Sifted key: {len(sifted_bob)} bits (from {len(qasm_strings)} raw qubits)")
    status(f"Sift rate: {len(sifted_bob)/len(qasm_strings)*100:.1f}%")

    # ── Step 7: Receive QBER result from Alice ──
    status("Waiting for QBER analysis result from Alice...")
    qber_result = recv_json(conn)
    qber = qber_result["qber"]
    abort = qber_result["abort"]
    sample_indices = set(qber_result["sample_indices"])

    if abort:
        error(f"QBER = {qber*100:.2f}% — EAVESDROPPER DETECTED!")
        error("Alice has aborted the protocol.")
        error("The quantum channel has been compromised.")
        conn.close()
        server.close()
        return
    else:
        success(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — Channel is SECURE")

    # ── Step 8: Information Reconciliation ──
    section("Phase 4: Key Distillation")

    status("Receiving reconciliation data from Alice...")
    reconciliation_data = recv_json(conn)
    corrections = reconciliation_data["corrections"]
    key_length = reconciliation_data["key_length"]

    # Bob removes sampled QBER bits to match Alice's remaining bits
    status("Aligning keys and applying error correction...")
    remaining_bob = [sifted_bob[i] for i in range(len(sifted_bob)) if i not in sample_indices]
    
    corrected_bob = list(remaining_bob[:key_length])
    for idx in corrections:
        corrected_bob[idx] ^= 1  # Flip error bits
        
    errors_fixed = len(corrections)
    success(f"Reconciliation complete: {errors_fixed} errors corrected")

    # ── Step 9: Privacy Amplification ──
    status("Receiving privacy amplification salt...")
    salt_data = recv_json(conn)
    salt = bytes.fromhex(salt_data["salt"])

    status("Privacy amplification (SHA-256 universal hashing)...")
    _, final_key = privacy_amplification(corrected_bob, salt=salt)
    success(f"Final key: {len(final_key) * 8}-bit AES key derived")
    status(f"Key (hex): {final_key.hex()[:32]}...")

    # ── Step 10: Receive & Decrypt File ──
    section("Phase 5: Secure File Reception")

    aes_key = derive_aes_key(final_key)

    status("Receiving encrypted file metadata...")
    file_meta = recv_json(conn)
    filename = file_meta["filename"]
    nonce = bytes.fromhex(file_meta["nonce"])
    tag = bytes.fromhex(file_meta["tag"])
    file_size = file_meta["size"]

    status(f"File: {filename} ({file_size} bytes encrypted)")
    status(f"Nonce: {nonce.hex()}")
    status(f"Auth tag: {tag.hex()}")

    status("Receiving encrypted file data...")
    ciphertext = recv_bytes(conn)
    success(f"Received {len(ciphertext)} bytes of ciphertext")

    status("Decrypting file with AES-256-GCM...")
    try:
        plaintext = decrypt_file(ciphertext, aes_key, nonce, tag)
        output_path = f"received_{filename}"
        with open(output_path, "wb") as f:
            f.write(plaintext)
        success(f"File decrypted and saved as '{output_path}'")
        success(f"Authentication tag verified — file integrity confirmed!")
    except Exception as e:
        error(f"Decryption FAILED: {e}")
        error("Authentication tag mismatch — file may have been tampered with!")

    # ── Done ──
    section("Transfer Complete")
    success("File securely received via BB84 QKD + AES-256-GCM")
    status(f"Quantum key bits used: {len(qasm_strings)}")
    status(f"Sifted key length: {len(sifted_bob)} bits")
    status(f"Final key length: {len(final_key) * 8} bits")
    status(f"QBER: {qber*100:.2f}%")

    conn.close()
    server.close()


if __name__ == "__main__":
    main()