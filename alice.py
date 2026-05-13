#!/usr/bin/env python3
"""
Alice — Sender in the BB84 QKD Secure File Transfer System.

Workflow:
  1. Connect to Bob (or Eve's proxy) via TCP
  2. Generate random bits, bases, and decoy-state intensity tags
  3. Prepare qubits and send over the quantum channel (socket)
  4. Exchange bases over the classical channel
  5. Perform basis sifting, decoy-state analysis, QBER estimation
  6. Run information reconciliation and privacy amplification
  7. Encrypt the file with AES-256-GCM using the quantum-derived key
  8. Transmit the encrypted file to Bob

Usage:
    python alice.py <file_to_send>
    python alice.py <file_to_send> --eve-mode   # Connect to Eve's proxy port
"""

import sys
import os
import json
import struct
import socket
import time

from config import (
    ALICE_HOST,
    BOB_PORT,
    EVE_PORT,
    BUFFER_SIZE,
    NUM_QUBITS,
    QBER_THRESHOLD,
    CHUNK_SIZE,
)
from quantum_channel import prepare_qubits, apply_channel_noise
from bb84_protocol import (
    generate_random_bits,
    generate_random_bases,
    tag_decoy_states,
    sift_keys,
    analyze_decoy_states,
    estimate_qber,
    reconcile_keys,
    privacy_amplification,
)
from crypto_utils import derive_aes_key, encrypt_chunk, derive_chunk_nonce


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
║          🔐  BB84 QKD Secure File Transfer  🔐           ║
║                    ━━━ ALICE (Sender) ━━━                ║
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
    raw_len = sock.recv(4)
    if not raw_len:
        raise ConnectionError("Connection closed")
    msg_len = struct.unpack(">I", raw_len)[0]
    data = b""
    while len(data) < msg_len:
        chunk = sock.recv(min(BUFFER_SIZE, msg_len - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed during receive")
        data += chunk
    return json.loads(data.decode())


def send_bytes(sock, data: bytes):
    """Send raw bytes with a 4-byte length prefix."""
    sock.sendall(struct.pack(">I", len(data)))
    sock.sendall(data)


# ─────────────────────────────────────────────
# Main Protocol
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python alice.py <file_to_send> [--eve-mode]")
        sys.exit(1)

    filepath = sys.argv[1]
    eve_mode = "--eve-mode" in sys.argv
    port = EVE_PORT if eve_mode else BOB_PORT

    banner()

    if eve_mode:
        warning(f"EVE MODE: Connecting to Eve's proxy at port {port}")
    else:
        status(f"Connecting to Bob at {ALICE_HOST}:{port}")

    # ── Step 1: Connect to Bob ──
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ALICE_HOST, port))
    success(f"Connected to {'Eve (proxy)' if eve_mode else 'Bob'}")

    # ── Step 2: Quantum Key Generation ──
    section("Phase 1: Quantum Key Distribution (BB84)")

    status(f"Generating {NUM_QUBITS} random bits and bases...")
    alice_bits = generate_random_bits(NUM_QUBITS)
    alice_bases = generate_random_bases(NUM_QUBITS)
    intensity_tags = tag_decoy_states(NUM_QUBITS)

    sig_count = intensity_tags.count("signal")
    dec_count = intensity_tags.count("decoy")
    vac_count = intensity_tags.count("vacuum")
    status(f"Decoy-state tagging: {sig_count} signal, {dec_count} decoy, {vac_count} vacuum")

    status("Preparing qubits (encoding bits in quantum states)...")
    t0 = time.time()
    qasm_strings = prepare_qubits(alice_bits, alice_bases)
    t1 = time.time()
    success(f"Prepared {NUM_QUBITS} qubits in {t1-t0:.2f}s")

    # Apply channel noise (simulating fiber-optic transmission)
    qasm_strings = apply_channel_noise(qasm_strings)
    status("Applied depolarizing channel noise")

    # ── Step 3: Send qubits to Bob ──
    status("Sending qubits over quantum channel...")
    send_json(sock, qasm_strings)
    success("Qubits transmitted ⟩⟩⟩")

    # ── Step 4: Classical Channel — Basis Exchange ──
    section("Phase 2: Classical Channel (Basis Exchange)")

    status("Waiting for Bob's measurement bases...")
    bob_bases = recv_json(sock)
    success(f"Received Bob's bases ({len(bob_bases)} entries)")

    status("Sending Alice's bases...")
    send_json(sock, alice_bases)

    # Send intensity tags for decoy analysis
    status("Sending decoy-state intensity tags...")
    send_json(sock, intensity_tags)

    # ── Step 5: Basis Sifting ──
    section("Phase 3: Key Sifting & Security Verification")

    status("Waiting for Bob's measured bits...")
    bob_bits = recv_json(sock)

    sifted_alice, sifted_bob, sifted_tags = sift_keys(
        alice_bits, alice_bases, bob_bits, bob_bases, intensity_tags
    )
    success(f"Sifted key: {len(sifted_alice)} bits (from {NUM_QUBITS} raw qubits)")
    status(f"Sift rate: {len(sifted_alice)/NUM_QUBITS*100:.1f}%")

    # ── Step 6: Decoy-State Analysis ──
    status("Running decoy-state analysis...")
    decoy_stats, decoy_safe, decoy_msg = analyze_decoy_states(
        sifted_alice, sifted_bob, sifted_tags
    )
    for line in decoy_msg.split("\n"):
        if "ATTACK" in line:
            error(line.strip())
        else:
            status(line.strip(), Colors.DIM)

    if not decoy_safe:
        error("ABORTING: Photon Number Splitting attack detected!")
        send_json(sock, {"abort": True, "reason": "PNS attack detected"})
        sock.close()
        sys.exit(1)

    # ── Step 7: QBER Estimation ──
    status("Estimating Quantum Bit Error Rate (QBER)...")
    qber, remaining_alice, remaining_bob, sample_indices = estimate_qber(sifted_alice, sifted_bob)

    if qber < QBER_THRESHOLD:
        success(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — Channel is SECURE")
    else:
        error(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — EAVESDROPPER DETECTED!")

    # Send QBER result + sample indices to Bob so he discards the same bits
    send_json(sock, {
        "qber": qber,
        "abort": qber >= QBER_THRESHOLD,
        "sample_indices": sample_indices,
    })

    if qber >= QBER_THRESHOLD:
        error("ABORTING: QBER exceeds security threshold!")
        error("The quantum channel has been compromised.")
        error("Possible intercept-resend attack by an eavesdropper.")
        sock.close()
        sys.exit(1)

    # ── Step 8: Information Reconciliation ──
    section("Phase 4: Key Distillation")

    status(f"Information reconciliation on {len(remaining_alice)} bits...")
    reconciled_alice, reconciled_bob, errors_fixed = reconcile_keys(
        remaining_alice, remaining_bob
    )
    success(f"Reconciliation complete: {errors_fixed} errors corrected")

    # Compute correction mask: which bit positions Bob needs to flip
    corrections = [i for i in range(len(remaining_alice))
                   if remaining_bob[i] != reconciled_bob[i]]
    send_json(sock, {"corrections": corrections, "key_length": len(reconciled_alice)})

    # ── Step 9: Privacy Amplification ──
    status("Privacy amplification (SHA-256 universal hashing)...")
    salt, final_key = privacy_amplification(reconciled_alice)
    success(f"Final key: {len(final_key) * 8}-bit AES key derived")
    status(f"Key (hex): {final_key.hex()[:32]}...")

    # Send salt to Bob so he can derive the same key
    send_json(sock, {"salt": salt.hex()})

    # ── Step 10: Chunked File Encryption & Streaming Transfer ──
    section("Phase 5: Secure File Transfer (Chunked Streaming)")

    aes_key = derive_aes_key(final_key)

    file_size = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 0
    base_nonce = os.urandom(8)  # 8 bytes; extended with 4-byte counter per chunk

    status(f"File: {filename} ({file_size} bytes)")
    status(f"Streaming as {num_chunks} chunk(s) of {CHUNK_SIZE // 1024} KB")

    # Send file metadata
    file_meta = {
        "filename": filename,
        "total_size": file_size,
        "chunk_size": CHUNK_SIZE,
        "num_chunks": num_chunks,
        "base_nonce": base_nonce.hex(),
    }
    send_json(sock, file_meta)

    # Stream: read chunk → encrypt → send
    with open(filepath, "rb") as f:
        for i in range(num_chunks):
            plaintext_chunk = f.read(CHUNK_SIZE)
            nonce = derive_chunk_nonce(base_nonce, i)
            ciphertext, tag = encrypt_chunk(plaintext_chunk, aes_key, nonce)
            # Send tag (16 B) + ciphertext as one length-prefixed message
            send_bytes(sock, tag + ciphertext)

            if (i + 1) % 100 == 0 or i == num_chunks - 1:
                pct = (i + 1) / num_chunks * 100
                status(f"  Sent chunk {i+1}/{num_chunks} ({pct:.1f}%)")

    success(f"Encrypted file '{filename}' streamed to Bob ({num_chunks} chunks)")

    # ── Done ──
    section("Transfer Complete")
    success(f"File securely transferred using BB84 QKD + AES-256-GCM")
    status(f"Quantum key bits used: {NUM_QUBITS}")
    status(f"Sifted key length: {len(sifted_alice)} bits")
    status(f"Final key length: {len(final_key) * 8} bits")
    status(f"QBER: {qber*100:.2f}%")
    status(f"Errors corrected: {errors_fixed}")
    status(f"File chunks: {num_chunks} × {CHUNK_SIZE // 1024} KB")

    sock.close()


if __name__ == "__main__":
    main()