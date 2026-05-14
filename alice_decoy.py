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

from __future__ import annotations
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

from crypto_utils import derive_aes_key, derive_chunk_nonce, encrypt_chunk


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

    total_start = time.perf_counter()

    filepath = sys.argv[1]
    eve_mode = "--eve-mode" in sys.argv
    
    host = ALICE_HOST
    port = EVE_PORT if eve_mode else BOB_PORT

    if "--host" in sys.argv:
        host = sys.argv[sys.argv.index("--host") + 1]
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])

    if eve_mode:
        warning(f"EVE MODE: Connecting to Eve's proxy at {host}:{port}")
    else:
        status(f"Connecting to Bob at {host}:{port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    max_retries = 15
    for attempt in range(max_retries):
        try:
            sock.connect((host, port))
            break
        except ConnectionRefusedError:
            if attempt < max_retries - 1:
                time.sleep(1.0)
            else:
                error(f"Failed to connect to {host}:{port} after {max_retries} attempts.")
                sys.exit(1)
                
    success(f"Connected to {'Eve (proxy)' if eve_mode else 'Bob'}")

    section("Phase 1: Quantum Key Distribution (BB84)")

    status(f"Generating {NUM_QUBITS} random bits and bases...")
    t_bits_start = time.perf_counter()
    alice_bits = generate_random_bits(NUM_QUBITS)
    alice_bases = generate_random_bases(NUM_QUBITS)
    intensity_tags = tag_decoy_states(NUM_QUBITS)
    t_bits_end = time.perf_counter()
    status(f"Generated in {t_bits_end - t_bits_start:.4f}s")

    status("Preparing qubits (encoding bits in quantum states)...")
    t0 = time.perf_counter()
    qasm_strings = prepare_qubits(alice_bits, alice_bases)
    t1 = time.perf_counter()
    success(f"Prepared {NUM_QUBITS} qubits in {t1-t0:.4f}s")

    # Qubits are transmitted noiselessly in this simplified protocol
    status("Sending qubits over quantum channel...")
    t_send_start = time.perf_counter()
    send_json(sock, qasm_strings)
    t_send_end = time.perf_counter()
    success(f"Qubits transmitted ⟩⟩⟩ in {t_send_end - t_send_start:.4f}s")


    section("Phase 2: Classical Channel (Basis Exchange)")

    status("Waiting for Bob's measurement bases...")
    t_basis_ex_start = time.perf_counter()
    bob_bases = recv_json(sock)
    t_basis_ex_end = time.perf_counter()
    success(f"Received Bob's bases ({len(bob_bases)} entries) in {t_basis_ex_end - t_basis_ex_start:.4f}s")

    section("Phase 3: Key Sifting & QBER Estimation")

    t_sift_start = time.perf_counter()
    matching_indices = [i for i in range(NUM_QUBITS) if alice_bases[i] == bob_bases[i]]
    sifted_alice = [alice_bits[i] for i in matching_indices]
    sifted_tags = [intensity_tags[i] for i in matching_indices]
    t_sift_end = time.perf_counter()
    success(f"Sifted key: {len(sifted_alice)} bits in {t_sift_end - t_sift_start:.4f}s")
    status(f"Sift rate: {len(sifted_alice)/NUM_QUBITS*100:.1f}%")

    status("Sending matching indices to Bob...")
    send_json(sock, matching_indices)

    status("Estimating Quantum Bit Error Rate (QBER)...")
    t_qber_start = time.perf_counter()
    import random
    from config import QBER_SAMPLE_FRACTION
    sample_size = max(1, int(len(sifted_alice) * QBER_SAMPLE_FRACTION))
    sample_indices = sorted(random.sample(range(len(sifted_alice)), min(sample_size, len(sifted_alice))))
    alice_sample_bits = [sifted_alice[i] for i in sample_indices]
    alice_sample_tags = [sifted_tags[i] for i in sample_indices]

    status("Sending sample indices to Bob for QBER estimation...")
    send_json(sock, {"sample_indices": sample_indices})

    status("Waiting for Bob's sample bits...")
    bob_req = recv_json(sock)
    bob_sample_bits = bob_req["sample_bits"]

    qber, _, _, _ = estimate_qber(alice_sample_bits, bob_sample_bits, sample_fraction=1.0)
    t_qber_end = time.perf_counter()
    status(f"QBER estimated in {t_qber_end - t_qber_start:.4f}s")

    status("Performing Decoy-State Analysis...")
    stats, is_safe, msg = analyze_decoy_states(alice_sample_bits, bob_sample_bits, alice_sample_tags)
    if is_safe:
        success(msg)
    else:
        error(msg)
        error("Photon Number Splitting (PNS) attack detected. Channel compromised!")
        sock.close()
        sys.exit(1)

    send_json(sock, {"qber": qber})

    if qber < QBER_THRESHOLD:
        success(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — Channel is SECURE")
    else:
        error(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — EAVESDROPPER DETECTED!")
        error("The quantum channel has been compromised.")
        sock.close()
        sys.exit(1)


    section("Phase 4: Key Distillation")

    remaining_alice = [sifted_alice[i] for i in range(len(sifted_alice)) if i not in sample_indices]

    status("Privacy amplification (SHA-256 universal hashing)...")
    t_priv_start = time.perf_counter()
    salt, final_key = privacy_amplification(remaining_alice)
    t_priv_end = time.perf_counter()
    success(f"Final key: {len(final_key) * 8}-bit AES key derived in {t_priv_end - t_priv_start:.4f}s")
    status(f"Key (hex): {final_key.hex()[:32]}...")


    send_json(sock, {"salt": salt.hex()})


    section("Phase 5: Secure File Transfer")
    section("Phase 5: Secure File Transfer (Chunked Streaming)")

    aes_key = derive_aes_key(final_key)

    file_size = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 0
    base_nonce = os.urandom(8)  # 8 bytes; extended with 4-byte counter per chunk

    status(f"File: {filename} ({file_size} bytes)")
    status(f"Streaming as {num_chunks} chunk(s) of {CHUNK_SIZE // 1024} KB")

    t_file_start = time.perf_counter()

    file_meta = {
        "filename": filename,
        "total_size": file_size,
        "chunk_size": CHUNK_SIZE,
        "num_chunks": num_chunks,
        "base_nonce": base_nonce.hex(),
    }
    send_json(sock, file_meta)

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

    t_file_end = time.perf_counter()
    success(f"Encrypted file '{filename}' streamed to Bob ({num_chunks} chunks) in {t_file_end - t_file_start:.4f}s")

    total_end = time.perf_counter()
    section("Transfer Complete")
    success(f"File securely transferred using BB84 QKD + AES-256-GCM")
    status(f"Total time elapsed: {total_end - total_start:.4f}s")
    status(f"Quantum key bits used: {NUM_QUBITS}")
    status(f"Sifted key length: {len(sifted_alice)} bits")
    status(f"Final key length: {len(final_key) * 8} bits")
    status(f"QBER: {qber*100:.2f}%")
    status(f"File chunks: {num_chunks} × {CHUNK_SIZE // 1024} KB")

    sock.close()


if __name__ == "__main__":
    main()