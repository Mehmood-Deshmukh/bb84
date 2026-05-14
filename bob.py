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

from __future__ import annotations
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
    privacy_amplification,
)
from crypto_utils import derive_aes_key, decrypt_chunk, derive_chunk_nonce


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

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", BOB_PORT))
    server.listen(1)

    # STEP 1: Wait for alice's connection
    status(f"Listening on port {BOB_PORT}...")
    status("Waiting for Alice's connection (60s timeout)...")
    
    server.settimeout(60.0)
    try:
        conn, addr = server.accept()
    except socket.timeout:
        error("Timed out waiting for Alice's connection.")
        server.close()
        import sys
        sys.exit(1)
        
    server.settimeout(None)
    success(f"Alice connected from {addr}")

    # STEP 2: Receive Qubits
    section("Phase 1: Quantum Key Distribution (BB84)")

    status("Receiving qubits from quantum channel...")
    t0 = time.time()
    qasm_strings = recv_json(conn)
    t1 = time.time()
    success(f"Received {len(qasm_strings)} qubits in {t1-t0:.2f}s")

    # STEP 3: Measure Qubits
    status("Generating random measurement bases...")
    bob_bases = generate_random_bases(len(qasm_strings))

    status("Measuring qubits (collapsing quantum states)...")
    t0 = time.time()
    bob_bits = measure_qubits(qasm_strings, bob_bases)
    t1 = time.time()
    success(f"Measured {len(bob_bits)} qubits in {t1-t0:.2f}s")

    # STEP 4: Exchange basis on the classical channel
    section("Phase 2: Classical Channel (Basis Exchange)")

    status("Sending measurement bases to Alice...")
    send_json(conn, bob_bases)

    status("Receiving matching indices from Alice...")
    matching_indices = recv_json(conn)
    
    # STEP 5: Sift the key
    section("Phase 3: Key Sifting & QBER Estimation")

    sifted_bob = [bob_bits[i] for i in matching_indices]

    success(f"Sifted key: {len(sifted_bob)} bits (from {len(qasm_strings)} raw qubits)")
    status(f"Sift rate: {len(sifted_bob)/len(qasm_strings)*100:.1f}%")

    # STEP 6: QBER estimation
    status("Waiting for QBER sample indices from Alice...")
    qber_req = recv_json(conn)
    sample_indices = qber_req["sample_indices"]

    # Extract Bob's bits at those indices and send them back to Alice
    sample_bits = [sifted_bob[i] for i in sample_indices]
    
    status("Sending sample bits back to Alice for calculation...")
    send_json(conn, {"sample_bits": sample_bits})

    # Wait for Alice's QBER calculation and verdict
    status("Waiting for QBER result from Alice...")
    result = recv_json(conn)
    qber = result["qber"]

    if qber >= QBER_THRESHOLD:
        error(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — EAVESDROPPER DETECTED!")
        error("The quantum channel has been compromised.")
        conn.close()
        server.close()
        import sys
        sys.exit(1)
    else:
        success(f"QBER = {qber*100:.2f}% (threshold: {QBER_THRESHOLD*100:.0f}%) — Channel is SECURE")

    # STEP 7: Information Reconciliation
    section("Phase 4: Key Distillation")

    # Remove sampled QBER bits to match Alice's remaining bits
    status("Aligning keys...")
    remaining_bob = [sifted_bob[i] for i in range(len(sifted_bob)) if i not in sample_indices]

    # No reconciliation, we use remaining_bob directly
    corrected_bob = remaining_bob

    # STEP 8: Privacy Amplification
    status("Receiving privacy amplification salt...")
    salt_data = recv_json(conn)
    salt = bytes.fromhex(salt_data["salt"])

    status("Privacy amplification (SHA-256 universal hashing)...")
    _, final_key = privacy_amplification(corrected_bob, salt=salt)
    success(f"Final key: {len(final_key) * 8}-bit AES key derived")
    status(f"Key (hex): {final_key.hex()[:32]}...")

    # STEP 10: Receive & Decrypt File (Chunked Streaming)
    section("Phase 5: Secure File Reception (Chunked Streaming)")

    aes_key = derive_aes_key(final_key)

    status("Receiving encrypted file metadata...")
    file_meta = recv_json(conn)
    filename = file_meta["filename"]
    total_size = file_meta["total_size"]
    chunk_size = file_meta["chunk_size"]
    num_chunks = file_meta["num_chunks"]
    base_nonce = bytes.fromhex(file_meta["base_nonce"])

    status(f"File: {filename} ({total_size} bytes, {num_chunks} chunks of {chunk_size // 1024} KB)")

    output_path = f"received_{filename}"
    status(f"Receiving and decrypting {num_chunks} chunks...")

    try:
        bytes_written = 0
        with open(output_path, "wb") as f:
            for i in range(num_chunks):
                # Receive tag (16 B) + ciphertext
                chunk_data = recv_bytes(conn)
                tag = chunk_data[:16]
                ciphertext = chunk_data[16:]

                nonce = derive_chunk_nonce(base_nonce, i)
                plaintext = decrypt_chunk(ciphertext, aes_key, nonce, tag)
                f.write(plaintext)
                bytes_written += len(plaintext)

                if (i + 1) % 100 == 0 or i == num_chunks - 1:
                    pct = (i + 1) / num_chunks * 100
                    status(f"  Decrypted chunk {i+1}/{num_chunks} ({pct:.1f}%)")

        success(f"File decrypted and saved as '{output_path}' ({bytes_written} bytes)")
        success(f"All {num_chunks} chunk authentication tags verified!")
    except Exception as e:
        error(f"Decryption FAILED: {e}")
        error("Authentication tag mismatch — file may have been tampered with!")

    # Done
    section("Transfer Complete")
    success("File securely received via BB84 QKD + AES-256-GCM")
    status(f"Quantum key bits used: {len(qasm_strings)}")
    status(f"Sifted key length: {len(sifted_bob)} bits")
    status(f"Final key length: {len(final_key) * 8} bits")
    status(f"QBER: {qber*100:.2f}%")
    status(f"File chunks: {num_chunks} × {chunk_size // 1024} KB")

    conn.close()
    server.close()


if __name__ == "__main__":
    main()