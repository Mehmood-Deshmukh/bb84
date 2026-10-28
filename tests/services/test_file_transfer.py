"""
End-to-end file transfer tests over TCP sockets.

Simulates Alice (sender) and Bob (receiver) running Phase 5 of the
BB84 protocol — chunked streaming file encryption and transfer — using
a pre-shared AES key over localhost TCP sockets.

Tests verify that files of various sizes are transferred intact,
including edge cases like empty files and exact chunk boundaries.
"""

import os
import sys
import json
import math
import struct
import socket
import shutil
import threading
import tempfile
import time
import unittest

from qkd.core.crypto_utils import derive_aes_key, encrypt_chunk, decrypt_chunk, derive_chunk_nonce
from qkd.core.config import CHUNK_SIZE, BUFFER_SIZE


# ─────────────────────────────────────────────
# Socket helpers (replicated from alice.py / bob.py
# to avoid importing qiskit as a test dependency)
# ─────────────────────────────────────────────

def _recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def send_json(sock, data):
    encoded = json.dumps(data).encode()
    sock.sendall(struct.pack(">I", len(encoded)))
    sock.sendall(encoded)


def recv_json(sock):
    raw_len = _recv_exact(sock, 4)
    msg_len = struct.unpack(">I", raw_len)[0]
    data = _recv_exact(sock, msg_len)
    return json.loads(data.decode())


def send_bytes(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)))
    sock.sendall(data)


def recv_bytes(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    msg_len = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, msg_len)


# ─────────────────────────────────────────────
# Sender / Receiver (Phase 5 logic extracted)
# ─────────────────────────────────────────────

def alice_send_file(sock, filepath, aes_key):
    """Simulate Alice's Phase 5: chunked streaming file transfer."""
    file_size = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    num_chunks = math.ceil(file_size / CHUNK_SIZE) if file_size > 0 else 0
    base_nonce = os.urandom(8)

    send_json(sock, {
        "filename": filename,
        "total_size": file_size,
        "chunk_size": CHUNK_SIZE,
        "num_chunks": num_chunks,
        "base_nonce": base_nonce.hex(),
    })

    with open(filepath, "rb") as f:
        for i in range(num_chunks):
            plaintext_chunk = f.read(CHUNK_SIZE)
            nonce = derive_chunk_nonce(base_nonce, i)
            ciphertext, tag = encrypt_chunk(plaintext_chunk, aes_key, nonce)
            send_bytes(sock, tag + ciphertext)

    sock.close()


def bob_receive_file(sock, output_dir, aes_key):
    """Simulate Bob's Phase 5: chunked streaming file reception."""
    file_meta = recv_json(sock)
    filename = file_meta["filename"]
    total_size = file_meta["total_size"]
    num_chunks = file_meta["num_chunks"]
    base_nonce = bytes.fromhex(file_meta["base_nonce"])

    output_path = os.path.join(output_dir, f"received_{filename}")

    bytes_written = 0
    with open(output_path, "wb") as f:
        for i in range(num_chunks):
            chunk_data = recv_bytes(sock)
            tag = chunk_data[:16]
            ciphertext = chunk_data[16:]

            nonce = derive_chunk_nonce(base_nonce, i)
            plaintext = decrypt_chunk(ciphertext, aes_key, nonce, tag)
            f.write(plaintext)
            bytes_written += len(plaintext)

    sock.close()
    return output_path, bytes_written


# ─────────────────────────────────────────────
# Test Suite
# ─────────────────────────────────────────────

class TestFileTransfer(unittest.TestCase):
    """End-to-end chunked file transfer tests over TCP sockets."""

    def setUp(self):
        self.key = derive_aes_key(os.urandom(32))
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_test_file(self, name: str, size: int) -> str:
        """Create a test file with random data (writes in 1 MB chunks)."""
        path = os.path.join(self.tmpdir, name)
        remaining = size
        with open(path, "wb") as f:
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                f.write(os.urandom(chunk))
                remaining -= chunk
        return path

    def _transfer(self, filepath: str) -> str:
        """Run sender→receiver transfer over a localhost socket pair."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        result = {}
        errors = {}

        def run_receiver():
            try:
                conn, _ = server.accept()
                path, size = bob_receive_file(conn, self.tmpdir, self.key)
                result["path"] = path
                result["size"] = size
            except Exception as e:
                errors["receiver"] = e
            finally:
                server.close()

        def run_sender():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", port))
                alice_send_file(sock, filepath, self.key)
            except Exception as e:
                errors["sender"] = e

        recv_thread = threading.Thread(target=run_receiver)
        send_thread = threading.Thread(target=run_sender)
        recv_thread.start()
        time.sleep(0.05)
        send_thread.start()
        send_thread.join(timeout=120)
        recv_thread.join(timeout=120)

        if errors:
            self.fail(f"Transfer failed: {errors}")

        return result["path"]

    def _assert_files_equal(self, path_a: str, path_b: str):
        """Compare two files in 1 MB chunks (memory-safe for large files)."""
        self.assertEqual(
            os.path.getsize(path_a),
            os.path.getsize(path_b),
            "File sizes differ",
        )
        with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
            offset = 0
            while True:
                ca = fa.read(1024 * 1024)
                cb = fb.read(1024 * 1024)
                if not ca and not cb:
                    break
                self.assertEqual(ca, cb, f"Content differs at offset {offset}")
                offset += len(ca)

    # ── Transfer Tests ──

    def test_empty_file(self):
        """Transfer a 0-byte file."""
        fp = self._create_test_file("empty.bin", 0)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)

    def test_one_byte(self):
        """Transfer a 1-byte file."""
        fp = self._create_test_file("one.bin", 1)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)

    def test_small_100B(self):
        """Transfer 100 bytes — single partial chunk."""
        fp = self._create_test_file("small.bin", 100)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)

    def test_exact_chunk_boundary(self):
        """Transfer exactly CHUNK_SIZE bytes — one full chunk."""
        fp = self._create_test_file("exact.bin", CHUNK_SIZE)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)

    def test_chunk_boundary_plus_one(self):
        """Transfer CHUNK_SIZE + 1 bytes — boundary edge case."""
        fp = self._create_test_file("boundary.bin", CHUNK_SIZE + 1)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)

    def test_medium_1MB(self):
        """Transfer 1 MB (~16 chunks)."""
        size = 1 * 1024 * 1024
        fp = self._create_test_file("medium.bin", size)
        t0 = time.time()
        received = self._transfer(fp)
        elapsed = time.time() - t0
        self._assert_files_equal(fp, received)
        print(f"\n    1 MB transfer: {elapsed:.2f}s")

    def test_large_10MB(self):
        """Transfer 10 MB (~153 chunks)."""
        size = 10 * 1024 * 1024
        fp = self._create_test_file("large.bin", size)
        t0 = time.time()
        received = self._transfer(fp)
        elapsed = time.time() - t0
        self._assert_files_equal(fp, received)
        print(f"\n    10 MB transfer: {elapsed:.2f}s")

    def test_very_large_100MB(self):
        """Transfer 100 MB (~1526 chunks)."""
        size = 100 * 1024 * 1024
        fp = self._create_test_file("very_large.bin", size)
        t0 = time.time()
        received = self._transfer(fp)
        elapsed = time.time() - t0
        self._assert_files_equal(fp, received)
        print(f"\n    100 MB transfer: {elapsed:.2f}s")

    def test_text_file_integrity(self):
        """Transfer a UTF-8 text file and verify content is preserved."""
        fp = os.path.join(self.tmpdir, "message.txt")
        content = "Top secret quantum message! 🔐\n" * 1000
        with open(fp, "w", encoding="utf-8") as f:
            f.write(content)

        received = self._transfer(fp)

        with open(received, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), content)

    def test_non_aligned_size(self):
        """Transfer a file whose size is not a multiple of any power of 2."""
        fp = self._create_test_file("odd_size.bin", 123_457)
        received = self._transfer(fp)
        self._assert_files_equal(fp, received)


if __name__ == "__main__":
    unittest.main(verbosity=2)
