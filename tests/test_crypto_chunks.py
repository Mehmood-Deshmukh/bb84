"""
Unit tests for chunked AES-256-GCM encryption/decryption.

Tests encrypt → decrypt roundtrips at various file sizes to verify
that the chunked streaming approach correctly handles:
  - Empty data
  - Data smaller than one chunk
  - Exact chunk boundaries
  - Multi-chunk data (small, medium, large, very large)
  - Tamper detection via GCM authentication tags
  - Nonce uniqueness and correctness
"""

import os
import sys
import math
import time
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import derive_aes_key, encrypt_chunk, decrypt_chunk, derive_chunk_nonce
from config import CHUNK_SIZE


class TestChunkedCrypto(unittest.TestCase):
    """Test chunked AES-256-GCM encryption/decryption at various file sizes."""

    def setUp(self):
        self.key = derive_aes_key(os.urandom(32))
        self.base_nonce = os.urandom(8)

    def _roundtrip(self, data: bytes) -> bytes:
        """Encrypt data in chunks, then decrypt, return recovered bytes."""
        num_chunks = math.ceil(len(data) / CHUNK_SIZE) if data else 0

        # Encrypt all chunks
        encrypted = []
        for i in range(num_chunks):
            chunk = data[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
            nonce = derive_chunk_nonce(self.base_nonce, i)
            ct, tag = encrypt_chunk(chunk, self.key, nonce)
            encrypted.append((ct, tag))

        # Decrypt all chunks
        recovered = b""
        for i, (ct, tag) in enumerate(encrypted):
            nonce = derive_chunk_nonce(self.base_nonce, i)
            recovered += decrypt_chunk(ct, self.key, nonce, tag)

        return recovered

    # ── Size Tests ──

    def test_empty(self):
        """0 bytes — no chunks produced."""
        self.assertEqual(self._roundtrip(b""), b"")

    def test_one_byte(self):
        """1 byte — minimal non-empty input."""
        data = os.urandom(1)
        self.assertEqual(self._roundtrip(data), data)

    def test_small_100B(self):
        """100 bytes — single partial chunk."""
        data = os.urandom(100)
        self.assertEqual(self._roundtrip(data), data)

    def test_exact_chunk_boundary(self):
        """Exactly CHUNK_SIZE bytes — one full chunk, no remainder."""
        data = os.urandom(CHUNK_SIZE)
        self.assertEqual(self._roundtrip(data), data)

    def test_chunk_boundary_plus_one(self):
        """CHUNK_SIZE + 1 — two chunks, second has 1 byte."""
        data = os.urandom(CHUNK_SIZE + 1)
        self.assertEqual(self._roundtrip(data), data)

    def test_two_full_chunks(self):
        """Exactly 2 × CHUNK_SIZE — two full chunks."""
        data = os.urandom(CHUNK_SIZE * 2)
        self.assertEqual(self._roundtrip(data), data)

    def test_medium_1MB(self):
        """1 MB — ~16 chunks at 64 KB."""
        size = 1 * 1024 * 1024
        data = os.urandom(size)
        t0 = time.time()
        recovered = self._roundtrip(data)
        elapsed = time.time() - t0
        self.assertEqual(recovered, data)
        print(f"\n    1 MB roundtrip: {elapsed:.2f}s")

    def test_large_10MB(self):
        """10 MB — ~153 chunks at 64 KB."""
        size = 10 * 1024 * 1024
        data = os.urandom(size)
        t0 = time.time()
        recovered = self._roundtrip(data)
        elapsed = time.time() - t0
        self.assertEqual(len(recovered), size)
        self.assertEqual(recovered, data)
        print(f"\n    10 MB roundtrip: {elapsed:.2f}s")

    def test_very_large_100MB(self):
        """100 MB — ~1526 chunks at 64 KB."""
        size = 100 * 1024 * 1024
        data = os.urandom(size)
        t0 = time.time()
        recovered = self._roundtrip(data)
        elapsed = time.time() - t0
        self.assertEqual(len(recovered), size)
        self.assertEqual(recovered, data)
        print(f"\n    100 MB roundtrip: {elapsed:.2f}s")

    # ── Security Tests ──

    def test_tampered_ciphertext_detected(self):
        """Flipping a ciphertext byte must raise an authentication error."""
        data = os.urandom(1000)
        nonce = derive_chunk_nonce(self.base_nonce, 0)
        ct, tag = encrypt_chunk(data, self.key, nonce)
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with self.assertRaises(Exception):
            decrypt_chunk(tampered, self.key, nonce, tag)

    def test_tampered_tag_detected(self):
        """Flipping a tag byte must raise an authentication error."""
        data = os.urandom(1000)
        nonce = derive_chunk_nonce(self.base_nonce, 0)
        ct, tag = encrypt_chunk(data, self.key, nonce)
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with self.assertRaises(Exception):
            decrypt_chunk(ct, self.key, nonce, bad_tag)

    def test_wrong_nonce_detected(self):
        """Using the wrong chunk index for the nonce must fail."""
        data = os.urandom(1000)
        nonce = derive_chunk_nonce(self.base_nonce, 0)
        ct, tag = encrypt_chunk(data, self.key, nonce)
        wrong_nonce = derive_chunk_nonce(self.base_nonce, 1)
        with self.assertRaises(Exception):
            decrypt_chunk(ct, self.key, wrong_nonce, tag)

    def test_wrong_key_detected(self):
        """Decrypting with a different key must fail."""
        data = os.urandom(1000)
        nonce = derive_chunk_nonce(self.base_nonce, 0)
        ct, tag = encrypt_chunk(data, self.key, nonce)
        wrong_key = derive_aes_key(os.urandom(32))
        with self.assertRaises(Exception):
            decrypt_chunk(ct, wrong_key, nonce, tag)

    # ── Nonce Tests ──

    def test_nonce_length(self):
        """All nonces must be exactly 12 bytes (96 bits) for AES-GCM."""
        for i in range(100):
            nonce = derive_chunk_nonce(self.base_nonce, i)
            self.assertEqual(len(nonce), 12)

    def test_nonce_uniqueness(self):
        """All chunk nonces from the same base must be unique."""
        nonces = [derive_chunk_nonce(self.base_nonce, i) for i in range(10000)]
        self.assertEqual(len(set(nonces)), 10000)

    def test_different_base_nonces_differ(self):
        """Different base nonces produce different nonce sequences."""
        base_a = os.urandom(8)
        base_b = os.urandom(8)
        for i in range(10):
            self.assertNotEqual(
                derive_chunk_nonce(base_a, i),
                derive_chunk_nonce(base_b, i),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
