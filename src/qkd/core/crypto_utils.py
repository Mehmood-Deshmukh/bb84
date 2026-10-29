"""
Cryptographic Utilities for Secure File Transfer.

Provides AES-256-GCM authenticated encryption/decryption and HKDF
key derivation from quantum-generated raw key material.

AES-GCM (Galois/Counter Mode) provides:
  - Confidentiality: data is encrypted
  - Integrity: any tampering is detected via the authentication tag
  - Authenticity: only holders of the key can create valid ciphertexts
"""

from __future__ import annotations
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_aes_key(raw_key: bytes, info: bytes = b"bb84-qkd-file-transfer") -> bytes:
    """
    Derive a 256-bit AES key from raw quantum key material using HKDF.

    HKDF (HMAC-based Key Derivation Function, RFC 5869):
      1. Extract: condense raw key into a pseudorandom key (PRK)
      2. Expand: stretch PRK to the desired output length

    This ensures uniform key distribution even if the quantum
    key has slight statistical biases.

    Args:
        raw_key: Raw bytes from privacy amplification
        info: Context string for domain separation

    Returns:
        32-byte (256-bit) AES key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(raw_key)


def derive_session_key(
    qkd_key: bytes,
    kem_ss: bytes | None,
    transcript_hash: bytes,
    mode: str,
) -> bytes:
    """
    Derive a 256-bit AES session key using HKDF-SHA256 based on the authentication mode.

    Modes:
      - 'hybrid': Combines QKD key and ML-KEM-768 shared secret:
          ikm = qkd_key || kem_ss, salt = transcript_hash, info = b"bb84-mlkem768-hybrid-v1"
      - 'sign': Uses QKD key only (KEM secret omitted; kem_ss may be None):
          ikm = qkd_key, salt = transcript_hash, info = b"bb84-mlkem768-hybrid-v1"
      - 'none': Returns derive_aes_key(qkd_key) for backwards compatibility.

    Args:
        qkd_key: 32-byte QKD shared key from privacy amplification.
        kem_ss: 32-byte ML-KEM-768 shared secret (required for 'hybrid' mode).
        transcript_hash: 32-byte SHA-256 digest of the classical channel transcript.
        mode: Authentication mode ('hybrid', 'sign', or 'none').

    Returns:
        32-byte (256-bit) AES session key.

    Raises:
        ValueError: If mode is unknown or if kem_ss is None in 'hybrid' mode.
    """
    norm_mode = mode.lower()
    if norm_mode == "hybrid":
        if kem_ss is None:
            raise ValueError("kem_ss is required in hybrid mode")
        ikm = qkd_key + kem_ss
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=transcript_hash,
            info=b"bb84-mlkem768-hybrid-v1",
        )
        return hkdf.derive(ikm)
    elif norm_mode == "sign":
        ikm = qkd_key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=transcript_hash,
            info=b"bb84-mlkem768-hybrid-v1",
        )
        return hkdf.derive(ikm)
    elif norm_mode == "none":
        return derive_aes_key(qkd_key)
    else:
        raise ValueError(f"Invalid mode: {mode!r}. Allowed: none, sign, hybrid")


def encrypt_file(filepath: str, key: bytes) -> tuple[bytes, bytes, bytes, str]:
    """
    Encrypt a file using AES-256-GCM.

    AES-GCM requires:
      - A 96-bit (12-byte) nonce (number used once)
      - A 128-bit authentication tag (generated automatically)

    The nonce MUST be unique for each encryption with the same key.
    Since quantum keys are single-use (key material is consumed
    and regenerated for each transfer), nonce reuse is prevented.

    Args:
        filepath: Path to the file to encrypt
        key: 256-bit AES key

    Returns:
        (nonce, tag, ciphertext, filename)
    """
    with open(filepath, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(12)  # 96-bit random nonce
    aesgcm = AESGCM(key)

    # GCM combines CTR encryption + GMAC authentication
    # ciphertext includes the 16-byte auth tag appended at the end
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Split: last 16 bytes are the authentication tag
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    filename = os.path.basename(filepath)
    return nonce, tag, ciphertext, filename


def decrypt_file(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes,
) -> bytes:
    """
    Decrypt a file using AES-256-GCM.

    Decryption also verifies the authentication tag. If the ciphertext
    or tag has been tampered with, decryption raises InvalidTag,
    ensuring both confidentiality and integrity.

    Args:
        ciphertext: Encrypted file data
        key: 256-bit AES key (must match encryption key)
        nonce: The nonce used during encryption
        tag: The 16-byte authentication tag

    Returns:
        Decrypted plaintext bytes

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    aesgcm = AESGCM(key)

    # Reconstruct ciphertext + tag (AESGCM expects them concatenated)
    ciphertext_with_tag = ciphertext + tag

    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext


# ─────────────────────────────────────────────
# Chunked Streaming Encryption / Decryption
# ─────────────────────────────────────────────

def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """
    Derive a unique 12-byte nonce for a specific chunk.

    Construction: base_nonce (8 bytes) || chunk_index (4 bytes big-endian)

    This supports up to 2^32 chunks per file transfer. At 64 KB per chunk,
    that allows files up to 256 TB.

    Args:
        base_nonce: 8-byte random value generated per file transfer
        chunk_index: 0-based chunk number

    Returns:
        12-byte nonce suitable for AES-GCM
    """
    return base_nonce + struct.pack(">I", chunk_index)


def encrypt_chunk(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt a single data chunk using AES-256-GCM.

    Each chunk is independently authenticated, so corruption or tampering
    of any individual chunk is detected immediately upon decryption.

    Args:
        plaintext: Raw data chunk
        key: 256-bit AES key
        nonce: 12-byte unique nonce for this chunk
        aad: Optional additional authenticated data (e.g. metadata hash)

    Returns:
        (ciphertext, tag) where tag is the 16-byte GCM authentication tag
    """
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return ciphertext, tag


def decrypt_chunk(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    aad: bytes | None = None,
) -> bytes:
    """
    Decrypt a single data chunk using AES-256-GCM.

    Verifies the authentication tag before returning plaintext.

    Args:
        ciphertext: Encrypted chunk data
        key: 256-bit AES key
        nonce: 12-byte nonce used during encryption
        tag: 16-byte GCM authentication tag
        aad: Optional additional authenticated data (must match encryption AAD)

    Returns:
        Decrypted plaintext bytes

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
