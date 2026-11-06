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
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
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

    Each mode uses its own HKDF info label for explicit domain separation:
      - 'hybrid': Combines QKD key and ML-KEM-768 shared secret:
          ikm = qkd_key || kem_ss, salt = transcript_hash, info = b"bb84-mlkem768-hybrid-v1"
      - 'sign': Uses QKD key only (KEM secret omitted; kem_ss may be None):
          ikm = qkd_key, salt = transcript_hash, info = b"bb84-sign-v1"
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
            info=b"bb84-sign-v1",
        )
        return hkdf.derive(ikm)
    elif norm_mode == "none":
        return derive_aes_key(qkd_key)
    else:
        raise ValueError(f"Invalid mode: {mode!r}. Allowed: none, sign, hybrid")


RESUME_KEY_INFO = b"bb84-resume-v1|"
RESUME_ROLES = ("alice", "bob")
_RESUME_NONCE_BYTES = 12


def derive_resume_key(session_key: bytes, role: str) -> bytes:
    """
    Derive the key that protects one resume negotiation message (HKDF-SHA256).

    There is one key per sender role ("bob" seals the request, "alice" the grant) and neither is the
    file key, so resume messages live in a different key space from the chunk nonces
    (base_nonce || index) used under session_key.
    """
    if role not in RESUME_ROLES:
        raise ValueError(f"Invalid role: {role!r}. Allowed: {', '.join(RESUME_ROLES)}")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=RESUME_KEY_INFO + role.encode()).derive(session_key)


def seal_resume_message(session_key: bytes, role: str, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM seal under the role's resume key. Returns nonce(12B) || ciphertext || tag."""
    nonce = os.urandom(_RESUME_NONCE_BYTES)
    return nonce + AESGCM(derive_resume_key(session_key, role)).encrypt(nonce, plaintext, aad)


def open_resume_message(session_key: bytes, role: str, blob: bytes, aad: bytes) -> bytes:
    """
    Open a message produced by seal_resume_message.

    Raises cryptography.exceptions.InvalidTag if the blob, the role, the key or the aad is wrong
    (also for a blob too short to hold a nonce and a tag).
    """
    from cryptography.exceptions import InvalidTag

    if len(blob) < _RESUME_NONCE_BYTES + 16:
        raise InvalidTag()
    nonce, sealed = blob[:_RESUME_NONCE_BYTES], blob[_RESUME_NONCE_BYTES:]
    return AESGCM(derive_resume_key(session_key, role)).decrypt(nonce, sealed, aad)


@dataclass(frozen=True)
class SessionKeys:
    """Independent subkeys expanded from one session key."""

    file: bytes  # AES-256-GCM key for the file chunks
    metadata: bytes  # AES-256-GCM key for the single metadata message
    confirm: bytes  # HMAC-SHA256 key for the key confirmation tags (step 4b)


def key_schedule(session_key: bytes) -> SessionKeys:
    """
    Expand the session key into one subkey per use with HKDF-Expand (RFC 5869).

    The session key is already the output of HKDF-Extract (derive_session_key),
    so it is used directly as the pseudorandom key. Distinct info labels make the
    three subkeys independent: revealing a confirmation tag says nothing useful
    about the file key, and the metadata and chunk ciphertexts never share a key,
    so their nonces cannot collide.
    """

    def expand(label: bytes) -> bytes:
        return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=label).derive(session_key)

    return SessionKeys(
        file=expand(b"bb84-file-v1"),
        metadata=expand(b"bb84-metadata-v1"),
        confirm=expand(b"bb84-confirm-v1"),
    )


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
