"""
Cryptographic Utilities for Secure File Transfer.

Provides AES-256-GCM authenticated encryption/decryption and HKDF
key derivation from quantum-generated raw key material.

AES-GCM (Galois/Counter Mode) provides:
  - Confidentiality: data is encrypted
  - Integrity: any tampering is detected via the authentication tag
  - Authenticity: only holders of the key can create valid ciphertexts
"""

import os
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
