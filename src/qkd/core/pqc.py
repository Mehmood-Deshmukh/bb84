"""
Post-quantum cryptography primitives (ML-DSA-65 and ML-KEM-768).

Provides signatures, key encapsulation, and key fingerprinting.
"""

from __future__ import annotations

try:
    import cryptography

    _version_str = getattr(cryptography, "__version__", "0")
    _major_version = int(_version_str.split(".")[0])
    if _major_version < 50:
        raise ImportError(f"cryptography>=50 required, but found {cryptography.__version__}")
    # The stubs will use mldsa and mlkem once implemented.
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
except (ImportError, ValueError) as exc:
    raise ImportError("cryptography>=50 is required for post-quantum primitives (ML-DSA and ML-KEM)") from exc


def sig_keygen() -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 keypair.

    Returns:
        tuple[bytes, bytes]: (public_key, seed) tuple where public_key is the
        raw public key bytes and seed is the 32-byte private key seed.
    """
    raise NotImplementedError


def sign(seed: bytes, message: bytes) -> bytes:
    """
    Sign a message using an ML-DSA-65 private seed.

    Args:
        seed: 32-byte private key seed.
        message: Message bytes to sign.

    Returns:
        bytes: Signature bytes.
    """
    raise NotImplementedError


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an ML-DSA-65 signature on a message.

    Args:
        public_key: Signer's ML-DSA-65 public key bytes.
        message: Message bytes that were signed.
        signature: Signature bytes to verify.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    raise NotImplementedError


def fingerprint(public_key: bytes) -> str:
    """
    Compute a fingerprint for a public key.

    The fingerprint is the first 16 bytes of SHA-256(public_key), formatted
    as 8 groups of 4 hexadecimal characters separated by hyphens
    (e.g., "ab12-cd34-56ef-...").

    Args:
        public_key: Raw public key bytes.

    Returns:
        str: Hexadecimal fingerprint string (8 groups of 4 hex digits).
    """
    raise NotImplementedError


def kem_keygen() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral ML-KEM-768 keypair.

    Returns:
        tuple[bytes, bytes]: (public_key, private_key) tuple where public_key
        is the raw 1184-byte encapsulation key and private_key is the raw
        decapsulation key/seed.
    """
    raise NotImplementedError


def kem_encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret against a peer's ML-KEM-768 public key.

    Args:
        public_key: Peer's ML-KEM-768 public key bytes.

    Returns:
        tuple[bytes, bytes]: (shared_secret, ciphertext) tuple where
        shared_secret is 32 bytes and ciphertext is 1088 bytes.
    """
    raise NotImplementedError


def kem_decaps(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate an ML-KEM-768 ciphertext using the private key.

    Args:
        private_key: Recipient's ML-KEM-768 private key bytes or seed.
        ciphertext: Encapsulated ciphertext bytes (1088 bytes).

    Returns:
        bytes: The 32-byte decapsulated shared secret.
    """
    raise NotImplementedError


__all__ = [
    "sig_keygen",
    "sign",
    "verify",
    "fingerprint",
    "kem_keygen",
    "kem_encaps",
    "kem_decaps",
]
