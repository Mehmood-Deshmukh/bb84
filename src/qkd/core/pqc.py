"""
Post-quantum cryptography primitives (ML-DSA-65 and ML-KEM-768).

Provides signatures, key encapsulation, and key fingerprinting using NIST FIPS 204
(ML-DSA-65) and NIST FIPS 203 (ML-KEM-768).
"""

from __future__ import annotations

import hashlib

try:
    import cryptography

    _version_str = getattr(cryptography, "__version__", "0")
    _major_version = int(_version_str.split(".")[0])
    if _major_version < 50:
        raise ImportError(f"cryptography>=50 required, but found {cryptography.__version__}")
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
except (ImportError, ValueError) as exc:
    raise ImportError("cryptography>=50 is required for post-quantum primitives (ML-DSA and ML-KEM)") from exc


def sig_keygen() -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 keypair.

    Returns:
        tuple[bytes, bytes]: (public_key, seed) tuple where public_key is the
        raw public key bytes (1952 bytes) and seed is the 32-byte private key seed.
    """
    priv = mldsa.MLDSA65PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pk = priv.public_key().public_bytes_raw()
    return pk, seed


def sign(seed: bytes, message: bytes) -> bytes:
    """
    Sign a message using an ML-DSA-65 private seed.

    Args:
        seed: 32-byte private key seed.
        message: Message bytes to sign.

    Returns:
        bytes: Signature bytes (3309 bytes).
    """
    priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
    return priv.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an ML-DSA-65 signature on a message.

    Returns False without raising if the signature is invalid, if any bits in the
    message, signature, or public key are corrupted, or if any input has an invalid length.

    Args:
        public_key: Signer's ML-DSA-65 public key bytes (1952 bytes).
        message: Message bytes that were signed.
        signature: Signature bytes to verify (3309 bytes).

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        pub = mldsa.MLDSA65PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


def fingerprint(public_key: bytes) -> str:
    """
    Compute a fingerprint for a public key.

    The fingerprint is the first 16 bytes of SHA-256(public_key), formatted
    as 8 groups of 4 lowercase hexadecimal characters separated by hyphens
    (e.g., "ab12-cd34-56ef-...").

    Args:
        public_key: Raw public key bytes.

    Returns:
        str: Hexadecimal fingerprint string (8 groups of 4 hex digits).
    """
    digest = hashlib.sha256(public_key).digest()[:16].hex()
    return "-".join(digest[i : i + 4] for i in range(0, 32, 4))


def kem_keygen() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral ML-KEM-768 keypair.

    The private key format is the 64-byte private seed, which can be passed to kem_decaps.

    Returns:
        tuple[bytes, bytes]: (public_key, private_key) tuple where public_key
        is the raw 1184-byte encapsulation key and private_key is the 64-byte seed.
    """
    priv = mlkem.MLKEM768PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pk = priv.public_key().public_bytes_raw()
    return pk, seed


def kem_encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret against a peer's ML-KEM-768 public key.

    Args:
        public_key: Peer's ML-KEM-768 public key bytes (1184 bytes).

    Returns:
        tuple[bytes, bytes]: (shared_secret, ciphertext) tuple where
        shared_secret is 32 bytes and ciphertext is 1088 bytes.
    """
    pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
    ss, ct = pub.encapsulate()
    return ss, ct


def kem_decaps(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate an ML-KEM-768 ciphertext using the private key.

    Args:
        private_key: ML-KEM-768 64-byte private key seed.
        ciphertext: Encapsulated ciphertext bytes (1088 bytes).

    Returns:
        bytes: The 32-byte decapsulated shared secret.
    """
    priv = mlkem.MLKEM768PrivateKey.from_seed_bytes(private_key)
    return priv.decapsulate(ciphertext)


__all__ = [
    "sig_keygen",
    "sign",
    "verify",
    "fingerprint",
    "kem_keygen",
    "kem_encaps",
    "kem_decaps",
]
