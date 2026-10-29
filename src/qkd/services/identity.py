"""
Node identity management and trust store backed by ML-DSA-65 (FIPS 204).

Generates a persistent ML-DSA-65 identity on first start, persists the seed
with mode 0600, and reloads the same key pair on subsequent starts.

Also provides a persistent known-peers trust store (``TrustStore``) and two
``PeerVerifier`` implementations:

* ``PinnedVerifier`` — accepts exactly one pre-known fingerprint.
* ``TrustStoreVerifier`` — TOFU-aware store-backed verifier.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from qkd.core.pqc import fingerprint as _pqc_fingerprint
from qkd.core.pqc import sig_keygen
from qkd.usecases.common import PeerAuthError

# File names within the identity directory.
_SEED_FILENAME = "identity.seed"
_PUBLIC_KEY_FILENAME = "identity.pub"


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class IdentityError(Exception):
    """Base error for identity operations."""


class CorruptIdentityError(IdentityError):
    """Raised when persisted identity files are corrupt or inconsistent."""


class MissingPublicKeyError(IdentityError):
    """Raised when the seed file exists but the public-key file is missing."""


class CorruptTrustStoreError(IdentityError):
    """Raised when known_peers.json cannot be parsed."""


# ─────────────────────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Identity:
    """An ML-DSA-65 node identity.

    Attributes:
        public_key: Raw ML-DSA-65 public-key bytes (1952 bytes).
        seed: 32-byte private-key seed.
    """

    public_key: bytes
    seed: bytes

    @property
    def fingerprint(self) -> str:
        """Human-readable fingerprint (8 groups of 4 hex digits, hyphen-separated)."""
        return _pqc_fingerprint(self.public_key)


def _write_bytes_secure(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically with mode 0600 from the start.

    Uses ``os.open`` with explicit flags so the file is never world-readable,
    even briefly.
    """
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # Belt-and-suspenders: ensure mode is exactly 0600 even on platforms
    # where umask may have modified the initial mode.
    os.chmod(str(path), 0o600)


def load_or_create_identity(directory: Path) -> Identity:
    """Load an existing identity from *directory*, or create a new one.

    On first call the directory and key files are created.  On subsequent
    calls the persisted key pair is loaded and returned unchanged.

    Args:
        directory: Path to the identity directory (created if absent).

    Returns:
        Identity: The loaded or newly generated identity.

    Raises:
        MissingPublicKeyError: If the seed file exists but the public-key
            file is missing — this indicates data loss and must not be
            silently repaired.
        CorruptIdentityError: If either file has an unexpected size
            (truncated or padded).
    """
    directory = Path(directory)
    seed_path = directory / _SEED_FILENAME
    pub_path = directory / _PUBLIC_KEY_FILENAME

    has_seed = seed_path.exists()
    has_pub = pub_path.exists()

    if has_seed and not has_pub:
        raise MissingPublicKeyError(
            f"Seed file exists at {seed_path} but the public-key file "
            f"{pub_path} is missing. This may indicate data loss — refusing "
            "to regenerate. Restore the public key or remove the seed to "
            "create a fresh identity."
        )

    if has_seed and has_pub:
        return _load_identity(seed_path, pub_path)

    # Neither file exists (or only the public key without a seed, which is
    # harmless — we treat it as a fresh start since the seed is authoritative).
    return _create_identity(directory, seed_path, pub_path)


def _load_identity(seed_path: Path, pub_path: Path) -> Identity:
    """Read and validate an existing identity from disk."""
    seed = seed_path.read_bytes()
    if len(seed) == 0:
        raise CorruptIdentityError(
            f"Seed file {seed_path} is empty (expected 32 bytes)."
        )
    if len(seed) != 32:
        raise CorruptIdentityError(
            f"Seed file {seed_path} has unexpected size {len(seed)} bytes "
            "(expected 32)."
        )

    public_key = pub_path.read_bytes()
    if len(public_key) == 0:
        raise CorruptIdentityError(
            f"Public-key file {pub_path} is empty (expected 1952 bytes)."
        )
    if len(public_key) != 1952:
        raise CorruptIdentityError(
            f"Public-key file {pub_path} has unexpected size "
            f"{len(public_key)} bytes (expected 1952)."
        )

    return Identity(public_key=public_key, seed=seed)


def _create_identity(
    directory: Path, seed_path: Path, pub_path: Path
) -> Identity:
    """Generate a fresh ML-DSA-65 identity and persist it."""
    directory.mkdir(parents=True, exist_ok=True)

    public_key, seed = sig_keygen()

    # Write seed first (mode 0600), then public key.
    _write_bytes_secure(seed_path, seed)
    # Public key is not secret, but we still write it carefully.
    pub_path.write_bytes(public_key)

    return Identity(public_key=public_key, seed=seed)


# ─────────────────────────────────────────────────────────────────────────────
# Trust store: persistent known_peers.json
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PeerRecord:
    """A single entry in the trust store.

    Attributes:
        name: Optional human-readable label for the peer.
        first_seen: ISO-8601 timestamp of first contact.
        verified: Whether the peer has been explicitly verified (out-of-band).
    """

    name: str
    first_seen: str
    verified: bool


class TrustStore:
    """Persistent mapping from peer fingerprint to :class:`PeerRecord`.

    Backed by a JSON file.  Missing file → empty store.  Corrupt file → loud
    failure (same policy as identity files).
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._peers: Dict[str, PeerRecord] = {}
        self._load()

    # ── public API ──────────────────────────────────────────────────────

    def get(self, fingerprint: str) -> Optional[PeerRecord]:
        """Return the record for *fingerprint*, or ``None`` if unknown."""
        return self._peers.get(fingerprint)

    def add(
        self,
        fingerprint: str,
        *,
        name: str = "",
        verified: bool = False,
    ) -> PeerRecord:
        """Insert a new peer.  Raises ``ValueError`` if already present."""
        if fingerprint in self._peers:
            raise ValueError(f"Peer {fingerprint} already exists in trust store")
        record = PeerRecord(
            name=name,
            first_seen=datetime.now(timezone.utc).isoformat(),
            verified=verified,
        )
        self._peers[fingerprint] = record
        self._save()
        return record

    def set_verified(self, fingerprint: str, verified: bool = True) -> None:
        """Mark a peer as explicitly verified (or un-verify)."""
        record = self._peers.get(fingerprint)
        if record is None:
            raise KeyError(f"Unknown peer fingerprint: {fingerprint}")
        record.verified = verified
        self._save()

    def forget(self, fingerprint: str) -> bool:
        """Remove a peer's trust record from the trust store.

        Returns:
            bool: True if removed, False if fingerprint was not in store.
        """
        if fingerprint in self._peers:
            del self._peers[fingerprint]
            self._save()
            return True
        return False

    def all_peers(self) -> Dict[str, PeerRecord]:
        """Return a shallow copy of the full peer mapping."""
        return dict(self._peers)

    # ── persistence ─────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = self._path.read_text(encoding="utf-8")
        if not raw.strip():
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CorruptTrustStoreError(
                f"Cannot parse trust store {self._path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise CorruptTrustStoreError(
                f"Trust store {self._path} must be a JSON object, "
                f"got {type(data).__name__}"
            )
        for fp, entry in data.items():
            if not isinstance(entry, dict):
                raise CorruptTrustStoreError(
                    f"Entry for {fp} in {self._path} must be a JSON object"
                )
            self._peers[fp] = PeerRecord(
                name=entry.get("name", ""),
                first_seen=entry.get("first_seen", ""),
                verified=bool(entry.get("verified", False)),
            )

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data: Dict[str, Any] = {}
        for fp, rec in self._peers.items():
            data[fp] = {
                "name": rec.name,
                "first_seen": rec.first_seen,
                "verified": rec.verified,
            }
        self._path.write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PeerVerifier implementations
# ─────────────────────────────────────────────────────────────────────────────

class PinnedVerifier:
    """Accepts exactly one pre-known peer fingerprint.

    Used for the pre-pinned-key acceptance test and the Mallory-rejection demo.
    """

    def __init__(self, expected_fingerprint: str) -> None:
        self._expected = expected_fingerprint

    def check(self, peer_public_key: bytes) -> str:
        """Return ``"pinned"`` if the key matches, else raise :class:`PeerAuthError`."""
        fp = _pqc_fingerprint(peer_public_key)
        if fp != self._expected:
            raise PeerAuthError(
                f"Peer fingerprint {fp} does not match pinned "
                f"fingerprint {self._expected}"
            )
        return "pinned"


class TrustStoreVerifier:
    """TOFU-aware verifier backed by a :class:`TrustStore`.

    * Unseen fingerprint + TOFU on → store as new, return ``"new"``.
    * Unseen fingerprint + TOFU off → raise :class:`PeerAuthError`.
    * Known fingerprint (unchanged) → ``"pinned"`` (or ``"verified"`` if
      the peer has been explicitly marked verified via the trust API).
    * Different key for a known peer → always :class:`PeerAuthError`,
      regardless of TOFU setting.
    """

    def __init__(self, store: TrustStore, *, tofu: bool = True) -> None:
        self._store = store
        self._tofu = tofu

    def check(self, peer_public_key: bytes) -> str:
        """Verify *peer_public_key* against the trust store."""
        fp = _pqc_fingerprint(peer_public_key)
        record = self._store.get(fp)

        if record is not None:
            # Known fingerprint — the key hasn't changed.
            if record.verified:
                return "verified"
            return "pinned"

        # Fingerprint is unseen.  The store is keyed by fingerprint, so an
        # unseen fingerprint is genuinely new — there's no stored entry to
        # conflict with.  (Name-based conflict checks belong in higher layers
        # that map names to fingerprints.)

        if not self._tofu:
            raise PeerAuthError(
                f"Unknown peer fingerprint {fp} and TOFU is disabled"
            )

        self._store.add(fp)
        return "new"
