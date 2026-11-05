"""Result types and reporting shared by the Alice, Bob, and Eve workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Protocol, runtime_checkable

from qkd.core.bb84_protocol import qber_exceeds_threshold
from qkd.services.reporting import Reporter


class PeerAuthError(Exception):
    """Raised when peer authentication or verification fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TransferInterrupted(Exception):
    """
    A resumable transfer stopped after key confirmation (connection lost, or a chunk failed
    authentication) and can be continued by a new session. `bytes_verified` is what the
    receiver has safely on disk (0 on the sender's side, which cannot know).
    """

    def __init__(self, reason: str, bytes_verified: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.bytes_verified = bytes_verified


@runtime_checkable
class PeerVerifier(Protocol):
    """Protocol for checking a peer public key against a trust policy."""

    def check(self, peer_public_key: bytes) -> str:
        """
        Verify peer public key against trust policy.

        Returns:
            "new" | "pinned" | "verified"

        Raises:
            PeerAuthError: If authentication fails.
        """
        ...


@dataclass(frozen=True)
class AuthContext:
    """Authentication context holding node identity and peer verifier."""

    mode: Literal["none", "sign", "hybrid"]
    public_key: bytes
    seed: bytes
    verifier: PeerVerifier



@dataclass(frozen=True)
class KeyExchangeResult:
    raw_qubits: int
    sifted_length: int
    sample_size: int
    qber: float
    threshold: float
    key: Optional[bytes]  # None when the exchange aborted

    @property
    def aborted(self) -> bool:
        return self.key is None


def report_qber_verdict(qber: float, threshold: float, sample_size: int, reporter: Reporter) -> bool:
    """Report the QBER against the threshold. Returns True when the exchange must abort."""
    reporter.metrics(qber=qber, qber_threshold=threshold, sample_size=sample_size)
    verdict = f"QBER = {qber*100:.2f}% (threshold: {threshold*100:.0f}%)"
    if qber_exceeds_threshold(qber, threshold):
        reporter.error(f"{verdict} — EAVESDROPPER DETECTED!")
        reporter.error("The quantum channel has been compromised.")
        return True
    reporter.success(f"{verdict} — Channel is SECURE")
    return False


def report_summary(kx: KeyExchangeResult, num_chunks: int, chunk_size: int, reporter: Reporter) -> None:
    reporter.info(f"Quantum key bits used: {kx.raw_qubits}")
    reporter.info(f"Sifted key length: {kx.sifted_length} bits")
    reporter.info(f"Final key length: {len(kx.key or b'') * 8} bits")
    reporter.info(f"QBER: {kx.qber*100:.2f}%")
    reporter.info(f"File chunks: {num_chunks} × {chunk_size // 1024} KB")
