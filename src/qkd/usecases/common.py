"""Result types and reporting shared by the Alice, Bob, and Eve workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Protocol, runtime_checkable

from qkd.core.bb84_protocol import qber_exceeds_threshold
from qkd.core.config import ProtocolParams
from qkd.core.finite_key import secure_key_length
from qkd.services.reporting import Reporter


class PeerAuthError(Exception):
    """Raised when peer authentication or verification fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KeyConfirmationError(Exception):
    """
    Raised when the peer's key confirmation tag does not match: the two keys differ.

    The peer's signature over the transcript has already verified by then, so this
    is not an identity failure. On a noiseless channel it means the quantum channel
    was disturbed in bits the QBER sample did not catch.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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
    secure_bits: Optional[int] = None  # finite-key bound; None if the exchange aborted on QBER first
    abort_reason: Optional[str] = None  # set when key is None

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


def finite_key_verdict(
    kept_bits: int, sample_size: int, qber: float, params: ProtocolParams, reporter: Reporter
) -> tuple[int, Optional[str]]:
    """
    Compute the finite-key secure length and decide whether to abort.

    Both peers call this with the same public values (kept bits, sample size,
    the QBER Alice announced, and the bound security policy), so they reach the
    same verdict without sending it. Returns (secure_bits, abort_reason or None).
    """
    secure = secure_key_length(kept_bits, sample_size, qber, params.eps_sec, params.eps_cor)
    reporter.metrics(secure_key_bits=secure)
    if secure >= params.final_key_bits:
        reporter.success(f"Finite-key bound: {secure} secure bits >= {params.final_key_bits} needed")
        return secure, None
    reason = (f"finite-key bound gives {secure} secure bits, {params.final_key_bits} needed "
              f"(kept {kept_bits}, sample {sample_size}, QBER {qber:.2%})")
    if not params.enforce_finite_key:
        reporter.warning(f"{reason}; continuing because enforce_finite_key is off (key NOT provably secure)")
        return secure, None
    reporter.error(reason)
    return secure, reason


def report_summary(kx: KeyExchangeResult, num_chunks: int, chunk_size: int, reporter: Reporter) -> None:
    reporter.info(f"Quantum key bits used: {kx.raw_qubits}")
    reporter.info(f"Sifted key length: {kx.sifted_length} bits")
    reporter.info(f"Final key length: {len(kx.key or b'') * 8} bits")
    reporter.info(f"QBER: {kx.qber*100:.2f}%")
    reporter.info(f"File chunks: {num_chunks} × {chunk_size // 1024} KB")
