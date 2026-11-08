"""Result types and reporting shared by the Alice, Bob, and Eve workflows."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, Optional, Protocol, runtime_checkable

from qkd.core import decoy
from qkd.core.bb84_protocol import qber_exceeds_threshold
from qkd.core.config import ProtocolParams
from qkd.core.finite_key import binary_entropy, secure_key_length
from qkd.core.source import DECOY, SIGNAL, VACUUM
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
    kept_bits: int, sample_size: int, qber: float, params: ProtocolParams, reporter: Reporter,
    reconciliation_bits: int = 0,
) -> tuple[int, Optional[str]]:
    """
    Compute the finite-key secure length and decide whether to abort.

    Both peers call this with the same public values (kept bits, sample size,
    the QBER Alice announced, and the bound security policy), so they reach the
    same verdict without sending it. Returns (secure_bits, abort_reason or None).
    """
    secure = secure_key_length(kept_bits, sample_size, qber, params.eps_sec, params.eps_cor, reconciliation_bits)
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


@dataclass(frozen=True)
class DecoyEstimate:
    """
    The decoy-state estimate from the measured per-intensity statistics (wire step 2d).

    gains/qbers are [signal, decoy, vacuum] (qbers[signal] may be None until the QBER step).
    sent/clicks are the per-intensity pulse and click counts. Y1_L, e1_U, Q1_L are the
    single-photon bounds from core/decoy.py (Y1 lower, e1 upper, Q1 lower).
    """

    gains: tuple
    qbers: tuple
    sent: tuple
    clicks: tuple
    y1_lower: float
    e1_upper: float
    q1_lower: float
    mu: float
    nu: float
    y0: float


def estimate_decoy(gains, qbers, sent, clicks, params: ProtocolParams) -> DecoyEstimate:
    """
    Vacuum+weak decoy estimate from measured gains/QBERs (core/decoy.py, Ma et al. Eqs 34/37/35).

    Y0 is the measured vacuum gain, Q_mu/Q_nu the signal/decoy gains, E_nu the decoy QBER.
    Both peers call this with the same agreed values, so they get the same bounds.
    """
    mu, nu = params.intensities[SIGNAL], params.intensities[DECOY]
    q_mu, q_nu, y0 = gains[SIGNAL], gains[DECOY], gains[VACUUM]
    e_nu = qbers[DECOY]
    y1_l = decoy.y1_lower(mu, nu, q_mu, q_nu, y0)
    e1_u = decoy.e1_upper(nu, q_nu, e_nu, y1_l, y0)
    q1_l = decoy.q1_lower(mu, y1_l)
    return DecoyEstimate(tuple(gains), tuple(qbers), tuple(sent), tuple(clicks),
                         y1_l, e1_u, q1_l, mu, nu, y0)


def report_decoy_estimate(est: DecoyEstimate, reporter: Reporter) -> None:
    """Emit the per-intensity measurements and the single-photon bounds (decoy mode only).

    Lists (decoy_gains/decoy_qbers/...) are the structured-event form; the per-intensity
    scalars (decoy_gain_signal, ...) are flat so the benchmark can record them as columns.
    """
    gq = lambda q: None if q is None else round(q, 9)  # noqa: E731
    reporter.metrics(
        decoy_sent=list(est.sent), decoy_clicks=list(est.clicks),
        decoy_gains=[round(g, 9) for g in est.gains],
        decoy_qbers=[gq(q) for q in est.qbers],
        decoy_Y1_lower=round(est.y1_lower, 9), decoy_e1_upper=round(est.e1_upper, 9),
        decoy_Q1_lower=round(est.q1_lower, 12),
        # Flat per-intensity columns for the benchmark.
        decoy_gain_signal=round(est.gains[SIGNAL], 9), decoy_gain_decoy=round(est.gains[DECOY], 9),
        decoy_gain_vacuum=round(est.gains[VACUUM], 9),
        decoy_qber_decoy=gq(est.qbers[DECOY]), decoy_qber_vacuum=gq(est.qbers[VACUUM]),
        decoy_sent_signal=int(est.sent[SIGNAL]), decoy_sent_decoy=int(est.sent[DECOY]),
        decoy_sent_vacuum=int(est.sent[VACUUM]),
        decoy_clicks_signal=int(est.clicks[SIGNAL]), decoy_clicks_decoy=int(est.clicks[DECOY]),
        decoy_clicks_vacuum=int(est.clicks[VACUUM]),
    )


def decoy_asymptotic_verdict(
    kept_signal_bits: int, est: DecoyEstimate, params: ProtocolParams, reporter: Reporter,
    reconciliation_bits: int = 0,
) -> tuple[int, Optional[str]]:
    """
    The decoy_asymptotic gate: an asymptotic secure-length estimate for the decoy source.

    Over the n_s kept signal bits, the single-photon fraction of the signal clicks is
    Q1_L / Q_mu, so

        l = floor( n_s * (Q1_L / Q_mu) * (1 - h(e1_U))
                   - leak_EC - log2(2 / (eps_sec^2 eps_cor)) )

    with leak_EC = reconciliation_bits + log2(2 / eps_cor). Both peers compute the same l
    from the agreed public values and abort (when enforce_finite_key is on) if l is below
    final_key_bits.

    IMPORTANT: this is an ASYMPTOTIC estimate with the single-photon privacy-amplification
    bound and the finite-key *correction terms* bolted on; it is NOT a composable finite-key
    bound. In particular it does not account for the statistical fluctuations of the measured
    per-intensity gains and QBERs (the decoy bounds Y1_L / e1_U are evaluated at the point
    estimates). Phase 5 replaces this gate with the composable Lim et al. (2014) bound.
    """
    q_mu = est.gains[SIGNAL]
    single_fraction = (est.q1_lower / q_mu) if q_mu > 0 else 0.0
    leak_ec = reconciliation_bits + math.log2(2 / params.eps_cor)
    length = (kept_signal_bits * single_fraction * (1 - binary_entropy(est.e1_upper))
              - leak_ec - math.log2(2 / (params.eps_sec ** 2 * params.eps_cor)))
    secure = max(0, math.floor(length))
    reporter.metrics(secure_key_bits=secure)
    if secure >= params.final_key_bits:
        reporter.success(f"Decoy asymptotic estimate: {secure} secure bits >= {params.final_key_bits} "
                         f"(single-photon fraction {single_fraction:.3f}, e1_U {est.e1_upper:.4f})")
        return secure, None
    reason = (f"decoy asymptotic estimate gives {secure} secure bits, {params.final_key_bits} needed "
              f"(kept signal {kept_signal_bits}, Q1_L/Q_mu {single_fraction:.3f}, e1_U {est.e1_upper:.3%})")
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
