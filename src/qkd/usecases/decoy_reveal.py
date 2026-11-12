"""
Wire step 2d: the decoy reveal, between sifting (step 2) and QBER estimation (step 3).

Run only when the security policy says source == "decoy". Both messages go through the
TranscriptChannel (tracked), so in signed modes any change to them makes the finished
signatures fail at step 4b.

  2d  Alice -> {"labels": "<m digits>", "sent": [s0,s1,s2], "decoy_bits": [0/1, ...]}
          labels     intensity label (0 signal, 1 decoy, 2 vacuum) of every clicked pulse,
                     one digit per clicked pulse in the order of the qubit message.
          sent       pulses sent at each intensity (over all N), for the per-intensity gains.
          decoy_bits Alice's bits at the sifted positions whose intensity is decoy or vacuum,
                     in sifted (matching) order. Signal bits are NOT revealed here; they go
                     on to the QBER sample, Cascade and privacy amplification as usual.
      Bob -> {"gains": [Q0,Q1,Q2], "qbers": [null, E1, E2]}
          Q_k = clicks_k / sent_k for each intensity; E_k the QBER among the revealed decoy
          and vacuum sifted positions (signal QBER is null here, it comes from step 3).

Alice recomputes the gains from her own labels and sent counts and aborts (PeerAuthError) on
any mismatch, which catches tampering with the labels or the sent counts before step 4b. She
cannot recompute the QBERs (she lacks Bob's bits); those are protected by the tracked
transcript (a change breaks the finished signature). Both sides then build the same decoy
estimate from the agreed gains and QBERs and continue with only the signal-intensity bits.
"""

from __future__ import annotations

from typing import Optional

from qkd.core.source import DECOY, SIGNAL, VACUUM
from qkd.core.config import ProtocolParams
from qkd.services.reporting import Reporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases.common import DecoyEstimate, PeerAuthError, estimate_decoy, report_decoy_estimate

GAIN_TOLERANCE = 1e-12  # the gains are rationals both sides compute from integer counts


def _encode_labels(labels) -> str:
    return "".join(str(int(k)) for k in labels)


def _decode_labels(raw: object, n_intensities: int) -> list[int]:
    if not isinstance(raw, str) or any(c not in "0123456789" for c in raw):
        raise ValueError("decoy reveal: labels must be a digit string")
    labels = [int(c) for c in raw]
    if any(k >= n_intensities for k in labels):
        raise ValueError("decoy reveal: label out of range")
    return labels


def _gains_qbers_from_bits(
    labels: list[int], matching: list[int], sent: list[int], n_intensities: int,
    alice_bits_nonsignal: list[int], bob_bits: list[int],
) -> tuple[list[float], list[Optional[float]], list[int]]:
    """
    Bob's per-intensity gains, QBERs (decoy/vacuum only), and click counts.

    alice_bits_nonsignal are Alice's revealed bits at the non-signal sifted positions, in
    matching order; bob_bits are Bob's bits per clicked pulse. Raises ValueError if the
    number of revealed bits does not match the non-signal sifted positions (tamper/garble).
    """
    clicks = [0] * n_intensities
    for k in labels:
        clicks[k] += 1
    gains = [clicks[k] / sent[k] if sent[k] else 0.0 for k in range(n_intensities)]

    errors = [0] * n_intensities
    counts = [0] * n_intensities
    revealed = iter(alice_bits_nonsignal)
    for pos in matching:
        k = labels[pos]
        if k == SIGNAL:
            continue
        try:
            alice_bit = next(revealed)
        except StopIteration:
            raise ValueError("decoy reveal: fewer revealed bits than non-signal sifted positions") from None
        counts[k] += 1
        if alice_bit != bob_bits[pos]:
            errors[k] += 1
    if next(revealed, None) is not None:
        raise ValueError("decoy reveal: more revealed bits than non-signal sifted positions")

    qbers: list[Optional[float]] = [None] * n_intensities
    for k in (DECOY, VACUUM):
        qbers[k] = (errors[k] / counts[k]) if counts[k] else 0.0
    return gains, qbers, clicks


def alice_decoy_reveal(
    channel: TranscriptChannel, bits: list[int], matching: list[int], labels, sent,
    params: ProtocolParams, reporter: Reporter,
) -> tuple[list[int], DecoyEstimate]:
    """Alice's side of step 2d. Returns (her signal-intensity sifted bits, the decoy estimate)."""
    reporter.info("Decoy reveal: sending intensity labels and decoy/vacuum bits...")
    labels = [int(k) for k in labels]
    sent = [int(s) for s in sent]
    decoy_bits = [bits[pos] for pos in matching if labels[pos] != SIGNAL]
    channel.send_json({"labels": _encode_labels(labels), "sent": sent, "decoy_bits": decoy_bits})

    reply = channel.recv_json()
    gains, qbers = _parse_bob_reply(reply, len(params.intensities))

    # Recompute the gains from Alice's own labels and sent counts; a mismatch means the
    # labels or sent counts were tampered with in flight.
    clicks = [0] * len(params.intensities)
    for k in labels:
        clicks[k] += 1
    for k in range(len(params.intensities)):
        mine = clicks[k] / sent[k] if sent[k] else 0.0
        if abs(mine - gains[k]) > GAIN_TOLERANCE:
            raise PeerAuthError(f"decoy gain mismatch at intensity {k}: Bob {gains[k]}, recomputed {mine}")

    est = estimate_decoy(gains, qbers, sent, clicks, params)
    report_decoy_estimate(est, reporter)
    reporter.success(f"Decoy reveal: Y1_L {est.y1_lower:.6f}, e1_U {est.e1_upper:.4f}")
    signal_sifted = [bits[pos] for pos in matching if labels[pos] == SIGNAL]
    return signal_sifted, est


def bob_decoy_reveal(
    channel: TranscriptChannel, bits: list[int], matching: list[int],
    params: ProtocolParams, reporter: Reporter,
) -> tuple[list[int], DecoyEstimate]:
    """Bob's side of step 2d. Returns (his signal-intensity sifted bits, the decoy estimate)."""
    reporter.info("Decoy reveal: receiving intensity labels and decoy/vacuum bits...")
    msg = channel.recv_json()
    n_intensities = len(params.intensities)
    if not isinstance(msg, dict):
        raise ValueError("decoy reveal: malformed message")
    labels = _decode_labels(msg.get("labels"), n_intensities)
    sent = msg.get("sent")
    decoy_bits = msg.get("decoy_bits")
    if (not isinstance(sent, list) or len(sent) != n_intensities
            or not all(isinstance(s, int) and not isinstance(s, bool) and s >= 0 for s in sent)):
        raise ValueError("decoy reveal: malformed sent counts")
    if len(labels) != len(bits):
        raise ValueError("decoy reveal: label count does not match the clicked pulses")
    if (not isinstance(decoy_bits, list)
            or not all(b in (0, 1) and not isinstance(b, bool) for b in decoy_bits)):
        raise ValueError("decoy reveal: malformed decoy_bits")

    gains, qbers, clicks = _gains_qbers_from_bits(labels, matching, sent, n_intensities, decoy_bits, bits)
    channel.send_json({"gains": gains, "qbers": qbers})

    est = estimate_decoy(gains, qbers, sent, clicks, params)
    report_decoy_estimate(est, reporter)
    reporter.success(f"Decoy reveal: Y1_L {est.y1_lower:.6f}, e1_U {est.e1_upper:.4f}")
    signal_sifted = [bits[pos] for pos in matching if labels[pos] == SIGNAL]
    return signal_sifted, est


def _parse_bob_reply(reply: object, n_intensities: int) -> tuple[list[float], list[Optional[float]]]:
    if not isinstance(reply, dict):
        raise ValueError("decoy reveal: malformed reply")
    gains, qbers = reply.get("gains"), reply.get("qbers")
    if (not isinstance(gains, list) or len(gains) != n_intensities
            or not all(isinstance(g, (int, float)) and not isinstance(g, bool) for g in gains)):
        raise ValueError("decoy reveal: malformed gains")
    if (not isinstance(qbers, list) or len(qbers) != n_intensities
            or not all(q is None or (isinstance(q, (int, float)) and not isinstance(q, bool)) for q in qbers)):
        raise ValueError("decoy reveal: malformed qbers")
    return [float(g) for g in gains], [None if q is None else float(q) for q in qbers]
