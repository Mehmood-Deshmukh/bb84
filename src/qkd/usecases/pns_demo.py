"""
Eve's photon-number-splitting (PNS) workflow: a man-in-the-middle proxy that attacks a
weak-coherent-source run (SOURCE=wcp or decoy) by splitting photons off multi-photon pulses.

Unlike the intercept-resend Eve (eavesdrop_demo.py), a PNS Eve replaces the fibre with a
lossless line, so she must receive the pulses BEFORE the channel loss. Alice, run in eve-mode
with a weak-coherent source, STREAMS the pre-loss pulses to this proxy in chunks (send_file's
pre-loss handoff: `preloss_chunk` messages ending with `preloss_end`) instead of the ordinary
step-1 qubit message; the proxy applies the attack per chunk (core/quantum_channel.pns_accumulate)
and keeps only the forwarded and stored pulses (a PnsAccumulator, O(detections)), never the whole
stream, then forwards one ordinary post-loss step-1 message to Bob, who cannot tell the difference.
This is why the 50 km attack runs in bounded memory. Every classical message is relayed transparently.

Wire handled here (Alice <-> Eve <-> Bob):
  0a/0b hellos (forwarded unchanged; Alice's carries the pre-loss flag so Bob reports detections)
  1     Alice's streamed pre-loss handoff (Alice -> Eve only, many chunks); Eve -> Bob one qubit message
  2     Bob -> {"bases","detected"} (forwarded); Alice -> matching (forwarded). Eve now knows
        Bob's bases and which detected pulses are sifted, and measures her stored photons in the
        revealed correct basis (she introduced no error, so Bob's QBER stays at the honest level).
  2d..  everything else (decoy reveal, QBER, reconciliation, salt, finished, file) relayed as-is.

Outcome against each gate (Ma et al. 2005; Brassard et al. 2000; Lutkenhaus):
  wcp   the single-photon (Tomamichel) gate ignores the gains, so the run COMPLETES and Eve
        learns the bits of every multi-photon pulse Bob detected — a large share of the key.
  decoy the decoy estimate sees the signal/decoy gains pulled apart by the multi-photon content,
        drives Y1_L toward 0, and the decoy gate ABORTS before any file data.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Optional

import numpy as np

from qkd.core.channel_model import encode_pulses
from qkd.core.config import ProtocolParams
from qkd.core.quantum_channel import (
    PnsAccumulator,
    measure_qubits_backend,
    pns_accumulate,
    pns_forward_fractions,
    passthrough_accumulate,
)
from qkd.core.source import SIGNAL
from qkd.services.reporting import Reporter
from qkd.services.wire import forward_message, recv_json, relay_until_closed, send_json


@dataclass(frozen=True)
class PnsEavesdropResult:
    """What Eve learned and did over one PNS run."""

    source: str
    detected: int            # pulses Bob detected
    sifted_signal: int       # signal-intensity sifted positions (the key before amplification)
    known_signal: int        # of those, how many Eve knows exactly
    blocked: list[int]       # per-intensity counts over the pulses Eve was handed (n >= 1)
    forwarded_single: list[int]
    split: list[int]

    @property
    def known_fraction(self) -> float:
        """Fraction of the (signal) sifted key Eve knows exactly."""
        return self.known_signal / self.sifted_signal if self.sifted_signal else 0.0


def _forward_hellos(alice: socket.socket, bob: socket.socket, reporter: Reporter) -> str:
    reporter.section("Phase 0: Forwarding Authentication Hellos (Unchanged)")
    hello = json.loads(forward_message(alice, bob))["hello"]   # 0a
    forward_message(bob, alice)                                # 0b
    source = hello.get("params", {}).get("source", "single")
    reporter.info(f"Hellos forwarded (mode: {hello.get('mode')}, source: {source})")
    return source


def _stream_preloss(alice: socket.socket, acc: PnsAccumulator, attack: bool, params: ProtocolParams,
                    mix_i, mix_p, multi_frac: float, single_frac: float,
                    rng: np.random.Generator, strength: float = 1.0,
                    split_rng: Optional[np.random.Generator] = None) -> tuple[int, int]:
    """
    Read Alice's streamed pre-loss handoff chunk by chunk, applying the PNS (or passthrough) rule to
    each chunk and accumulating only the forwarded and stored pulses in ``acc``. Returns (n_pulses
    sent, pulses handed with a photon). Eve's memory thus tracks the detections, never N.

    ``strength`` g in [0, 1] is the partial-attack knob: each handed pulse is attacked (PNS) with
    probability g (drawn from ``split_rng``, independent of the forwarding ``rng``) and otherwise
    passed through the honest channel loss. g >= 1 is the full attack and does not touch split_rng,
    so it reproduces the maximal attack's stream exactly; g <= 0 is the honest control. Either way
    Eve forwards states unchanged, so Bob sees no extra error at any g.
    """
    handed = 0
    while True:
        msg = recv_json(alice)
        if not isinstance(msg, dict):
            raise ValueError("expected a pre-loss chunk; is Alice running with --eve-mode?")
        if "preloss_end" in msg:
            return int(msg["preloss_end"]["n"]), handed
        chunk = msg.get("preloss_chunk")
        if not isinstance(chunk, dict):
            raise ValueError("expected a pre-loss chunk; is Alice running with --eve-mode?")
        index = [int(i) for i in chunk["index"]]
        labels = [int(c) for c in chunk["labels"]]
        photons = [int(p) for p in chunk["photons"]]
        qubits = list(chunk["qubits"])
        handed += len(index)
        if not attack or strength <= 0.0:
            passthrough_accumulate(acc, index, labels, photons, qubits, params.channel, rng)
        elif strength >= 1.0:
            pns_accumulate(acc, index, labels, photons, qubits, multi_frac, single_frac, rng)
        else:
            # Partial attack: PNS a fraction g of the pulses, pass the rest through honestly.
            mask = split_rng.random(len(index)) < strength
            att = [j for j, m in enumerate(mask) if m]
            pas = [j for j, m in enumerate(mask) if not m]
            pns_accumulate(acc, [index[j] for j in att], [labels[j] for j in att],
                           [photons[j] for j in att], [qubits[j] for j in att],
                           multi_frac, single_frac, rng)
            passthrough_accumulate(acc, [index[j] for j in pas], [labels[j] for j in pas],
                                   [photons[j] for j in pas], [qubits[j] for j in pas],
                                   params.channel, rng)


def run_pns(
    alice: socket.socket,
    bob: socket.socket,
    reporter: Reporter,
    params: ProtocolParams,
    *,
    attack: bool = True,
    forward_fraction: Optional[float] = None,
    multi_fraction: Optional[float] = None,
    strength: float = 1.0,
    seed: Optional[int] = None,
) -> PnsEavesdropResult:
    """
    Run Eve's PNS proxy between connected Alice and Bob sockets.

    `attack=False` is the honest control: Eve applies the real channel loss and forwards
    survivors without splitting, which reproduces the honest gains. `forward_fraction` and
    `multi_fraction` override the single- and multi-photon forwarding rates (see eve_pns); the
    defaults match Bob's overall gain to the honest channel while maximising what Eve learns.
    `strength` g in [0, 1] is the partial-attack knob: Eve PNS-attacks a fraction g of the pulses
    and passes the rest through honestly (g=1 the full attack, g=0 the honest control). As g rises
    the decoy single-photon-yield bound degrades smoothly; Bob's QBER stays at the honest floor.
    """
    rng = np.random.default_rng(seed)
    split_rng = np.random.default_rng(None if seed is None else seed + 1)
    source = _forward_hellos(alice, bob, reporter)
    mix_i, mix_p = params.source_mix()
    n_intensities = len(params.intensities)
    multi_frac, single_frac = (pns_forward_fractions(params.channel, mix_i, mix_p,
                                                     forward_fraction, multi_fraction)
                               if attack else (0.0, 0.0))

    reporter.section("Phase 1: Photon-Number-Splitting Attack")
    acc = PnsAccumulator(n_intensities)
    n_pulses, handed = _stream_preloss(alice, acc, attack, params, mix_i, mix_p,
                                       multi_frac, single_frac, rng, strength, split_rng)
    plan = acc.to_plan(n_pulses)
    reporter.info(f"Streamed {handed} pre-loss pulses with a photon ({n_pulses} sent)")
    if attack:
        reporter.info(f"Split {sum(plan.split)} multi-photon pulses, forwarded "
                      f"{sum(plan.forwarded_single)} single-photon pulses, blocked {sum(plan.blocked)}")
    else:
        reporter.info(f"Honest control (no splitting): forwarded {len(plan.forward_index)} pulses")
    # A partial attack (0 < g < 1) routes each pulse to the attack or passthrough accumulator, so a
    # chunk's forwarded pulses land out of global order; Bob needs strictly increasing indices. The
    # full attack and honest control stream in order already, so they skip the sort.
    fwd_index, fwd_qubits = plan.forward_index, plan.forward_qubits
    if attack and 0.0 < strength < 1.0:
        order = sorted(range(len(fwd_index)), key=fwd_index.__getitem__)
        fwd_index = [fwd_index[j] for j in order]
        fwd_qubits = [fwd_qubits[j] for j in order]
    send_json(bob, encode_pulses(n_pulses, fwd_index, fwd_qubits))

    reporter.section("Phase 2: Forwarding Sifting (Transparent)")
    bob_step2 = json.loads(forward_message(bob, alice))   # Bob's {"bases","detected"}
    bob_bases = bob_step2["bases"]
    detected = [int(g) for g in bob_step2["detected"]]
    matching = json.loads(forward_message(alice, bob))    # Alice's matching indices (into detected)

    known_signal, sifted_signal = _measure_stored(
        plan, detected, bob_bases, matching, source, reporter, params.measurement, rng)

    reporter.metrics(eve_known_signal=known_signal, eve_sifted_signal=sifted_signal,
                     eve_pns_strength=round(float(strength), 4),
                     eve_known_fraction=round(known_signal / sifted_signal, 6) if sifted_signal else 0.0)
    reporter.section("Phase 3: Relaying the Remainder")
    relay_until_closed(alice, bob)
    return PnsEavesdropResult(source, len(detected), sifted_signal, known_signal,
                              plan.blocked, plan.forwarded_single, plan.split)


def _measure_stored(plan, detected, bob_bases, matching, source, reporter,
                    measurement="aer", rng=None):
    """
    Measure Eve's stored photons at the sifted signal positions, in Bob's revealed basis.

    At a sifted position Bob's basis equals Alice's, so measuring the stored photon there returns
    Alice's bit exactly. Returns (bits Eve knows, size of the signal-intensity sifted key).
    The intensity label of each forwarded pulse (plan.forward_label, parallel to forward_index) lets
    Eve tell which sifted positions are signal intensity, without her retaining all N pulses.
    """
    label_by_g = dict(zip(plan.forward_index, plan.forward_label))
    bob_basis_by_g = dict(zip(detected, bob_bases))
    stored_qubit_by_g = dict(zip(plan.stored_index, plan.stored_qubits))

    sifted_globals = [detected[p] for p in matching]
    if source == "decoy":
        key_globals = [g for g in sifted_globals if label_by_g.get(g) == SIGNAL]
    else:
        key_globals = list(sifted_globals)

    to_measure = [g for g in key_globals if g in stored_qubit_by_g]
    known = 0
    if to_measure:
        # One batched Aer job; at a sifted position the stored photon yields Alice's bit exactly.
        known = len(measure_qubits_backend([stored_qubit_by_g[g] for g in to_measure],
                                           [bob_basis_by_g[g] for g in to_measure], measurement, rng))
    pct = (known / len(key_globals) * 100) if key_globals else 0.0
    reporter.info(f"Eve knows {known}/{len(key_globals)} signal sifted-key bits ({pct:.1f}%)")
    return known, len(key_globals)
