"""
Eve's photon-number-splitting (PNS) workflow: a man-in-the-middle proxy that attacks a
weak-coherent-source run (SOURCE=wcp or decoy) by splitting photons off multi-photon pulses.

Unlike the intercept-resend Eve (eavesdrop_demo.py), a PNS Eve replaces the fibre with a
lossless line, so she must receive the pulses BEFORE the channel loss. Alice, run in eve-mode
with a weak-coherent source, hands the whole pre-loss pulse stream to this proxy (send_file's
pre-loss handoff) instead of the ordinary step-1 qubit message; the proxy runs the attack
(core/quantum_channel.eve_pns) and forwards an ordinary post-loss step-1 message to Bob, who
cannot tell the difference. Every classical message is relayed transparently.

Wire handled here (Alice <-> Eve <-> Bob):
  0a/0b hellos (forwarded unchanged; Alice's carries the pre-loss flag so Bob reports detections)
  1     Alice's pre-loss handoff (Alice -> Eve only); Eve -> Bob an ordinary qubit message
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
from qkd.core.quantum_channel import eve_passthrough, eve_pns, measure_qubits_backend
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


def _receive_preloss(alice: socket.socket) -> dict:
    """Alice's pre-loss handoff: {n, index, labels, photons, qubits} for the pulses with n >= 1."""
    msg = recv_json(alice)
    if not isinstance(msg, dict) or not isinstance(msg.get("preloss"), dict):
        raise ValueError("expected a pre-loss handoff; is Alice running with --eve-mode?")
    pl = msg["preloss"]
    return {
        "n": int(pl["n"]),
        "index": [int(i) for i in pl["index"]],
        "labels": [int(c) for c in pl["labels"]],
        "photons": [int(p) for p in pl["photons"]],
        "qubits": list(pl["qubits"]),
    }


def run_pns(
    alice: socket.socket,
    bob: socket.socket,
    reporter: Reporter,
    params: ProtocolParams,
    *,
    attack: bool = True,
    forward_fraction: Optional[float] = None,
    multi_fraction: Optional[float] = None,
    seed: Optional[int] = None,
) -> PnsEavesdropResult:
    """
    Run Eve's PNS proxy between connected Alice and Bob sockets.

    `attack=False` is the honest control: Eve applies the real channel loss and forwards
    survivors without splitting, which reproduces the honest gains. `forward_fraction` and
    `multi_fraction` override the single- and multi-photon forwarding rates (see eve_pns); the
    defaults match Bob's overall gain to the honest channel while maximising what Eve learns.
    """
    rng = np.random.default_rng(seed)
    source = _forward_hellos(alice, bob, reporter)
    mix_i, mix_p = params.source_mix()
    n_intensities = len(params.intensities)

    reporter.section("Phase 1: Photon-Number-Splitting Attack")
    pl = _receive_preloss(alice)
    reporter.info(f"Received {len(pl['index'])} pre-loss pulses with a photon ({pl['n']} sent)")
    if attack:
        plan = eve_pns(pl["index"], pl["labels"], pl["photons"], pl["qubits"], pl["n"],
                       n_intensities, params.channel, mix_i, mix_p, rng,
                       forward_fraction=forward_fraction, multi_fraction=multi_fraction)
        reporter.info(f"Split {sum(plan.split)} multi-photon pulses, forwarded "
                      f"{sum(plan.forwarded_single)} single-photon pulses, blocked {sum(plan.blocked)}")
    else:
        plan = eve_passthrough(pl["index"], pl["photons"], pl["qubits"], pl["n"], params.channel, rng)
        reporter.info(f"Honest control (no splitting): forwarded {len(plan.forward_index)} pulses")
    send_json(bob, encode_pulses(pl["n"], plan.forward_index, plan.forward_qubits))

    reporter.section("Phase 2: Forwarding Sifting (Transparent)")
    bob_step2 = json.loads(forward_message(bob, alice))   # Bob's {"bases","detected"}
    bob_bases = bob_step2["bases"]
    detected = [int(g) for g in bob_step2["detected"]]
    matching = json.loads(forward_message(alice, bob))    # Alice's matching indices (into detected)

    known_signal, sifted_signal = _measure_stored(
        plan, detected, bob_bases, matching, pl["index"], pl["labels"], source, reporter,
        params.measurement, rng)

    reporter.metrics(eve_known_signal=known_signal, eve_sifted_signal=sifted_signal,
                     eve_known_fraction=round(known_signal / sifted_signal, 6) if sifted_signal else 0.0)
    reporter.section("Phase 3: Relaying the Remainder")
    relay_until_closed(alice, bob)
    return PnsEavesdropResult(source, len(detected), sifted_signal, known_signal,
                              plan.blocked, plan.forwarded_single, plan.split)


def _measure_stored(plan, detected, bob_bases, matching, handed_index, handed_labels, source, reporter,
                    measurement="aer", rng=None):
    """
    Measure Eve's stored photons at the sifted signal positions, in Bob's revealed basis.

    At a sifted position Bob's basis equals Alice's, so measuring the stored photon there returns
    Alice's bit exactly. Returns (bits Eve knows, size of the signal-intensity sifted key).
    `handed_index`/`handed_labels` are the pre-loss pulses and their intensity labels, so Eve can
    tell which sifted positions are signal intensity (the key) even when she did not store them.
    """
    label_by_g = dict(zip(handed_index, handed_labels))
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
