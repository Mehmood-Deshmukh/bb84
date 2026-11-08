"""
BB84 over a lossy, noisy channel (core/channel_model.py), end to end on the Aer simulator.

Without reconciliation (not built yet) any error in the kept bits leaves Alice and Bob
with different keys, so these tests check the channel's effect on the exchange itself:
detection counts, the measured QBER, and that loss alone does not cause errors.
"""

from __future__ import annotations

from dataclasses import replace

from qkd.core.channel_model import ChannelParams, preset
from qkd.core.config import ProtocolParams
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases import receive_file as bob
from qkd.usecases import send_file as alice

BASE = ProtocolParams(enforce_finite_key=False, qber_threshold=1.01)  # study the channel, not the gates


def _exchange(connected, params: ProtocolParams):
    return connected(
        lambda s: alice.run_key_exchange(TranscriptChannel(s, "alice"), params, NullReporter()),
        lambda s: bob.run_key_exchange(TranscriptChannel(s, "bob"), params, NullReporter()),
    )


def test_loss_alone_drops_pulses_but_adds_no_errors(connected) -> None:
    params = replace(BASE, num_qubits=40_000, channel=ChannelParams(detector_efficiency=0.1))
    a, b = _exchange(connected, params)
    assert a.raw_qubits == b.raw_qubits == 40_000
    assert a.sifted_length == b.sifted_length
    # about 10% of pulses click and about half of those sift: 2000 +- 5 sd
    assert 1750 < a.sifted_length < 2250
    assert a.qber == 0.0 and a.key == b.key


def test_misalignment_shows_up_as_qber(connected) -> None:
    params = replace(BASE, num_qubits=20_000, channel=ChannelParams(misalignment=0.05))
    a, b = _exchange(connected, params)
    assert 0.03 < a.qber < 0.07  # sample of about 1500 bits around 5%
    assert a.key != b.key  # errors in the kept bits, and nothing corrects them yet


def test_realistic_link_matches_the_model(connected) -> None:
    link = preset("KTH", 50)  # click rate about 1.5%, expected QBER about 2.3%
    params = replace(BASE, num_qubits=300_000, channel=link)
    a, b = _exchange(connected, params)
    assert a.sifted_length == b.sifted_length
    detected_sift = a.sifted_length / (params.num_qubits * link.click_prob)
    assert 0.45 < detected_sift < 0.55  # half the clicks sift
    assert abs(a.qber - link.error_rate) < 0.025  # sample of about 300 bits
