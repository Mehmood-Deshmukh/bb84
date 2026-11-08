"""
Cascade over the wire (usecases/reconcile.py), end to end on the Aer simulator.

With reconciliation "cascade", errors from a noisy channel are corrected before
privacy amplification, the revealed parities are charged in the finite-key bound,
and every Cascade message is in the transcript (so tampering fails the signatures).
"""

from __future__ import annotations

import socket
from dataclasses import replace
from pathlib import Path

from qkd.core.cascade import CascadeError
from qkd.core.channel_model import ChannelParams, preset
from qkd.core.config import ProtocolParams
from qkd.core.finite_key import secure_key_length
from qkd.services import wire
from qkd.services.reporting import NullReporter
from qkd.services.transcript import TranscriptChannel
from qkd.usecases import receive_file as bob
from qkd.usecases import send_file as alice
from qkd.usecases.common import PeerAuthError
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys  # noqa: F401

CASCADE = ProtocolParams(reconciliation="cascade", enforce_finite_key=False)


def _exchange(connected, params: ProtocolParams, reporters=(None, None)):
    ra, rb = reporters
    return connected(
        lambda s: alice.run_key_exchange(TranscriptChannel(s, "alice"), params, ra or NullReporter()),
        lambda s: bob.run_key_exchange(TranscriptChannel(s, "bob"), params, rb or NullReporter()),
    )


def test_cascade_makes_keys_agree_on_a_noisy_channel(connected) -> None:
    params = replace(CASCADE, num_qubits=20_000, channel=ChannelParams(misalignment=0.05))
    ra, rb = RecordingReporter(), RecordingReporter()
    a, b = _exchange(connected, params, (ra, rb))
    assert a.qber > 0.02
    assert a.key == b.key  # errors corrected before privacy amplification
    ma, mb = ra.merged(), rb.merged()
    assert ma["leaked_bits"] == mb["leaked_bits"] > 0  # both sides count the same parities
    assert mb["errors_corrected"] > 0
    assert "reconciliation" in ra.stages and ra.stages.index("reconciliation") < ra.stages.index("privacy_amplification")


def test_revealed_parities_are_charged_in_the_finite_key_bound(connected) -> None:
    params = replace(CASCADE, num_qubits=20_000, channel=ChannelParams(misalignment=0.03))
    ra = RecordingReporter()
    a, _ = _exchange(connected, params, (ra, None))
    m = ra.merged()
    kept = a.sifted_length - a.sample_size
    without = secure_key_length(kept, a.sample_size, a.qber, params.eps_sec, params.eps_cor)
    assert a.secure_bits == without - m["leaked_bits"] or (a.secure_bits == 0 and without <= m["leaked_bits"])


def test_ideal_channel_with_cascade_still_works(connected) -> None:
    a, b = _exchange(connected, replace(CASCADE, num_qubits=8192))
    assert a.qber == 0.0 and a.key == b.key


def test_honest_hybrid_transfer_over_a_realistic_link(keys, connected, make_file, same_file, tmp_path: Path) -> None:
    # GYS at 25 km (QBER about 3.3%), every check on, Cascade correcting the errors
    link = preset("GYS", 25)
    params = ProtocolParams(reconciliation="cascade", channel=link, num_qubits=int(24_000 / link.click_prob))
    src = make_file("payload.bin", 50_000)
    out_dir = tmp_path / "received"
    sent, got = connected(
        lambda s: send_file(s, str(src), NullReporter(), params, context(keys, "alice", "hybrid")),
        lambda s: receive_file(s, str(out_dir), NullReporter(), params, context(keys, "bob", "hybrid")),
    )
    assert not sent.aborted and 0.02 < sent.qber < 0.05
    assert sent.secure_bits >= 256
    assert same_file(src, Path(got.output_path))


def test_tampered_cascade_answer_never_yields_a_key(keys, parallel, make_file, tmp_path: Path) -> None:
    params = replace(CASCADE, num_qubits=4096, channel=ChannelParams(misalignment=0.05))
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()

    def proxy() -> None:
        # Forward message by message; change the first {"parities": ...} from Alice
        import selectors

        changed = False
        with selectors.DefaultSelector() as sel:
            sel.register(proxy_a, selectors.EVENT_READ)
            sel.register(proxy_b, selectors.EVENT_READ)
            try:
                while True:
                    for key, _ in sel.select():
                        src_sock = key.fileobj
                        dst = proxy_b if src_sock is proxy_a else proxy_a
                        raw = wire.recv_bytes(src_sock)
                        if not changed and src_sock is proxy_a and raw.startswith(b'{"parities":'):
                            msg = wire.decode_json(raw)
                            msg["parities"][0] ^= 1
                            raw = wire.encode_json(msg)
                            changed = True
                        wire.send_bytes(dst, raw)
            except (ConnectionError, OSError, ValueError):
                pass
            finally:
                for s in (proxy_a, proxy_b):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    with alice_end, proxy_a, proxy_b, bob_end:
        alice_res, bob_res, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), NullReporter(), params, context(keys, "alice", "hybrid")))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), NullReporter(), params, context(keys, "bob", "hybrid")))(bob_end),
            proxy,
        )
    # Either Bob notices the inconsistent parities (CascadeError) and stops, or he finishes
    # with a transcript that differs from Alice's and the finished signature fails. Either
    # way no key is used and no file is written.
    caught_by_cascade = isinstance(bob_res, CascadeError)
    caught_by_signature = isinstance(alice_res, PeerAuthError) and "signature" in alice_res.reason
    assert caught_by_cascade or caught_by_signature, (alice_res, bob_res)
    assert not out_dir.exists()
