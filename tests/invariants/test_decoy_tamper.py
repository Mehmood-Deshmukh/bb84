"""
Tamper-acceptance for the decoy reveal (wire step 2d): altering any field of either 2d
message makes an honest signed (hybrid) run fail before any file is delivered.

Two integrity mechanisms catch the tampers, both raising PeerAuthError:
  - Gain-affecting tampers (the sent counts, the intensity labels, Bob's reported gains)
    are caught at step 2d itself: Alice recomputes the per-intensity gains from her own
    labels and sent counts and aborts on the mismatch.
  - Tampers that do not change the gains (the revealed decoy bits, Bob's reported QBERs)
    leave the gains consistent but diverge the transcript, so they are caught at step 4b,
    where Bob's finished signature no longer verifies against Alice's transcript.

Either way the run aborts and no file is written. Small N with the finite-key gate off keeps
each run fast (this tests tamper mechanics, not key length); the ideal channel gives plenty
of signal and decoy clicks.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable

import pytest

from qkd.core.config import ProtocolParams
from qkd.usecases.common import PeerAuthError
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import WIRE_STEPS_DECOY, RecordingReporter, context, guarded, keys, proxy

# Ideal channel (default) so there are many signal and decoy clicks; QBER abort disabled and
# the finite-key gate off, so the only thing that can stop the run is the tamper.
DECOY_TAMPER_PARAMS = ProtocolParams(num_qubits=1024, qber_sample_fraction=0.3, qber_threshold=1.01,
                                     enforce_finite_key=False, source="decoy")


def _changed(new: Any, old: Any) -> Any:
    assert new != old, "tamper did not change the message"
    return new


def t_sent(msg: dict) -> dict:
    sent = list(msg["sent"])
    sent[0] += 1
    return _changed({**msg, "sent": sent}, msg)


def t_labels(msg: dict) -> dict:
    # Toggle the first non-signal label (decoy <-> vacuum): this keeps the signal/non-signal
    # partition (so the revealed-bit count still lines up) but changes the per-intensity
    # click counts, which Alice's gain recomputation catches.
    s = msg["labels"]
    i = next((j for j, c in enumerate(s) if c != "0"), None)
    assert i is not None, "no non-signal clicks to tamper with"
    flipped = "2" if s[i] == "1" else "1"
    return _changed({**msg, "labels": s[:i] + flipped + s[i + 1:]}, msg)


def t_decoy_bits(msg: dict) -> dict:
    bits = list(msg["decoy_bits"])
    assert bits, "no revealed decoy bits to tamper with"
    bits[0] ^= 1
    return _changed({**msg, "decoy_bits": bits}, msg)


def t_gains(msg: dict) -> dict:
    gains = list(msg["gains"])
    gains[0] += 1e-3
    return _changed({**msg, "gains": gains}, msg)


def t_qbers(msg: dict) -> dict:
    qbers = list(msg["qbers"])
    qbers[1] = (qbers[1] or 0.0) + 0.1  # the decoy QBER (index 1)
    return _changed({**msg, "qbers": qbers}, msg)


def _run(parallel, src: Path, out_dir: Path, keys, **proxy_kwargs):
    alice_rep, bob_rep = RecordingReporter(), RecordingReporter()
    alice_end, proxy_a = socket.socketpair()
    proxy_b, bob_end = socket.socketpair()
    with alice_end, proxy_a, proxy_b, bob_end:
        alice_res, bob_res, _ = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), alice_rep, DECOY_TAMPER_PARAMS, context(keys, "alice", "hybrid")))(alice_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), bob_rep, DECOY_TAMPER_PARAMS, context(keys, "bob", "hybrid")))(bob_end),
            lambda: proxy(proxy_a, proxy_b, steps=WIRE_STEPS_DECOY, **proxy_kwargs),
        )
    return alice_res, bob_res, alice_rep, bob_rep


@pytest.mark.parametrize(
    "step, tamper",
    [
        ("2d-reveal", t_sent),
        ("2d-reveal", t_labels),
        ("2d-reveal", t_decoy_bits),
        ("2d-gains", t_gains),
        ("2d-gains", t_qbers),
    ],
)
def test_decoy_reveal_tamper_aborts(step, tamper, keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 1000)
    out_dir = tmp_path / "received"
    alice_res, _, alice_rep, bob_rep = _run(
        parallel, src, out_dir, keys, tamper_step=step, tamper=tamper, stop_after="4b-bob"
    )
    assert isinstance(alice_res, PeerAuthError), alice_res
    assert "file_transfer" not in alice_rep.stages
    assert "file_transfer" not in bob_rep.stages
    assert not out_dir.exists()


def test_untampered_decoy_proxy_run_succeeds(keys, parallel, make_file, same_file, tmp_path: Path) -> None:
    # No tamper: proves the proxy and the disabled QBER check do not themselves break a decoy
    # run, so the aborts above are the tampers.
    src = make_file("payload.bin", 2000)
    out_dir = tmp_path / "received"
    alice_res, bob_res, _, _ = _run(parallel, src, out_dir, keys, stop_after=None)
    assert not isinstance(alice_res, Exception), alice_res
    assert not isinstance(bob_res, Exception), bob_res
    assert same_file(src, Path(bob_res.output_path))
