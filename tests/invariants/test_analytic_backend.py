"""
Analytic measurement backend equivalence (Phase 5b). The analytic backend (MEASUREMENT=analytic,
NumPy, no Qiskit) must reproduce the Aer backend's statistics: the same sifted-key rate, QBER and
per-intensity decoy gains, within sampling tolerance. This is the evidence that the fast path used
for the large composable finite-key runs is the same physical model, not a different one.

Run honestly on a decoy source over GYS and KTH at a block small enough for Aer to be affordable,
several repeats per backend, and compare the pooled statistics with a fixed-seed chi-square/interval
check.
"""

from __future__ import annotations

import math
import socket
from pathlib import Path

import pytest

from qkd.core import decoy
from qkd.core.channel_model import preset
from qkd.core.config import ProtocolParams
from qkd.core.source import DECOY, SIGNAL
from qkd.usecases.receive_file import receive_file
from qkd.usecases.send_file import send_file
from tests.invariants.support import RecordingReporter, context, guarded, keys  # noqa: F401

N = 2 ** 20            # ~1e6 pulses: a few thousand clicks, cheap enough for Aer
REPEATS = 4


def _run(measurement, length, keys, parallel, src, out_dir):
    params = ProtocolParams(num_qubits=N, channel=preset("GYS", length) if length is None else length,
                            reconciliation="cascade", source="decoy", enforce_finite_key=False,
                            measurement=measurement)
    a_rep, b_rep = RecordingReporter(), RecordingReporter()
    a_end, b_end = socket.socketpair()
    with a_end, b_end:
        a_res, b_res = parallel(
            lambda: guarded(lambda s: send_file(s, str(src), a_rep, params, context(keys, "alice", "hybrid")))(a_end),
            lambda: guarded(lambda s: receive_file(s, str(out_dir), b_rep, params, context(keys, "bob", "hybrid")))(b_end),
        )
    assert not isinstance(a_res, Exception), a_res
    assert not isinstance(b_res, Exception), b_res
    return a_res, b_rep.merged()


@pytest.mark.parametrize("preset_name", ["GYS", "KTH"])
def test_analytic_matches_aer_statistics(preset_name, keys, parallel, make_file, tmp_path: Path) -> None:
    src = make_file("payload.bin", 20_000)
    link = preset(preset_name, 25)
    stats = {"aer": [], "analytic": []}
    for backend in ("aer", "analytic"):
        for r in range(REPEATS):
            _, m = _run(backend, link, keys, parallel, src, tmp_path / f"{backend}{r}")
            stats[backend].append(m)

    def pooled(backend, key, idx=None):
        vals = [(m[key][idx] if idx is not None else m[key]) for m in stats[backend]]
        return sum(vals) / len(vals)

    # Per-intensity gains agree between backends and both track the decoy model.
    for idx, mu, rel in ((SIGNAL, 0.48, 0.12), (DECOY, 0.10, 0.18)):
        aer_g = pooled("aer", "decoy_gains", idx)
        ana_g = pooled("analytic", "decoy_gains", idx)
        model = decoy.gain(link, mu)
        assert ana_g == pytest.approx(aer_g, rel=0.15), (preset_name, idx, aer_g, ana_g)
        assert ana_g == pytest.approx(model, rel=rel)
        assert aer_g == pytest.approx(model, rel=rel)

    # Sifted-key rate (sifted / raw) agrees.
    aer_sift = pooled("aer", "sifted_length") / N
    ana_sift = pooled("analytic", "sifted_length") / N
    assert ana_sift == pytest.approx(aer_sift, rel=0.15)

    # QBER sits at the misalignment level on both, within the statistical noise of the sample.
    assert pooled("analytic", "qber") == pytest.approx(pooled("aer", "qber"), abs=0.02)
    assert pooled("analytic", "qber") == pytest.approx(link.error_rate, abs=0.02)
