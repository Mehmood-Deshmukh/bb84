"""
Pure helpers of scripts/benchmark.py and scripts/plot_figures.py: event parsing,
stage timing, outcome labels, statistics, and the analytic detection model.

No processes are started here; the harness itself is exercised by running it.
"""

from __future__ import annotations

import importlib.util
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench = _load("benchmark")


def ev(type_: str, ts: float, stage: str = "", **payload) -> dict:
    return {"type": type_, "stage": stage, "payload": payload, "ts": ts}


EVENTS = [
    ev("stage", 0.0, "connecting"),
    ev("stage", 1.0, "authentication"),
    ev("metrics", 1.1, "authentication", auth_mode="none"),
    ev("stage", 1.5, "quantum_transmission"),
    ev("stage", 3.5, "sifting"),
    ev("metrics", 3.6, "sifting", sifted_length=100, sim_ms=1800.0),
    ev("stage", 4.0, "file_transfer"),
    ev("result", 4.25, "file_transfer", outcome="completed", error=None),
]


def test_parse_events_skips_non_json() -> None:
    lines = ["banner text", '{"type": "stage", "stage": "x", "payload": {}, "ts": 1}', "{broken", "[1, 2]"]
    assert [e["type"] for e in bench.parse_events(lines)] == ["stage"]


def test_stage_durations_run_to_next_stage_or_result() -> None:
    d = bench.stage_durations(EVENTS)
    assert d["authentication"] == pytest.approx(0.5)
    assert d["quantum_transmission"] == pytest.approx(2.0)
    assert d["sifting"] == pytest.approx(0.5)
    assert d["file_transfer"] == pytest.approx(0.25)


def test_summarize_events_measures_from_authentication_to_result() -> None:
    s = bench.summarize_events(EVENTS)
    assert s["protocol_s"] == pytest.approx(3.25)  # connecting is not counted
    assert s["metrics"] == {"auth_mode": "none", "sifted_length": 100, "sim_ms": 1800.0}
    assert (s["outcome"], s["error"]) == ("completed", None)


def side(outcome: str, error: str | None = None) -> dict:
    return {"outcome": outcome, "error": error}


@pytest.mark.parametrize(
    "alice, bob, intact, expected",
    [
        (side("completed"), side("completed"), True, "delivered"),
        (side("completed"), side("completed"), False, "other"),
        (side("aborted_qber", "QBER 25.00% >= threshold 11%"), side("aborted_qber", "QBER 25.00% >= threshold 11%"),
         False, "qber_check"),
        (side("aborted_qber", "finite-key bound gives 0 secure bits, 256 needed"), side("aborted_qber", "x"),
         False, "finite_key"),
        (side("aborted_qber", "key confirmation failed: bob's key differs"), side("failed", "Connection reset"),
         False, "key_confirmation"),
        (side("aborted_auth", "bob finished signature invalid"), side("failed", "closed"), False, "authentication"),
        (side("completed"), side("failed", "InvalidTag"), False, "chunk_tag"),
    ],
)
def test_classify(alice: dict, bob: dict, intact: bool, expected: str) -> None:
    assert bench.classify(alice, bob, intact) == expected


def test_wilson_interval() -> None:
    lo, hi = bench.wilson(44, 50)
    assert (round(lo, 3), round(hi, 3)) == (0.762, 0.944)
    assert bench.wilson(0, 10)[0] == 0.0 and bench.wilson(10, 10)[1] == 1.0
    assert all(math.isnan(v) for v in bench.wilson(0, 0))


def test_quartiles() -> None:
    assert bench.quartiles([5.0]) == (5.0, 5.0, 5.0)
    assert bench.quartiles([1.0, 2.0, 3.0, 4.0, 5.0]) == (2.0, 3.0, 4.0)


def test_grid_points_cover_every_combination_with_defaults() -> None:
    cfg = {"fixed": {"payload_bytes": 10}, "grid": {"mode": ["none", "hybrid"], "QKD_NUM_QUBITS": [1, 2, 3]}}
    keys, points = bench.grid_points(cfg)
    assert keys == ["mode", "QKD_NUM_QUBITS"]
    assert len(points) == 6
    assert all(p["payload_bytes"] == 10 and p["eve_fraction"] == 0.0 for p in points)


def test_summarize_gives_rates_and_quartiles_per_point() -> None:
    rows = [{"mode": "none", "stopped_at": s, "protocol_s": t}
            for s, t in [("delivered", 1.0), ("delivered", 2.0), ("qber_check", 3.0)]]
    (summary,) = bench.summarize(rows, ["mode"])
    assert summary["n"] == 3
    assert summary["rate_delivered"] == pytest.approx(2 / 3, abs=1e-4)
    assert summary["rate_qber_check_lo"] < 1 / 3 < summary["rate_qber_check_hi"]
    assert summary["protocol_s_median"] == 2.0


def test_detection_model() -> None:
    pytest.importorskip("matplotlib")
    pytest.importorskip("yaml")
    plot = _load("plot_figures")
    # 9 sample bits: one error already reaches 11%, so detection = 1 - (3/4)^9 for a full attack
    assert plot.detection_probability(9, 1.0) == pytest.approx(1 - 0.75**9)
    assert plot.detection_probability(600, 0.0) == 0.0
    assert plot.detection_probability(600, 1.0) > 0.999999
