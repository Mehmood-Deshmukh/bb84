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


def test_run_plan_covers_every_run_once_in_a_seeded_order() -> None:
    plan = bench.run_plan(4, 3, seed=7)
    assert sorted(plan) == [(i, r) for i in range(4) for r in range(3)]
    assert plan == bench.run_plan(4, 3, seed=7)
    assert plan != bench.run_plan(4, 3, seed=8)
    # Shuffled, not grouped: the first point's repeats are not all at the front
    assert plan[:3] != [(0, 0), (0, 1), (0, 2)]


def test_run_id_names_time_commit_and_quality_flags() -> None:
    from datetime import datetime, timezone

    t = datetime(2026, 11, 5, 18, 26, tzinfo=timezone.utc)
    assert bench.run_id(t, "0ca1f28abcdef", False, False) == "20261105T1826Z_0ca1f28"
    assert bench.run_id(t, "0ca1f28abcdef", True, True) == "20261105T1826Z_0ca1f28-dirty-scratch"


@pytest.mark.parametrize(
    "meta, expected",
    [
        ({"status": "complete", "git_dirty": False, "repeats": 30, "config": {"repeats": 30}}, True),
        ({"status": "complete", "git_dirty": False, "repeats": 30, "config": {}}, True),  # default 30
        ({"status": "running", "git_dirty": False, "repeats": 30, "config": {"repeats": 30}}, False),
        ({"status": "complete", "git_dirty": True, "repeats": 30, "config": {"repeats": 30}}, False),
        ({"status": "complete", "git_dirty": False, "repeats": 2, "config": {"repeats": 30}}, False),
    ],
    ids=["clean", "default_repeats", "running", "dirty", "scratch"],
)
def test_paper_grade(meta: dict, expected: bool) -> None:
    assert bench.paper_grade(meta) is expected


def test_row_log_appends_and_resume_skips_finished_runs(tmp_path) -> None:
    keys = ["mode", "eve_fraction"]
    log = bench.RowLog(tmp_path / "runs.csv")
    log.append({"mode": "none", "eve_fraction": 0.0, "repeat": 0, "stopped_at": "delivered"})
    log.append({"mode": "none", "eve_fraction": 1.0, "repeat": 1, "stopped_at": "qber_check"})

    # A new RowLog on the same file (what --resume does) keeps the header and appends
    again = bench.RowLog(tmp_path / "runs.csv")
    again.append({"mode": "hybrid", "eve_fraction": 0.0, "repeat": 0, "stopped_at": "delivered"})
    rows = bench.read_csv(tmp_path / "runs.csv")
    assert [r["mode"] for r in rows] == ["none", "none", "hybrid"]

    done = bench.done_keys(rows, keys)
    assert bench.run_key({"mode": "none", "eve_fraction": 1.0}, keys, 1) in done
    assert bench.run_key({"mode": "none", "eve_fraction": 1.0}, keys, 0) not in done


def test_update_latest_points_at_the_run_dir(tmp_path) -> None:
    first, second = tmp_path / "20261105T1826Z_aaaaaaa", tmp_path / "20261106T0100Z_bbbbbbb"
    first.mkdir()
    second.mkdir()
    bench.update_latest(tmp_path, first)
    bench.update_latest(tmp_path, second)
    latest = tmp_path / "latest"
    assert latest.is_symlink() and latest.resolve() == second.resolve()
    assert not (tmp_path / ".latest.tmp").exists()


def test_point_channel_follows_the_channel_settings() -> None:
    gys = bench.point_channel({"QKD_CHANNEL_PRESET": "GYS", "QKD_CHANNEL_LENGTH_KM": 50}, {})
    assert gys.length_km == 50 and gys.loss_db_per_km == 0.21
    # The environment applies unless the point overrides it
    over = bench.point_channel({"QKD_MISALIGNMENT": 0.02}, {"QKD_CHANNEL_PRESET": "KTH"})
    assert over.detector_efficiency == 0.143 and over.misalignment == 0.02
    assert bench.point_channel({}, {}).is_ideal


def test_a_run_whose_tree_changed_is_not_paper_grade() -> None:
    meta = {"status": "complete", "git_dirty": False, "repeats": 30, "config": {"repeats": 30}}
    assert bench.paper_grade(meta)
    assert not bench.paper_grade({**meta, "tree_changed_during_run": True})
