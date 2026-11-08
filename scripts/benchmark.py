#!/usr/bin/env python3
"""
Run an experiment defined in experiments/configs/*.yaml.

    python scripts/benchmark.py experiments/configs/e4_overhead.yaml [--repeats N] [--seed S]
    python scripts/benchmark.py --resume experiments/results/e4_overhead/<run id>

Every run starts real qkd.runner.bob, qkd.runner.alice, and (optionally) qkd.runner.eve
processes on localhost, exactly as a user would. Timing comes from the JSON events the
runners emit (each carries a wall-clock "ts"), so process start-up and the qiskit import
are not counted. Bob is started on port 0 and the harness waits for his `listening`
event instead of sleeping.

Config keys:
  name          output file stem
  description   free text, copied into the metadata file
  repeats       runs per grid point (default 30)
  grid          parameter -> list of values; every combination is run
  fixed         parameter -> single value, applied to every run (optional)
  seed          seed for the run order (optional; --seed overrides; random if neither)

All runs of an experiment are executed in one shuffled order (see run_plan), and
each row records its position in that order in the `order` column.

Parameters:
  mode           none | sign | hybrid (default none)
  payload_bytes  size of the random file Alice sends (default 1000)
  eve_fraction   share of qubits Eve intercepts; 0 means no Eve (default 0)
  target_detected  aim for this many pulses detected at Bob: sets QKD_NUM_QUBITS to
                 ceil(target / click probability) for the point's channel (QKD_CHANNEL_*
                 settings), so every distance gets a similar number of detections
  rtt_ms         round-trip time added between Alice and the next hop by
                 scripts/latency_proxy.py (rtt_ms / 2 each way); unset means no proxy,
                 0 means the proxy with no delay (the baseline for its own overhead)
  QKD_*          anything else is passed to all processes as an environment variable

Outputs: one folder per invocation (a "run id"), never overwritten:

  experiments/results/<name>/<YYYYMMDDTHHMMZ>_<commit7>[-dirty][-scratch]/
    runs.csv      one row per run, appended as each run finishes (survives interruption)
    summary.csv   one row per grid point: median and IQR of every timing and byte column,
                  and the rate of each outcome with a Wilson 95% interval; written at the end
    meta.json     status (running | complete), git commit, package versions, CPU, Python,
                  the config, the run order seed; resume history
    log.txt       everything this script printed
  experiments/results/<name>/latest  ->  the newest run id that is paper grade

A run id is paper grade when it completed, ran on a clean tree, and used the config's
own repeats. Anything else is marked -scratch (or -dirty) and never moves `latest`.
scripts/plot_figures.py reads only `latest`. Findings are written up by hand in
experiments/ignore-INSIGHTS.md (gitignored), one entry per run id.

Needs the `experiments` extra (pyyaml).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import os
import platform
import queue
import random
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments" / "results"

STAGES = [
    "authentication",
    "quantum_transmission",
    "sifting",
    "qber_estimation",
    "reconciliation",
    "privacy_amplification",
    "key_confirmation",
    "file_transfer",
]
METRICS = [
    "raw_qubits", "detected", "sifted_length", "sample_size", "qber", "secure_key_bits", "key_bits",
    "handshake_ms", "auth_overhead_bytes", "qubit_bytes", "channel_bytes", "file_wire_bytes",
    "reconciliation_rounds", "leaked_bits", "leaked_bits_conservative", "errors_corrected", "reconciliation_ms",
    # Decoy-state measurements (decoy source only; None otherwise)
    "decoy_gain_signal", "decoy_gain_decoy", "decoy_gain_vacuum",
    "decoy_qber_decoy", "decoy_qber_vacuum",
    "decoy_sent_signal", "decoy_sent_decoy", "decoy_sent_vacuum",
    "decoy_clicks_signal", "decoy_clicks_decoy", "decoy_clicks_vacuum",
    "decoy_Y1_lower", "decoy_e1_upper", "decoy_Q1_lower",
]
SPECIAL = {"mode", "payload_bytes", "eve_fraction", "eve_attack", "rtt_ms", "target_detected"}
DEFAULTS = {"mode": "none", "payload_bytes": 1000, "eve_fraction": 0.0, "eve_attack": "none",
            "rtt_ms": None, "target_detected": None}
LATENCY_PROXY = ROOT / "scripts" / "latency_proxy.py"
PROCESS_TIMEOUT = 600.0


# ── small helpers ───────────────────────────────────────────────────────────

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def runner(name: str, *args: str) -> list[str]:
    return [sys.executable, "-m", f"qkd.runner.{name}", *args]


def parse_events(lines: Iterable[str]) -> list[dict]:
    """JSON event lines from a runner's stdout; anything else is skipped."""
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and "type" in event:
            events.append(event)
    return events


def stage_durations(events: list[dict]) -> dict[str, float]:
    """
    Seconds spent in each stage: from its stage event to the next stage event,
    or to the result event for the last one.
    """
    marks = [(e["payload"].get("stage") or e.get("stage"), e["ts"]) for e in events if e["type"] == "stage"]
    end = next((e["ts"] for e in events if e["type"] == "result"), None)
    durations: dict[str, float] = {}
    for i, (stage, ts) in enumerate(marks):
        nxt = marks[i + 1][1] if i + 1 < len(marks) else end
        if nxt is not None:
            durations[stage] = durations.get(stage, 0.0) + (nxt - ts)
    return durations


def summarize_events(events: list[dict]) -> dict[str, Any]:
    """Metrics, outcome, error, stage durations, and protocol time from one side's events."""
    metrics: dict[str, Any] = {}
    outcome, error = "missing", None
    for e in events:
        if e["type"] == "metrics":
            metrics.update(e["payload"])
        elif e["type"] == "result":
            outcome, error = e["payload"].get("outcome"), e["payload"].get("error")
    durations = stage_durations(events)
    start = next((e["ts"] for e in events if e["type"] == "stage" and _stage_name(e) == "authentication"), None)
    end = next((e["ts"] for e in events if e["type"] == "result"), None)
    protocol_s = (end - start) if start is not None and end is not None else None
    return {"metrics": metrics, "outcome": outcome, "error": error, "durations": durations,
            "protocol_s": protocol_s, "start_ts": start, "end_ts": end}


def _stage_name(event: dict) -> Optional[str]:
    return event["payload"].get("stage") or event.get("stage")


def classify(alice: dict, bob: dict, intact: bool) -> str:
    """
    Where the run stopped, as one label:
      delivered, qber_check, finite_key, key_confirmation, authentication,
      chunk_tag (keys differed and only AES-GCM noticed, none mode), other
    """
    if alice["outcome"] == "completed" and bob["outcome"] == "completed" and intact:
        return "delivered"
    errors = " | ".join(str(side["error"] or "") for side in (alice, bob)).lower()
    if "key confirmation" in errors:
        return "key_confirmation"
    if "finite-key" in errors:
        return "finite_key"
    if any(side["outcome"] == "aborted_qber" for side in (alice, bob)):
        return "qber_check"
    if any(side["outcome"] == "aborted_auth" for side in (alice, bob)):
        return "authentication"
    if "invalidtag" in errors:
        return "chunk_tag"
    return "other"


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (math.nan, math.nan)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def quartiles(values: list[float]) -> tuple[float, float, float]:
    """(q1, median, q3) with the inclusive method; a single value gives itself three times."""
    if len(values) == 1:
        return (values[0],) * 3
    q1, q2, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return q1, q2, q3


# ── one run ─────────────────────────────────────────────────────────────────

class LineReader:
    """Collect a process's stdout lines on a thread, and signal when Bob reports his port."""

    def __init__(self, proc: subprocess.Popen) -> None:
        self.lines: list[str] = []
        self.port: queue.Queue[int] = queue.Queue()
        self._thread = threading.Thread(target=self._read, args=(proc,), daemon=True)
        self._thread.start()

    def _read(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            self.lines.append(line)
            if '"listening"' in line:
                for event in parse_events([line]):
                    if event["type"] == "listening":
                        self.port.put(int(event["payload"]["port"]))

    def join(self) -> None:
        self._thread.join(timeout=10)


def point_channel(point: dict, base_env: dict):
    """
    The ChannelParams a run at this point will use, built the way core/config.py builds
    it from the QKD_CHANNEL_* settings (the point's values override the environment's).
    """
    from dataclasses import replace

    from qkd.core.channel_model import preset

    env = {**base_env, **{k: str(v) for k, v in point.items() if k not in SPECIAL}}

    def num(name: str):
        raw = env.get(f"QKD_{name}", "")
        return float(raw) if raw != "" else None

    base = preset(env.get("QKD_CHANNEL_PRESET") or "ideal", num("CHANNEL_LENGTH_KM") or 0.0)
    overrides = {field: value for field, value in (
        ("loss_db_per_km", num("FIBER_LOSS_DB_PER_KM")),
        ("detector_efficiency", num("DETECTOR_EFFICIENCY")),
        ("dark_count_prob", num("DARK_COUNT_PROB")),
        ("misalignment", num("MISALIGNMENT")),
    ) if value is not None}
    return replace(base, **overrides)


def run_once(point: dict, payload: Path, payload_sha: str, work: Path, ids: dict, base_env: dict) -> dict:
    """One Alice/Bob (and maybe Eve) run for a grid point. Returns a flat result row."""
    mode, fraction = point["mode"], float(point["eve_fraction"])
    attack = str(point.get("eve_attack", "none"))
    env = {**base_env, **{k: str(v) for k, v in point.items() if k not in SPECIAL}}
    channel = point_channel(point, base_env)
    if point.get("target_detected") is not None:
        env["QKD_NUM_QUBITS"] = str(math.ceil(float(point["target_detected"]) / channel.click_prob))
    out_dir = work / "received"
    auth_alice, auth_bob = [], []
    if mode != "none":
        auth_alice = ["--auth", mode, "--identity", str(ids["alice_dir"]), "--peer-fingerprint", ids["bob_fp"]]
        auth_bob = ["--auth", mode, "--identity", str(ids["bob_dir"]), "--peer-fingerprint", ids["alice_fp"]]
    else:
        auth_alice, auth_bob = ["--auth", "none"], ["--auth", "none"]

    procs: list[subprocess.Popen] = []
    try:
        bob = subprocess.Popen(
            runner("bob", "--port", "0", "--events", "json", "--output-dir", str(out_dir), *auth_bob),
            env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        procs.append(bob)
        bob_reader = LineReader(bob)
        bob_port = bob_reader.port.get(timeout=120)

        alice_port = bob_port
        alice_eve = []
        if attack == "pns":
            # PNS Eve: Alice hands her pre-loss pulses (needs --eve-mode and a weak-coherent source).
            alice_port = free_port()
            alice_eve = ["--eve-mode"]
            procs.append(subprocess.Popen(
                runner("eve", "--attack", "pns", "--bob-port", str(bob_port), "--listen-port", str(alice_port)),
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
        elif fraction > 0:
            alice_port = free_port()
            procs.append(subprocess.Popen(
                runner("eve", "--bob-port", str(bob_port), "--listen-port", str(alice_port), "--fraction", str(fraction)),
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))

        if point.get("rtt_ms") is not None:
            # Alice -> latency proxy -> (Eve ->) Bob; half the round trip in each direction
            proxy = subprocess.Popen(
                [sys.executable, str(LATENCY_PROXY), "--target-port", str(alice_port),
                 "--one-way-ms", str(float(point["rtt_ms"]) / 2)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            procs.append(proxy)
            ready = proxy.stdout.readline()
            if not ready.startswith("listening "):
                raise RuntimeError(f"latency proxy did not start: {ready!r}")
            alice_port = int(ready.split()[1])

        wall_start = time.perf_counter()
        alice = subprocess.run(
            runner("alice", str(payload), "--host", "127.0.0.1", "--port", str(alice_port), "--events", "json",
                   *alice_eve, *auth_alice),
            env=env, capture_output=True, text=True, timeout=PROCESS_TIMEOUT,
        )
        wall_s = time.perf_counter() - wall_start
        for proc in procs:
            proc.wait(timeout=PROCESS_TIMEOUT)
        bob_reader.join()
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()

    a = summarize_events(parse_events(alice.stdout.splitlines()))
    b = summarize_events(parse_events(bob_reader.lines))
    received = out_dir / f"received_{payload.name}"
    intact = received.exists() and _sha256(received) == payload_sha
    if received.exists():
        received.unlink()

    row: dict[str, Any] = {
        "num_pulses": int(env.get("QKD_NUM_QUBITS", 0)) or None,
        # What the channel model predicts for this point, to compare with the measurements
        "model_click_prob": channel.click_prob,
        "model_qber": round(channel.error_rate, 6),
        "stopped_at": classify(a, b, intact),
        "intact": int(intact),
        "alice_outcome": a["outcome"], "bob_outcome": b["outcome"],
        "alice_error": a["error"], "bob_error": b["error"],
        "wall_s": round(wall_s, 4),
        "protocol_s": _round(a["protocol_s"]),
        # Alice's first protocol stage to Bob's result: includes Bob decrypting and writing
        # the file after Alice has finished sending. Same machine clock, so valid on localhost.
        "end_to_end_s": _round(b["end_ts"] - a["start_ts"]) if b["end_ts"] and a["start_ts"] else None,
    }
    for name in METRICS:
        row[name] = a["metrics"].get(name, b["metrics"].get(name))
    # Classical BB84 messages only: everything through the channel minus the qubit
    # stream and the hello/finished messages counted in auth_overhead_bytes
    if None not in (row["channel_bytes"], row["qubit_bytes"], row["auth_overhead_bytes"]):
        row["bb84_classical_bytes"] = row["channel_bytes"] - row["qubit_bytes"] - row["auth_overhead_bytes"]
    else:
        row["bb84_classical_bytes"] = None
    row["click_rate"] = (row["detected"] / row["raw_qubits"]) if row.get("detected") and row.get("raw_qubits") else None
    row["sim_s"] = _round(((a["metrics"].get("sim_ms") or 0) + (b["metrics"].get("sim_ms") or 0)) / 1000)
    # Protocol time with the simulator's share removed. The simulation steps run one
    # after another (Alice prepares, then Bob measures), so subtracting both is valid.
    row["protocol_minus_sim_s"] = _round(a["protocol_s"] - row["sim_s"]) if a["protocol_s"] is not None else None
    row["end_to_end_minus_sim_s"] = _round(row["end_to_end_s"] - row["sim_s"]) if row["end_to_end_s"] is not None else None
    # Expected decoy quantities from the channel model, next to the measured ones (decoy only).
    row.update(_decoy_model_columns(env, channel))
    for stage in STAGES:
        row[f"alice_{stage}_s"] = _round(a["durations"].get(stage))
        row[f"bob_{stage}_s"] = _round(b["durations"].get(stage))
    return row


def _round(value: Optional[float], digits: int = 5) -> Optional[float]:
    return None if value is None else round(value, digits)


DECOY_MODEL_COLUMNS = ["model_gain_signal", "model_gain_decoy", "model_gain_vacuum", "model_Y1", "model_e1"]


def _decoy_model_columns(env: dict, channel) -> dict:
    """Expected gains and single-photon values from the channel model (None unless decoy)."""
    if env.get("QKD_SOURCE") != "decoy":
        return {col: None for col in DECOY_MODEL_COLUMNS}
    from qkd.core import decoy

    raw = env.get("QKD_DECOY_INTENSITIES")
    mus = tuple(float(x) for x in raw.split(",")) if raw else (0.48, 0.1, 0.0)
    return {
        "model_gain_signal": round(decoy.gain(channel, mus[0]), 9),
        "model_gain_decoy": round(decoy.gain(channel, mus[1]), 9),
        "model_gain_vacuum": round(decoy.gain(channel, mus[2]), 9),
        "model_Y1": round(decoy.single_photon_yield(channel), 9),
        "model_e1": round(decoy.single_photon_error(channel), 9),
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ── summary and metadata ────────────────────────────────────────────────────

NUMERIC_SUMMARY = ["num_pulses", "click_rate", "model_click_prob", "model_qber", "wall_s", "protocol_s", "end_to_end_s", "end_to_end_minus_sim_s", "sim_s", "protocol_minus_sim_s", "bb84_classical_bytes", *METRICS, *DECOY_MODEL_COLUMNS,
                   *[f"{side}_{stage}_s" for side in ("alice", "bob") for stage in STAGES]]
OUTCOMES = ["delivered", "qber_check", "finite_key", "key_confirmation", "authentication", "chunk_tag", "other"]


def summarize(rows: list[dict], keys: list[str]) -> list[dict]:
    """One row per grid point: n, outcome rates with Wilson intervals, and quartiles of numeric columns."""
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault(tuple(row[k] for k in keys), []).append(row)
    out = []
    for point, group in groups.items():
        summary: dict[str, Any] = dict(zip(keys, point))
        n = len(group)
        summary["n"] = n
        for outcome in OUTCOMES:
            hits = sum(r["stopped_at"] == outcome for r in group)
            lo, hi = wilson(hits, n)
            summary[f"rate_{outcome}"] = round(hits / n, 5)
            summary[f"rate_{outcome}_lo"] = round(lo, 5)
            summary[f"rate_{outcome}_hi"] = round(hi, 5)
        for col in NUMERIC_SUMMARY:
            values = [float(r[col]) for r in group if r.get(col) not in (None, "")]
            if not values:
                continue
            q1, med, q3 = quartiles(values)
            summary[f"{col}_median"] = round(med, 6)
            summary[f"{col}_q1"] = round(q1, 6)
            summary[f"{col}_q3"] = round(q3, 6)
        out.append(summary)
    return out


def environment(cfg: dict) -> dict:
    def version(pkg: str) -> Optional[str]:
        try:
            return importlib_metadata.version(pkg)
        except importlib_metadata.PackageNotFoundError:
            return None

    def git(*args: str) -> Optional[str]:
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    cpu = platform.processor() or None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "started": datetime.now(timezone.utc).isoformat(),
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu": cpu,
        "cpu_count": os.cpu_count(),
        "packages": {p: version(p) for p in ("qiskit", "qiskit-aer", "cryptography", "numpy", "qkd")},
        "config": cfg,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fields: list[str] = []
    for row in rows:
        fields.extend(k for k in row if k not in fields)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


class RowLog:
    """Append rows to runs.csv one at a time, flushing each, so an interrupted run keeps them."""

    def __init__(self, path: Path) -> None:
        self.path = path
        existing = read_csv(path)
        self.fields: Optional[list[str]] = list(existing[0]) if existing else None

    def append(self, row: dict) -> None:
        new_file = self.fields is None
        if new_file:
            self.fields = list(row)
        with open(self.path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.fields)
            if new_file:
                writer.writeheader()
            writer.writerow(row)
            f.flush()
            os.fsync(f.fileno())


def run_id(started: datetime, commit: Optional[str], dirty: bool, scratch: bool) -> str:
    """Folder name for one invocation: UTC start time, short commit, and quality flags."""
    name = f"{started.strftime('%Y%m%dT%H%MZ')}_{(commit or 'nocommit')[:7]}"
    if dirty:
        name += "-dirty"
    if scratch:
        name += "-scratch"
    return name


def paper_grade(meta: dict) -> bool:
    """Complete, clean tree throughout, and the config's own number of repeats."""
    return (meta.get("status") == "complete" and not meta.get("git_dirty")
            and not meta.get("tree_changed_during_run")
            and meta.get("repeats") == meta.get("config", {}).get("repeats", 30))


def tree_changed(meta: dict) -> bool:
    """
    Did the code change while the run was going? The runners import the working tree
    (editable install), so an edit during a run silently mixes code versions.
    """
    now = environment(meta.get("config", {}))
    return (now["git_commit"], now["git_dirty"]) != (meta.get("git_commit"), meta.get("git_dirty"))


def done_keys(rows: list[dict], keys: list[str]) -> set[tuple[str, ...]]:
    """(grid values..., repeat) of every run already in runs.csv, as strings."""
    return {tuple(str(r[k]) for k in keys) + (str(r["repeat"]),) for r in rows}


def run_key(point: dict, keys: list[str], repeat: int) -> tuple[str, ...]:
    return tuple(str(point[k]) for k in keys) + (str(repeat),)


def point_label(point: dict, keys: list[str]) -> str:
    return ", ".join(f"{k}={point[k]}" for k in keys)


def update_latest(exp_dir: Path, run_dir: Path) -> None:
    """Point <experiment>/latest at run_dir (a relative symlink, replaced atomically)."""
    tmp = exp_dir / ".latest.tmp"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(run_dir.name)
    os.replace(tmp, exp_dir / "latest")


def grid_points(cfg: dict) -> tuple[list[str], list[dict]]:
    """(grid parameter names, list of full parameter dicts) for every combination."""
    grid = cfg.get("grid", {})
    keys = list(grid)
    points = []
    for combo in itertools.product(*(grid[k] for k in keys)):
        points.append({**DEFAULTS, **cfg.get("fixed", {}), **dict(zip(keys, combo))})
    return keys, points


def run_plan(num_points: int, repeats: int, seed: int) -> list[tuple[int, int]]:
    """
    Every (grid point index, repeat) pair, in a seeded random order.

    Running a point's repeats back to back would line up slow drift over a long
    session (heat, background load) with the parameter being varied. Shuffling
    spreads that drift evenly over all points; the seed makes the order
    reproducible and is recorded in the metadata file.
    """
    plan = [(i, r) for i in range(num_points) for r in range(repeats)]
    random.Random(seed).shuffle(plan)
    return plan


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    import yaml

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", type=Path, nargs="?")
    parser.add_argument("--repeats", type=int, help="Override the config's repeats (marks the run id -scratch)")
    parser.add_argument("--seed", type=int, help="Seed for the run order (default: config 'seed', else random)")
    parser.add_argument("--resume", type=Path, metavar="RUN_DIR",
                        help="Continue an interrupted run id; uses its recorded config, repeats, and seed")
    args = parser.parse_args()
    if (args.config is None) == (args.resume is None):
        parser.error("give either a config file or --resume RUN_DIR")

    if args.resume:
        run_dir = args.resume.resolve()
        meta = json.loads((run_dir / "meta.json").read_text())
        cfg, repeats, seed = meta["config"], meta["repeats"], meta["run_order_seed"]
        env_now = environment(cfg)
        if (env_now["git_commit"], env_now["git_dirty"]) != (meta["git_commit"], meta["git_dirty"]):
            print(f"refusing to resume: run used {meta['git_commit'][:7]} (dirty={meta['git_dirty']}), "
                  f"tree is now {env_now['git_commit'][:7]} (dirty={env_now['git_dirty']})", file=sys.stderr)
            return 2
        meta.setdefault("resumed", []).append(datetime.now(timezone.utc).isoformat())
    else:
        cfg = yaml.safe_load(args.config.read_text())
        repeats = args.repeats or cfg.get("repeats", 30)
        seed = args.seed if args.seed is not None else cfg.get("seed", secrets.randbits(32))
        meta = environment(cfg)
        meta.update(repeats=repeats, run_order_seed=seed, status="running")
        scratch = repeats != cfg.get("repeats", 30)
        started = datetime.fromisoformat(meta["started"])
        run_dir = RESULTS / cfg["name"] / run_id(started, meta["git_commit"], meta["git_dirty"], scratch)
        run_dir.mkdir(parents=True, exist_ok=False)
        meta["run_id"] = run_dir.name

    meta_path = run_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2, default=str))
    log_file = open(run_dir / "log.txt", "a")

    def say(line: str) -> None:
        print(line, flush=True)
        log_file.write(line + "\n")
        log_file.flush()

    keys, points = grid_points(cfg)
    rows_log = RowLog(run_dir / "runs.csv")
    done = done_keys(read_csv(run_dir / "runs.csv"), keys)
    plan = run_plan(len(points), repeats, seed)
    todo = [(order, i, r) for order, (i, r) in enumerate(plan) if run_key(points[i], keys, r) not in done]
    say(f"run id {run_dir.name}: {len(plan)} runs planned, {len(plan) - len(todo)} already done, seed {seed}")
    base_env = {**os.environ, "PYTHONUNBUFFERED": "1"}

    with tempfile.TemporaryDirectory(prefix="qkd-bench-") as tmp:
        work = Path(tmp)
        ids = _identities(work)
        # Every payload is written before the first run, so file creation never
        # falls between two timed runs
        payloads: dict[int, tuple[Path, str]] = {}
        for point in points:
            size = int(point["payload_bytes"])
            if size not in payloads:
                path = work / f"payload_{size}.bin"
                path.write_bytes(os.urandom(size))
                payloads[size] = (path, _sha256(path))

        for n, (order, index, repeat) in enumerate(todo, start=len(plan) - len(todo) + 1):
            point = points[index]
            payload, sha = payloads[int(point["payload_bytes"])]
            row = {**{k: point[k] for k in keys}, "repeat": repeat, "order": order,
                   **run_once(point, payload, sha, work, ids, base_env)}
            rows_log.append(row)
            say(f"[{n}/{len(plan)}] {point_label(point, keys)} #{repeat + 1}: {row['stopped_at']} "
                f"protocol={row['protocol_s']}s")

    # The summary is always computed from runs.csv on disk, so resumed runs are included
    write_csv(run_dir / "summary.csv", summarize(read_csv(run_dir / "runs.csv"), keys))
    meta.update(status="complete", finished=datetime.now(timezone.utc).isoformat(),
                tree_changed_during_run=tree_changed(meta))
    meta_path.write_text(json.dumps(meta, indent=2, default=str))
    if meta["tree_changed_during_run"]:
        say("WARNING: the code changed during this run (commit or uncommitted edits); "
            "it is not paper grade. Rerun on a clean, unchanged tree.")
    if paper_grade(meta):
        update_latest(run_dir.parent, run_dir)
        say(f"complete; {run_dir.parent.name}/latest -> {run_dir.name}")
    else:
        say("complete; not paper grade (scratch or dirty tree), so latest was not moved")
    say(f"results in {run_dir.relative_to(ROOT)}")
    log_file.close()
    return 0


def _identities(work: Path) -> dict:
    """Fresh ML-DSA identities for Alice and Bob, pinned to each other."""
    from qkd.services.identity import load_or_create_identity

    alice = load_or_create_identity(work / "alice_id")
    bob = load_or_create_identity(work / "bob_id")
    return {"alice_dir": work / "alice_id", "bob_dir": work / "bob_id",
            "alice_fp": alice.fingerprint, "bob_fp": bob.fingerprint}


if __name__ == "__main__":
    sys.exit(main())
