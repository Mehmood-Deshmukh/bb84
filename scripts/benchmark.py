#!/usr/bin/env python3
"""
Run an experiment defined in experiments/configs/*.yaml.

    python scripts/benchmark.py experiments/configs/e4_overhead.yaml [--repeats N]

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

Parameters:
  mode           none | sign | hybrid (default none)
  payload_bytes  size of the random file Alice sends (default 1000)
  eve_fraction   share of qubits Eve intercepts; 0 means no Eve (default 0)
  QKD_*          anything else is passed to all processes as an environment variable

Outputs (experiments/results/):
  <name>.csv            one row per run
  <name>_summary.csv    one row per grid point: median and IQR of every timing and byte
                        column, and the rate of each outcome with a Wilson 95% interval
  <name>.meta.json      git commit, package versions, CPU, Python, and the config

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
    "privacy_amplification",
    "key_confirmation",
    "file_transfer",
]
METRICS = [
    "raw_qubits", "sifted_length", "sample_size", "qber", "secure_key_bits", "key_bits",
    "handshake_ms", "auth_overhead_bytes", "qubit_bytes", "channel_bytes", "file_wire_bytes",
]
SPECIAL = {"mode", "payload_bytes", "eve_fraction"}
DEFAULTS = {"mode": "none", "payload_bytes": 1000, "eve_fraction": 0.0}
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


def run_once(point: dict, payload: Path, payload_sha: str, work: Path, ids: dict, base_env: dict) -> dict:
    """One Alice/Bob (and maybe Eve) run for a grid point. Returns a flat result row."""
    mode, fraction = point["mode"], float(point["eve_fraction"])
    env = {**base_env, **{k: str(v) for k, v in point.items() if k not in SPECIAL}}
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
        if fraction > 0:
            alice_port = free_port()
            procs.append(subprocess.Popen(
                runner("eve", "--bob-port", str(bob_port), "--listen-port", str(alice_port), "--fraction", str(fraction)),
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))

        wall_start = time.perf_counter()
        alice = subprocess.run(
            runner("alice", str(payload), "--host", "127.0.0.1", "--port", str(alice_port), "--events", "json", *auth_alice),
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
    row["sim_s"] = _round(((a["metrics"].get("sim_ms") or 0) + (b["metrics"].get("sim_ms") or 0)) / 1000)
    # Protocol time with the simulator's share removed. The simulation steps run one
    # after another (Alice prepares, then Bob measures), so subtracting both is valid.
    row["protocol_minus_sim_s"] = _round(a["protocol_s"] - row["sim_s"]) if a["protocol_s"] is not None else None
    row["end_to_end_minus_sim_s"] = _round(row["end_to_end_s"] - row["sim_s"]) if row["end_to_end_s"] is not None else None
    for stage in STAGES:
        row[f"alice_{stage}_s"] = _round(a["durations"].get(stage))
        row[f"bob_{stage}_s"] = _round(b["durations"].get(stage))
    return row


def _round(value: Optional[float], digits: int = 5) -> Optional[float]:
    return None if value is None else round(value, digits)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ── summary and metadata ────────────────────────────────────────────────────

NUMERIC_SUMMARY = ["wall_s", "protocol_s", "end_to_end_s", "end_to_end_minus_sim_s", "sim_s", "protocol_minus_sim_s", "bb84_classical_bytes", *METRICS,
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


def grid_points(cfg: dict) -> tuple[list[str], list[dict]]:
    """(grid parameter names, list of full parameter dicts) for every combination."""
    grid = cfg.get("grid", {})
    keys = list(grid)
    points = []
    for combo in itertools.product(*(grid[k] for k in keys)):
        points.append({**DEFAULTS, **cfg.get("fixed", {}), **dict(zip(keys, combo))})
    return keys, points


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    import yaml

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", type=Path)
    parser.add_argument("--repeats", type=int, help="Override the config's repeats (for a quick check)")
    parser.add_argument("--name", help="Override the output name")
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    repeats = args.repeats or cfg.get("repeats", 30)
    name = args.name or cfg["name"]
    keys, points = grid_points(cfg)
    RESULTS.mkdir(parents=True, exist_ok=True)
    meta = environment(cfg)
    meta["repeats"] = repeats
    base_env = {**os.environ, "PYTHONUNBUFFERED": "1"}

    rows: list[dict] = []
    total = len(points) * repeats
    with tempfile.TemporaryDirectory(prefix="qkd-bench-") as tmp:
        work = Path(tmp)
        ids = _identities(work)
        payloads: dict[int, tuple[Path, str]] = {}
        for point in points:
            size = int(point["payload_bytes"])
            if size not in payloads:
                path = work / f"payload_{size}.bin"
                path.write_bytes(os.urandom(size))
                payloads[size] = (path, _sha256(path))
            payload, sha = payloads[size]
            for repeat in range(repeats):
                row = {**{k: point[k] for k in keys}, "repeat": repeat,
                       **run_once(point, payload, sha, work, ids, base_env)}
                rows.append(row)
                label = ", ".join(f"{k}={point[k]}" for k in keys)
                print(f"[{len(rows)}/{total}] {label} #{repeat + 1}: {row['stopped_at']} "
                      f"protocol={row['protocol_s']}s", flush=True)

    meta["finished"] = datetime.now(timezone.utc).isoformat()
    write_csv(RESULTS / f"{name}.csv", rows)
    write_csv(RESULTS / f"{name}_summary.csv", summarize(rows, keys))
    (RESULTS / f"{name}.meta.json").write_text(json.dumps(meta, indent=2, default=str))
    print(f"Wrote experiments/results/{name}.csv, {name}_summary.csv, {name}.meta.json")
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
