#!/usr/bin/env python3
"""
Run a benchmark sweep from experiments/configs/*.yaml.

Each run starts real qkd.runner.bob / alice (and optionally eve) subprocesses on
free localhost ports and records the wall time of Alice's process.

    python scripts/benchmark.py experiments/configs/qubit_scaling.yaml

Results go to experiments/results/<name>.csv. Needs the `experiments` extra (pyyaml).
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments" / "results"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_payload(path: Path, size_mb: float) -> None:
    path.write_bytes(os.urandom(int(size_mb * 1024 * 1024)))


def runner(name: str, *args: str) -> list[str]:
    return [sys.executable, "-m", f"qkd.runner.{name}", *args]


def run_once(payload: Path, work: Path, env: dict[str, str], eve: bool, timeout: float = 300) -> dict:
    bob_port = free_port()
    alice_port = free_port() if eve else bob_port
    procs = [subprocess.Popen(runner("bob", "--port", str(bob_port), "--output-dir", str(work / "received")),
                              env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    time.sleep(1.5)  # let Bob bind
    if eve:
        procs.append(subprocess.Popen(runner("eve", "--bob-port", str(bob_port), "--listen-port", str(alice_port)),
                                      env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.5)

    start = time.perf_counter()
    alice = subprocess.run(runner("alice", str(payload), "--host", "127.0.0.1", "--port", str(alice_port)),
                           env=env, capture_output=True, text=True, timeout=timeout)
    elapsed = time.perf_counter() - start
    exits = [p.wait(timeout=timeout) for p in procs]
    return {"elapsed_s": round(elapsed, 4), "alice_exit": alice.returncode, "bob_exit": exits[0],
            "aborted": int(alice.returncode != 0 and exits[0] != 0)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    sweep = cfg["sweep"]
    base_env = {**os.environ, **{k: str(v) for k, v in cfg.get("env", {}).items()}}
    RESULTS.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS / f"{cfg['name']}.csv"

    rows = []
    with tempfile.TemporaryDirectory(prefix="qkd-bench-") as tmp:
        work = Path(tmp)
        for value in sweep["values"]:
            env = dict(base_env)
            payload_mb = cfg.get("payload_mb", 1)
            if sweep["param"] == "payload_mb":
                payload_mb = value
            else:
                env[sweep["param"]] = str(value)
            payload = work / "payload.bin"
            make_payload(payload, payload_mb)

            for repeat in range(cfg.get("repeats", 1)):
                result = run_once(payload, work, env, cfg.get("eve", False))
                rows.append({"param": sweep["param"], "value": value, "repeat": repeat, **result})
                print(f"{sweep['param']}={value} run {repeat + 1}: {result}", flush=True)

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
