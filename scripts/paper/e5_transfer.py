"""
E5 — transfer time over the real CLI (qkd-bob / qkd-alice, --events json, localhost TCP),
current protocol. 5 runs each, median + IQR, with a per-stage breakdown from both sides'
JSON event timestamps. All timings are measured with Nagle ENABLED (src sets no
TCP_NODELAY; see implementation.md / REPORT.md).

Sub-experiments:
  (a) N in {512,1024,2048,4096,8192} at 1 MB, hybrid. The finite-key gate is DISABLED
      (QKD_ENFORCE_FINITE_KEY=0) for this sweep ONLY, because at N<8192 the bound gives
      <256 bits and the run would abort before the file transfer; disabling it lets the
      whole pipeline run so time-vs-N is comparable. Recorded in the CSV (enforce=0).
  (b) file sizes {1 KB, 1 MB, 10 MB, 100 MB} at N=8192, hybrid, gate ON.
  (c) modes {none, sign, hybrid} at N=8192, 1 MB, gate ON.

Run on an idle machine (prints load averages).
"""

from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import common
from common import RESULTS, loadavg, median_iqr

ROOT = common.ROOT
BOB_STAGES = ["authentication", "quantum_transmission", "sifting", "qber_estimation",
              "privacy_amplification", "key_confirmation", "file_transfer"]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


def _runner(name, *args):
    return [sys.executable, "-m", f"qkd.runner.{name}", *args]


def _parse(stdout):
    events, outcome = [], "unknown"
    for line in stdout.splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.append(e)
        if e.get("type") == "result":
            outcome = e["payload"]["outcome"]
    return events, outcome


def _stage_durations(events):
    stamps = [(e.get("stage"), e["ts"]) for e in events if e.get("type") == "stage"]
    result_ts = next((e["ts"] for e in events if e.get("type") == "result"), None)
    out = {}
    for i, (name, ts) in enumerate(stamps):
        end = stamps[i + 1][1] if i + 1 < len(stamps) else result_ts
        if end is not None and name:
            out[name] = out.get(name, 0.0) + (end - ts)
    return out


def run_once(payload, mode, qubits, enforce, aid, bid, adir, bdir):
    port = free_port()
    env = {**os.environ, "QKD_NUM_QUBITS": str(qubits), "QKD_ENFORCE_FINITE_KEY": str(enforce),
           "QKD_KNOWN_PEERS_FILE": str(bdir / "known.json"), "QKD_TOFU": "1"}
    env_a = {**env, "QKD_KNOWN_PEERS_FILE": str(adir / "known.json")}
    bob = subprocess.Popen(_runner("bob", "--port", str(port), "--events", "json", "--auth", mode,
                                   "--identity", str(bid), "--output-dir", str(bdir / "received")),
                           cwd=str(bdir), env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    listening = False
    t0 = time.time()
    while time.time() - t0 < 60:
        line = bob.stdout.readline()
        if not line:
            break
        try:
            if json.loads(line).get("type") == "listening":
                listening = True; break
        except json.JSONDecodeError:
            continue
    if not listening:
        bob.kill(); raise RuntimeError("Bob never reported listening")
    start = time.perf_counter()
    alice = subprocess.run(_runner("alice", str(payload), "--host", "127.0.0.1", "--port", str(port),
                                   "--events", "json", "--auth", mode, "--identity", str(aid)),
                           cwd=str(adir), env=env_a, capture_output=True, text=True, timeout=600)
    wall = time.perf_counter() - start
    bob_rest = bob.stdout.read(); bob.wait(timeout=60)
    a_ev, a_out = _parse(alice.stdout); b_ev, b_out = _parse(bob_rest)
    a_dur, b_dur = _stage_durations(a_ev), _stage_durations(b_ev)
    row = {"mode": mode, "qubits": qubits, "enforce": enforce, "payload_bytes": payload.stat().st_size,
           "alice_wall_s": round(wall, 4), "alice_outcome": a_out, "bob_outcome": b_out}
    for s in BOB_STAGES:
        row[f"bob_{s}"] = round(b_dur.get(s, 0.0), 4)
        row[f"alice_{s}"] = round(a_dur.get(s, 0.0), 4)
    return row


def summarize(rows, key_fields):
    groups = {}
    for r in rows:
        groups.setdefault(tuple(r[f] for f in key_fields), []).append(r)
    out = []
    for k, rs in groups.items():
        med, q1, q3, iqr = median_iqr([r["alice_wall_s"] for r in rs])
        s = dict(zip(key_fields, k))
        s.update({"runs": len(rs), "wall_median": round(med, 4), "wall_iqr": round(iqr, 4),
                  "alice_outcome": rs[0]["alice_outcome"], "bob_outcome": rs[0]["bob_outcome"]})
        for st in BOB_STAGES:
            s[f"bob_{st}_median"] = round(median_iqr([r[f"bob_{st}"] for r in rs])[0], 4)
        out.append(s)
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    RUNS = 2 if args.smoke else 5
    print("=" * 60, flush=True)
    print(f"[E5] CLI transfer time. loadavg start: {loadavg()}", flush=True)

    base = Path(tempfile.mkdtemp(prefix="e5v2-"))
    adir, bdir = base / "alice", base / "bob"
    for d in (adir, bdir):
        (d / "id").mkdir(parents=True, exist_ok=True)
    aid, bid = adir / "id", bdir / "id"
    sizes = {"1KB": 1024, "1MB": 1024 * 1024, "10MB": 10 * 1024 * 1024, "100MB": 100 * 1024 * 1024}
    if args.smoke:
        sizes = {"1KB": 1024, "1MB": 1024 * 1024}
    payloads = {}
    for nm, nb in sizes.items():
        p = base / f"p_{nm}.bin"; p.write_bytes(os.urandom(nb)); payloads[nm] = p

    rows = []
    n_list = [512, 8192] if args.smoke else [512, 1024, 2048, 4096, 8192]
    # (a) N sweep at 1MB hybrid, gate OFF
    for q in n_list:
        for _ in range(RUNS):
            rows.append({"exp": "qubits", **run_once(payloads["1MB"], "hybrid", q, 0, aid, bid, adir, bdir)})
            print(f"[E5a] N={q} wall={rows[-1]['alice_wall_s']}s out={rows[-1]['alice_outcome']}", flush=True)
    # (b) sizes at N=8192 hybrid, gate ON
    for nm, p in payloads.items():
        for _ in range(RUNS):
            rows.append({"exp": "size", **run_once(p, "hybrid", 8192, 1, aid, bid, adir, bdir)})
            print(f"[E5b] size={nm} wall={rows[-1]['alice_wall_s']}s out={rows[-1]['alice_outcome']}", flush=True)
    # (c) modes at N=8192 1MB, gate ON
    for mode in (["hybrid"] if args.smoke else ["none", "sign", "hybrid"]):
        for _ in range(RUNS):
            rows.append({"exp": "mode", **run_once(payloads["1MB"], mode, 8192, 1, aid, bid, adir, bdir)})
            print(f"[E5c] mode={mode} wall={rows[-1]['alice_wall_s']}s out={rows[-1]['alice_outcome']}", flush=True)

    with open(RESULTS / "e5_transfer_time.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    with open(RESULTS / "e5_summary_qubits.csv", "w", newline="") as f:
        s = summarize([r for r in rows if r["exp"] == "qubits"], ["qubits"])
        w = csv.DictWriter(f, fieldnames=list(s[0])); w.writeheader(); w.writerows(s)
    with open(RESULTS / "e5_summary_sizes.csv", "w", newline="") as f:
        s = summarize([r for r in rows if r["exp"] == "size"], ["payload_bytes"])
        w = csv.DictWriter(f, fieldnames=list(s[0])); w.writeheader(); w.writerows(s)
    with open(RESULTS / "e5_summary_modes.csv", "w", newline="") as f:
        s = summarize([r for r in rows if r["exp"] == "mode"], ["mode"])
        w = csv.DictWriter(f, fieldnames=list(s[0])); w.writeheader(); w.writerows(s)
    print(f"[E5] loadavg end: {loadavg()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
