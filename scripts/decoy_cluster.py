#!/usr/bin/env python3
"""
Phase 5b live composable-finite-key decoy experiments, fanned across CPU cores.

    python scripts/decoy_cluster.py --experiments d5_decoy_honest d5_decoy_pns d5_required_n \
        --repeats 15 --jobs $(nproc)
    python scripts/decoy_cluster.py --reduce experiments/results/d5_decoy_honest/<run id>
    python scripts/decoy_cluster.py --emit-slurm experiments/slurm/d5.slurm --repeats 15

Three experiments, all on the composable decoy_finite_key gate (core/decoy_finitekey.py), with
Cascade reconciliation, hybrid auth, and the analytic measurement backend (so a 1e7-1e8-pulse run
is tractable):

  d5_decoy_honest  honest decoy transfers at the per-point required N (GYS and KTH, 0/25/50 km).
                   Records whether a 256-bit key was produced and the file arrived, the measured
                   composable ell and Y1_L, and the per-intensity gains.
  d5_decoy_pns     a photon-number-splitting Eve at the same N and points. The composable gate
                   must abort (no file), with Y1_L driven to ~0; Eve's known-key fraction recorded.
  d5_required_n    at GYS 25 km, N swept 0.25x..4x of the required N; the fraction of runs that
                   yield a 256-bit key should cross 1/2 around the computed required N, validating
                   the Phase 5a calculator against live runs.
  d6_wcp_pns       the insecure no-decoy baseline under the same PNS attack (SOURCE=wcp, GYS 0/25
                   km). The single-photon (Tomamichel) finite-key gate ignores the per-intensity
                   gains, so the attacked run COMPLETES and delivers the file at the honest QBER
                   floor while Eve holds a large share of the sifted key (eve_known_fraction) --
                   the measured counterpart to the decoy defence. N is sized so the honest gate
                   clears 256 bits with wide margin (so every attacked run delivers).
  d7_pns_partial   GYS 25 km decoy under a PARTIAL PNS attack, strength g swept 0..1 (Eve attacks a
                   fraction g of the pulses, passes the rest through honestly). Shows the composable
                   bound degrading smoothly -- Y1_L and ell fall, the key rate drops 1 -> 0 at some
                   g*, Eve's known fraction rises -- while the QBER stays at the honest floor. Run
                   at 2x the required N so g=0 is a solidly secure key rate and g* is well defined.

The required N per point is read from the Phase 5a calculator (core/decoy_finitekey.required_N),
never hardcoded; the decoy intensities/probs are optimised per point for the symmetric-basis
(q_x = 0.5) protocol the runners actually use, so the live gate and the calculator are consistent.

Runs are independent, so the grid (presets x distances x attack x repeats, plus the N sweep ~ a
few hundred tasks) fans across a process pool sized to the core count; each task is one
Alice/Bob(/Eve) run writing its row under experiments/results/<exp>/<run id>/. A reduce step
collects rows into summary.csv (Wilson intervals) and writes the required-N figure. --emit-slurm
writes an equivalent CPU-partition array script (one task per array index) for a cluster.

Pure-CPU NumPy; modest memory per honest task (arrays of the clicked pulses) and O(N) memory for a
PNS task (Alice hands Eve all pre-loss pulses), so size --jobs to RAM for the long-distance points.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
from scipy.optimize import minimize

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from qkd.core import decoy_finitekey as dfk  # noqa: E402
from qkd.core.channel_model import preset  # noqa: E402
from benchmark import (  # noqa: E402
    LineReader, classify, free_port, parse_events, runner, summarize_events, wilson, _identities, _sha256,
)

RESULTS = ROOT / "experiments" / "results"
PRESETS = ("GYS", "KTH")
DISTANCES = (0.0, 25.0, 50.0)
EPS_SEC, EPS_COR, Q_X = 1e-10, 1e-15, 0.5
SWEEP_FACTORS = (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0)
SWEEP_PRESET, SWEEP_DISTANCE = "GYS", 25.0
# d6 no-decoy baseline: a wcp laser at the signal intensity only (probs ignored; source_mix uses
# intensities[0]). N per point is sized so the honest single-photon finite-key gate clears 256 bits
# with ~14x/26x margin (validated: honest ell ~3600 at 0 km, ~6630 at 25 km), so every attacked run
# delivers. It is NOT the decoy calculator's required N -- wcp runs the Tomamichel gate, not decoy.
D6_WCP_DISTANCES = (0.0, 25.0)
D6_WCP_N = {0.0: 2_000_000, 25.0: 10_000_000}
D6_WCP_INTENSITIES = (0.48, 0.1, 0.0)
D6_WCP_PROBS = (0.7, 0.2, 0.1)
# d7 partial-PNS sweep: GYS 25 km, decoy source, composable gate, Eve PNS-attacks a fraction g of
# the pulses (g in D7_STRENGTHS) and passes the rest through honestly, so the decoy bound degrades
# smoothly. Run at D7_N_MULTIPLIER x the required N so the honest end (g=0) is a solidly secure
# key_rate ~ 1 and the secure->broken transition (g*) is well defined (at exactly 1x required N the
# honest key_rate is ~0.5 by construction, so g* would sit at 0 and be uninformative).
D7_STRENGTHS = tuple(round(0.1 * i, 1) for i in range(11))  # 0.0, 0.1, ..., 1.0
D7_N_MULTIPLIER = 2.0
PROCESS_TIMEOUT = 1800.0
PALETTE = {"GYS": "#2a78d6", "KTH": "#eb6834", "mark": "#1baf7a"}


# ── per-point decoy setup: optimise intensities/probs at q_x = 0.5, size N ────

def optimise_setup(params, n_ref: float = 3e8) -> tuple[tuple, tuple]:
    """Intensities (mu1, mu2, 0) and probs maximising the composable ell/N at q_x = 0.5."""
    def neg(x):
        mu1, mu2, p1, p2 = x
        if not (0 < mu2 < mu1 <= 0.9 and p1 > 0.02 and p2 > 0.02 and p1 + p2 < 0.98):
            return 1.0
        try:
            counts = dfk.expected_counts(params, n_ref, (mu1, mu2, 0.0), (p1, p2, 1 - p1 - p2), Q_X)
            return -dfk.secure_key_length(counts, EPS_SEC, EPS_COR).raw / n_ref
        except (ValueError, ZeroDivisionError):
            return 1.0
    best = None
    for x0 in [(0.5, 0.1, 0.5, 0.35), (0.45, 0.12, 0.4, 0.4), (0.55, 0.15, 0.4, 0.4)]:
        res = minimize(neg, x0, method="Nelder-Mead",
                       options={"xatol": 1e-6, "fatol": 1e-12, "maxiter": 6000})
        if best is None or res.fun < best.fun:
            best = res
    mu1, mu2, p1, p2 = (float(v) for v in best.x)
    p1, p2 = round(p1, 6), round(p2, 6)
    return (round(mu1, 6), round(mu2, 6), 0.0), (p1, p2, 1.0 - p1 - p2)  # p3 exact so probs sum to 1


def plan_point(preset_name: str, length_km: float) -> dict:
    """The decoy setup and required N for one (preset, distance), from the Phase 5a calculator."""
    params = preset(preset_name, length_km)
    intensities, probs = optimise_setup(params)
    req = dfk.required_N(params, [length_km], intensities, probs, EPS_SEC, EPS_COR,
                         ell_min=256, q_x=Q_X)[0]
    return {"preset": preset_name, "length_km": length_km, "intensities": intensities,
            "probs": probs, "required_N": req.n_pulses, "feasible": req.feasible,
            "expected_ell": req.ell_at_n}


# ── one run (a pool task) ────────────────────────────────────────────────────

def _env_for(task: dict) -> dict:
    mu1, mu2, mu3 = task["intensities"]
    p1, p2, p3 = task["probs"]
    env = dict(os.environ)
    env.update({
        "QKD_SOURCE": task.get("source", "decoy"),
        "QKD_DECOY_INTENSITIES": f"{mu1},{mu2},{mu3}",
        "QKD_DECOY_PROBS": f"{p1},{p2},{p3}",
        "QKD_CHANNEL_PRESET": task["preset"],
        "QKD_CHANNEL_LENGTH_KM": str(task["length_km"]),
        "QKD_RECONCILIATION": "cascade",
        "QKD_MEASUREMENT": "analytic",
        "QKD_DECOY_GATE": "composable",
        "QKD_NUM_QUBITS": str(int(task["n_pulses"])),
        "QKD_ENFORCE_FINITE_KEY": "1",
        "QKD_FINAL_KEY_BITS": "256",
        "QKD_EPS_SEC": repr(EPS_SEC),
        "QKD_EPS_COR": repr(EPS_COR),
    })
    return env


def run_task(task: dict) -> dict:
    """Launch one Alice/Bob(/Eve) run for a task and return a flat result row."""
    work = Path(task["work"])
    work.mkdir(parents=True, exist_ok=True)
    payload = work / "payload.bin"
    if not payload.exists():
        payload.write_bytes(os.urandom(task["payload_bytes"]))
    payload_sha = _sha256(payload)
    out_dir = work / "received"
    ids = _identities(work)
    env = _env_for(task)
    pns = task["attack"] == "pns"
    auth_alice = ["--auth", "hybrid", "--identity", str(ids["alice_dir"]), "--peer-fingerprint", ids["bob_fp"]]
    auth_bob = ["--auth", "hybrid", "--identity", str(ids["bob_dir"]), "--peer-fingerprint", ids["alice_fp"]]

    procs: list[subprocess.Popen] = []
    eve_reader = None
    try:
        bob = subprocess.Popen(
            runner("bob", "--port", "0", "--events", "json", "--output-dir", str(out_dir), *auth_bob),
            env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        procs.append(bob)
        bob_reader = LineReader(bob)
        bob_port = bob_reader.port.get(timeout=300)

        alice_port, alice_eve = bob_port, []
        if pns:
            alice_port = free_port()
            alice_eve = ["--eve-mode"]
            eve = subprocess.Popen(
                runner("eve", "--attack", "pns", "--events", "json",
                       "--pns-strength", str(task.get("pns_strength", 1.0)),
                       "--bob-port", str(bob_port), "--listen-port", str(alice_port)),
                env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(eve)
            eve_reader = LineReader(eve)

        wall_start = time.perf_counter()
        alice = subprocess.run(
            runner("alice", str(payload), "--host", "127.0.0.1", "--port", str(alice_port),
                   "--events", "json", *alice_eve, *auth_alice),
            env=env, capture_output=True, text=True, timeout=PROCESS_TIMEOUT)
        wall_s = time.perf_counter() - wall_start
        for proc in procs:
            proc.wait(timeout=PROCESS_TIMEOUT)
        bob_reader.join()
        if eve_reader is not None:
            eve_reader.join()
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()

    a = summarize_events(parse_events(alice.stdout.splitlines()))
    b = summarize_events(parse_events(bob_reader.lines))
    eve_m = summarize_events(parse_events(eve_reader.lines))["metrics"] if eve_reader else {}
    received = out_dir / f"received_{payload.name}"
    intact = received.exists() and _sha256(received) == payload_sha
    if received.exists():
        received.unlink()

    def metric(name):
        return a["metrics"].get(name, b["metrics"].get(name))

    key_produced = int(a["outcome"] == "completed" and b["outcome"] == "completed" and intact)
    # The runner maps a decoy-gate abort to the aborted_qber outcome, so relabel it from the
    # error text: a composable/asymptotic decoy-bound abort is the decoy gate, not the QBER check.
    stopped = classify(a, b, intact)
    errtext = f"{a['error'] or ''} {b['error'] or ''}".lower()
    if not key_produced and ("composable bound" in errtext or "asymptotic estimate" in errtext):
        stopped = "decoy_gate"
    return {
        "exp": task["exp"], "preset": task["preset"], "length_km": task["length_km"],
        "attack": task["attack"], "repeat": task["repeat"], "n_pulses": int(task["n_pulses"]),
        "required_N": int(task["required_N"]), "n_over_required": round(task["n_pulses"] / task["required_N"], 4),
        "source": task.get("source", "decoy"), "pns_strength": task.get("pns_strength", 1.0),
        "stopped_at": stopped, "key_produced": key_produced, "file_delivered": int(intact),
        "secure_key_bits": metric("secure_key_bits"),
        "decoy_comp_Y1_lower": metric("decoy_comp_Y1_lower"),
        "decoy_comp_phase_error": metric("decoy_comp_phase_error"),
        "decoy_Y1_lower": metric("decoy_Y1_lower"),        # the asymptotic bound, for comparison
        "decoy_gain_signal": metric("decoy_gain_signal"), "decoy_gain_decoy": metric("decoy_gain_decoy"),
        "qber": metric("qber"), "detected": metric("detected"), "raw_qubits": metric("raw_qubits"),
        "eve_known_fraction": eve_m.get("eve_known_fraction"),
        "alice_outcome": a["outcome"], "bob_outcome": b["outcome"],
        "alice_error": a["error"], "bob_error": b["error"], "wall_s": round(wall_s, 3),
    }


# ── building the task list ───────────────────────────────────────────────────

def build_tasks(experiments: list[str], repeats: int, payload_bytes: int, work_root: Path,
                plans: dict, distances=DISTANCES) -> list[dict]:
    tasks: list[dict] = []

    def add(exp, preset_name, length, attack, n_pulses, required_N, intensities, probs, reps,
            source="decoy", strength=1.0):
        for r in range(reps):
            tasks.append({
                "exp": exp, "preset": preset_name, "length_km": length, "attack": attack,
                "n_pulses": n_pulses, "required_N": required_N, "intensities": intensities,
                "probs": probs, "repeat": r, "payload_bytes": payload_bytes, "source": source,
                "pns_strength": strength,
                "work": str(work_root / f"{exp}_{preset_name}_{length:g}_{attack}_{n_pulses}_g{strength:g}_{r}"),
            })

    for preset_name in PRESETS:
        for length in distances:
            plan = plans[(preset_name, length)]
            if not plan["feasible"]:
                continue
            n = plan["required_N"]
            if "d5_decoy_honest" in experiments:
                add("d5_decoy_honest", preset_name, length, "none", n, n,
                    plan["intensities"], plan["probs"], repeats)
            if "d5_decoy_pns" in experiments:
                add("d5_decoy_pns", preset_name, length, "pns", n, n,
                    plan["intensities"], plan["probs"], repeats)

    if "d5_required_n" in experiments:
        plan = plans[(SWEEP_PRESET, SWEEP_DISTANCE)]
        for factor in SWEEP_FACTORS:
            n = max(1000, int(plan["required_N"] * factor))
            add("d5_required_n", SWEEP_PRESET, SWEEP_DISTANCE, "none", n, plan["required_N"],
                plan["intensities"], plan["probs"], 10)

    if "d6_wcp_pns" in experiments:
        for length in D6_WCP_DISTANCES:
            n = D6_WCP_N[length]
            add("d6_wcp_pns", "GYS", length, "pns", n, n,
                D6_WCP_INTENSITIES, D6_WCP_PROBS, repeats, source="wcp")

    if "d7_pns_partial" in experiments:
        plan = plans[(SWEEP_PRESET, SWEEP_DISTANCE)]      # GYS 25 km
        n = int(plan["required_N"] * D7_N_MULTIPLIER)
        for g in D7_STRENGTHS:
            add("d7_pns_partial", SWEEP_PRESET, SWEEP_DISTANCE, "pns", n, plan["required_N"],
                plan["intensities"], plan["probs"], repeats, strength=g)
    return tasks


# ── reduce ───────────────────────────────────────────────────────────────────

def _f(row, key):
    v = row.get(key)
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def reduce_rows(rows: list[dict]) -> list[dict]:
    """Aggregate rows by (exp, preset, length, attack, n_pulses) into summary rows."""
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        s = _f(row, "pns_strength")
        key = (row["exp"], row["preset"], float(row["length_km"]), row["attack"], int(row["n_pulses"]), s)
        groups.setdefault(key, []).append(row)

    def med(vals):
        vals = [v for v in vals if v is not None]
        return round(float(np.median(vals)), 6) if vals else None

    def mn(vals):
        vals = [v for v in vals if v is not None]
        return round(float(min(vals)), 6) if vals else None

    def mx(vals):
        vals = [v for v in vals if v is not None]
        return round(float(max(vals)), 6) if vals else None

    out = []
    for (exp, preset_name, length, attack, n_pulses, strength), g in sorted(
            groups.items(), key=lambda kv: tuple(map(str, kv[0]))):
        n = len(g)
        successes = sum(int(_f(r, "key_produced") or 0) for r in g)
        delivered = sum(int(_f(r, "file_delivered") or 0) for r in g)
        lo, hi = wilson(successes, n)
        req = int(g[0]["required_N"])
        out.append({
            "exp": exp, "preset": preset_name, "length_km": length, "attack": attack,
            "pns_strength": strength if strength is not None else "",
            "n_pulses": n_pulses, "required_N": req, "n_over_required": round(n_pulses / req, 4),
            "runs": n, "key_produced": successes, "key_rate": round(successes / n, 4),
            "key_rate_wilson_lo": round(lo, 4), "key_rate_wilson_hi": round(hi, 4),
            "file_delivered": delivered, "file_delivered_rate": round(delivered / n, 4),
            "ell_median": med([_f(r, "secure_key_bits") for r in g]),
            "comp_Y1_lower_median": med([_f(r, "decoy_comp_Y1_lower") for r in g]),
            "asym_Y1_lower_median": med([_f(r, "decoy_Y1_lower") for r in g]),
            "gain_signal_median": med([_f(r, "decoy_gain_signal") for r in g]),
            "gain_decoy_median": med([_f(r, "decoy_gain_decoy") for r in g]),
            "qber_median": med([_f(r, "qber") for r in g]),
            "eve_known_fraction_median": med([_f(r, "eve_known_fraction") for r in g]),
            "eve_known_fraction_min": mn([_f(r, "eve_known_fraction") for r in g]),
            "eve_known_fraction_max": mx([_f(r, "eve_known_fraction") for r in g]),
            "stopped_at_mode": max(set(r["stopped_at"] for r in g), key=lambda s: sum(x["stopped_at"] == s for x in g)),
            "wall_s_median": med([_f(r, "wall_s") for r in g]),
        })
    return out


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys())
    extra = [k for r in rows for k in r if k not in fields]
    fields += list(dict.fromkeys(extra))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def plot_required_n(summary: list[dict], out_pdf: Path) -> None:
    sweep = [r for r in summary if r["exp"] == "d5_required_n"]
    if not sweep:
        return
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sweep.sort(key=lambda r: float(r["n_over_required"]))
    x = [float(r["n_over_required"]) for r in sweep]
    y = [float(r["key_rate"]) for r in sweep]
    lo = [float(r["key_rate_wilson_lo"]) for r in sweep]
    hi = [float(r["key_rate_wilson_hi"]) for r in sweep]
    req = int(sweep[0]["required_N"])
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.fill_between(x, lo, hi, color=PALETTE["GYS"], alpha=0.18, label="Wilson 95%")
    ax.plot(x, y, "o-", color=PALETTE["GYS"], lw=1.8, label="256-bit key rate")
    ax.axvline(1.0, color=PALETTE["mark"], ls="--", lw=1.2, label=f"computed required N = {req:,}")
    ax.axhline(0.5, color="#8a8985", ls=":", lw=0.8)
    ax.set_xscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels([(f"{v:g}x") for v in x])
    ax.minorticks_off()
    ax.set_xlabel("Block size N / required N (GYS, 25 km)")
    ax.set_ylabel("Fraction of runs yielding a 256-bit key")
    ax.set_ylim(-0.03, 1.03)
    ax.legend(loc="lower right", fontsize=8, frameon=False)
    ax.grid(True, color="#e4e3df", lw=0.6)
    fig.tight_layout()
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_pdf.with_suffix(".png"), dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_pns_partial(summary: list[dict], out_pdf: Path) -> Optional[float]:
    """Y1_L and the 256-bit key rate vs the PNS strength g (GYS 25 km). Returns g* or None."""
    rows = [r for r in summary if r["exp"] == "d7_pns_partial"]
    if not rows:
        return None
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rows.sort(key=lambda r: float(r["pns_strength"]))
    g = [float(r["pns_strength"]) for r in rows]
    y1 = [float(r["comp_Y1_lower_median"]) for r in rows]
    kr = [float(r["key_rate"]) for r in rows]
    gstar = next((gg for gg, k in zip(g, kr) if k < 1.0), None)  # first g with any abort

    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.plot(g, y1, "o-", color=PALETTE["GYS"], lw=1.8, label=r"composable $Y_1^L$ (median)")
    ax.set_xlabel("PNS attack strength $g$")
    ax.set_ylabel(r"Single-photon yield bound $Y_1^L$", color=PALETTE["GYS"])
    ax.tick_params(axis="y", labelcolor=PALETTE["GYS"])
    ax.set_ylim(bottom=0.0)
    ax2 = ax.twinx()
    ax2.plot(g, kr, "s--", color=PALETTE["KTH"], lw=1.6, label="256-bit key rate")
    ax2.set_ylabel("Fraction of runs yielding a 256-bit key", color=PALETTE["KTH"])
    ax2.tick_params(axis="y", labelcolor=PALETTE["KTH"])
    ax2.set_ylim(-0.03, 1.03)
    if gstar is not None:
        ax.axvline(gstar, color=PALETTE["mark"], ls=":", lw=1.2)
        ax.text(gstar, max(y1) * 0.96, f" g* = {gstar:g}", color=PALETTE["mark"], fontsize=8,
                ha="left", va="top")
    lines = ax.get_lines()[:1] + ax2.get_lines()[:1]
    ax.legend(lines, [ln.get_label() for ln in lines], loc="upper right", fontsize=8,
              frameon=True, framealpha=1)
    ax.grid(True, color="#e4e3df", lw=0.6)
    fig.tight_layout()
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_pdf.with_suffix(".png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    return gstar


# ── slurm ────────────────────────────────────────────────────────────────────

SLURM_TEMPLATE = """#!/bin/bash
#SBATCH --job-name=d5_decoy
#SBATCH --partition=cpu
#SBATCH --array=0-{last}
#SBATCH --cpus-per-task=1
#SBATCH --mem={mem_mb}M
#SBATCH --time=01:00:00
#SBATCH --output=experiments/results/slurm/%A_%a.out
#
# One array index = one Alice/Bob(/Eve) run. CPU partition, no GPU. Each index re-derives its
# task from the same plan (seeded), runs it, and appends a row to the run directory. A final
# reduce (run once, after the array finishes) collects the rows:
#   python scripts/decoy_cluster.py --reduce experiments/results/<exp>/<run id>
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
source .venv/bin/activate
python scripts/decoy_cluster.py --slurm-task "$SLURM_ARRAY_TASK_ID" \\
    --experiments {experiments} --repeats {repeats} --run-dir "{run_dir}"
"""


def write_slurm(path: Path, n_tasks: int, experiments: list[str], repeats: int,
                run_dir: str, mem_mb: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SLURM_TEMPLATE.format(
        last=n_tasks - 1, mem_mb=mem_mb, experiments=" ".join(experiments),
        repeats=repeats, run_dir=run_dir))


# ── driver ───────────────────────────────────────────────────────────────────

def git(*args: str) -> Optional[str]:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_id(started: datetime) -> str:
    commit = git("rev-parse", "HEAD") or "nocommit"
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    return f"{started.strftime('%Y%m%dT%H%MZ')}_{(commit or 'x')[:7]}" + ("-dirty" if dirty else "")


def build_plans() -> dict:
    print("Planning per-point decoy setups and required N (Phase 5a calculator)...")
    plans = {}
    for preset_name in PRESETS:
        for length in DISTANCES:
            plans[(preset_name, length)] = plan_point(preset_name, length)
            p = plans[(preset_name, length)]
            print(f"  {preset_name} {length:>4g} km: mu=({p['intensities'][0]},{p['intensities'][1]}) "
                  f"probs={p['probs']} required_N={p['required_N']:,} (expected ell {p['expected_ell']})")
    return plans


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Phase 5b composable decoy experiments.")
    parser.add_argument("--experiments", nargs="+",
                        default=["d5_decoy_honest", "d5_decoy_pns", "d5_required_n"])
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--payload-bytes", type=int, default=10000)
    parser.add_argument("--reduce", type=Path, help="Reduce an existing run directory to summary.csv + figure")
    parser.add_argument("--emit-slurm", type=Path, help="Write a Slurm array script and exit")
    parser.add_argument("--run-dir", type=Path, help="Shared run directory (Slurm array mode)")
    parser.add_argument("--slurm-task", type=int, help="Array index to run (Slurm array mode)")
    parser.add_argument("--limit", type=int, help="Run only the first N tasks (smoke test)")
    parser.add_argument("--distances", type=float, nargs="+", default=list(DISTANCES),
                        help="Fibre lengths for the honest/pns points (the sweep is fixed at 25 km)")
    args = parser.parse_args(argv)

    if args.reduce:
        rows = read_csv(args.reduce / "runs.csv")
        summary = reduce_rows(rows)
        write_csv(args.reduce / "summary.csv", summary)
        plot_required_n(summary, ROOT / "experiments" / "figures" / "decoy_required_n.pdf")
        gstar = plot_pns_partial(summary, ROOT / "experiments" / "figures" / "decoy_pns_partial.pdf")
        if gstar is not None:
            print(f"d7 partial-PNS figure written; g* (gate begins to abort) = {gstar:g}")
        print(f"summary: {args.reduce / 'summary.csv'}  ({len(summary)} rows)")
        return 0

    plans = build_plans()
    tasks = build_tasks(args.experiments, args.repeats, args.payload_bytes,
                        ROOT / "experiments" / "results" / "_work", plans, tuple(args.distances))
    if args.emit_slurm:
        mem_mb = 12000
        write_slurm(args.emit_slurm, len(tasks), args.experiments, args.repeats,
                    "experiments/results", mem_mb)   # relative to $SLURM_SUBMIT_DIR
        print(f"Slurm array script ({len(tasks)} tasks): {args.emit_slurm}")
        return 0

    if args.slurm_task is not None:
        task = tasks[args.slurm_task]
        row = run_task({**task, "work": str((args.run_dir or Path(".")) / "_work" / f"task{args.slurm_task}")})
        append_row(args.run_dir / task["exp"] / "runs.csv", row)
        return 0

    if args.limit:
        tasks = tasks[:args.limit]
    started = datetime.now(timezone.utc)
    run = run_id(started)
    print(f"Running {len(tasks)} tasks across {args.jobs} workers (run {run})...")
    by_exp: dict[str, list[dict]] = {}
    done = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_task, t): t for t in tasks}
        for fut in as_completed(futures):
            row = fut.result()
            by_exp.setdefault(row["exp"], []).append(row)
            done += 1
            print(f"  [{done}/{len(tasks)}] {row['exp']} {row['preset']} {row['length_km']:g}km "
                  f"{row['attack']} N={row['n_pulses']:,} -> key={row['key_produced']} "
                  f"ell={row['secure_key_bits']} stop={row['stopped_at']} ({row['wall_s']}s)")

    for exp, rows in by_exp.items():
        run_dir = RESULTS / exp / run
        write_csv(run_dir / "runs.csv", rows)
        summary = reduce_rows(rows)
        write_csv(run_dir / "summary.csv", summary)
        print(f"[{exp}] {run_dir}")
    allrows = [r for rows in by_exp.values() for r in rows]
    if any(r["exp"] == "d5_required_n" for r in allrows):
        plot_required_n(reduce_rows(allrows), ROOT / "experiments" / "figures" / "decoy_required_n.pdf")
        print(f"figure: {ROOT / 'experiments' / 'figures' / 'decoy_required_n.pdf'}")
    if any(r["exp"] == "d7_pns_partial" for r in allrows):
        gstar = plot_pns_partial(reduce_rows(allrows), ROOT / "experiments" / "figures" / "decoy_pns_partial.pdf")
        print(f"figure: {ROOT / 'experiments' / 'figures' / 'decoy_pns_partial.pdf'}  (g* = {gstar})")
    return 0


def append_row(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)


if __name__ == "__main__":
    sys.exit(main())
