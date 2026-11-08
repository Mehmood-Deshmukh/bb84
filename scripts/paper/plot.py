"""
Figures for the paper-eval v2 report (PDF vector + PNG), from the E1/E3/E5/E6 CSVs in
experiments/results/paper-v2/. Skips any figure whose inputs are missing.
Usage: python scripts/paper/plot.py
"""

from __future__ import annotations

import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import common
from common import RESULTS


def _save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(RESULTS / f"{name}.{ext}", bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"wrote {name}.pdf/.png", flush=True)


def _read(p):
    with open(p) as f:
        return list(csv.DictReader(f))


def fig_e1():
    p = RESULTS / "e1_summary.csv"
    if not p.exists():
        return
    rows = _read(p)
    fs = sorted({float(r["f"]) for r in rows})
    ns = sorted({int(r["n"]) for r in rows})
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    colors = ["#1f4e79", "#c00000", "#2e7d32", "#9c27b0"]
    for i, f in enumerate(fs):
        rs = sorted([r for r in rows if float(r["f"]) == f], key=lambda r: int(r["n"]))
        x = [int(r["n"]) for r in rs]
        rate = [float(r["thr_rate"]) for r in rs]
        lo = [float(r["thr_rate"]) - float(r["thr_wilson_lo"]) for r in rs]
        hi = [float(r["thr_wilson_hi"]) - float(r["thr_rate"]) for r in rs]
        model = [float(r["thr_model"]) for r in rs]
        c = colors[i % len(colors)]
        ax.errorbar(x, rate, yerr=[lo, hi], fmt="o", capsize=3, color=c, label=f"f={f} measured")
        ax.plot(x, model, "--", color=c, alpha=0.7, label=f"f={f} model")
    ax.set_xscale("log", base=2); ax.set_xticks(ns); ax.set_xticklabels(ns)
    ax.set_xlabel("raw qubits N"); ax.set_ylabel("QBER-threshold detection rate")
    ax.set_ylim(-0.02, 1.05); ax.grid(True, alpha=0.3); ax.legend(fontsize=7, ncol=2)
    ax.set_title("E1: threshold detection vs N and f (95% Wilson; dashed = binomial model)")
    _save(fig, "e1_detection")


def fig_e2_stopping_check():
    p = RESULTS / "e2_summary.csv"
    if not p.exists():
        return
    rows = _read(p)
    layers = [("cnt_threshold", "QBER threshold", "#c00000"),
              ("cnt_finite_key", "finite-key bound", "#ed7d31"),
              ("cnt_tag", "confirmation tag", "#1f4e79"),
              ("cnt_gcm", "GCM tag", "#2e7d32")]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, mode in zip(axes, ("hybrid", "none")):
        rs = sorted([r for r in rows if r["mode"] == mode], key=lambda r: float(r["f"]))
        fs = [float(r["f"]) for r in rs]
        x = list(range(len(fs)))
        bottom = [0.0] * len(rs)
        for key, label, color in layers:
            vals = [int(r.get(key, 0) or 0) for r in rs]
            if sum(vals) == 0:
                continue
            ax.bar(x, vals, bottom=bottom, label=label, color=color)
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax.set_xticks(x); ax.set_xticklabels([f"{f:g}" for f in fs], rotation=45, fontsize=7)
        ax.set_title(f"{mode}"); ax.set_xlabel("Eve fraction f")
        ax.grid(True, axis="y", alpha=0.3)
    axes[0].set_ylabel("runs (of 30) stopped by each check")
    axes[1].legend(fontsize=8, loc="upper right")
    fig.suptitle("E2: which check stops a partial-Eve run, by mode and f (N=8192)")
    _save(fig, "e2_stopping_check")


def fig_e3_keylen():
    p = RESULTS / "e3_keylen_vs_qber.csv"
    if not p.exists():
        return
    rows = _read(p)
    fig, ax = plt.subplots(figsize=(6, 4))
    for N, c in (("8192", "#1f4e79"), ("4096", "#c00000")):
        rs = [r for r in rows if r["N"] == N]
        ax.plot([float(r["qber"]) for r in rs], [float(r["secure_bits"]) for r in rs], "o-", color=c, label=f"N={N}")
    ax.axhline(256, color="black", ls=":", label="l = 256")
    ax.set_xlabel("sample QBER Q"); ax.set_ylabel("secure key length l (bits)")
    ax.grid(True, alpha=0.3); ax.legend(); ax.set_title("E3: finite-key length vs QBER")
    _save(fig, "e3_keylen_vs_qber")


def fig_e5():
    p = RESULTS / "e5_summary_sizes.csv"
    if not p.exists():
        return
    rows = sorted(_read(p), key=lambda r: int(r["payload_bytes"]))
    stages = ["authentication", "quantum_transmission", "sifting", "qber_estimation",
              "privacy_amplification", "key_confirmation", "file_transfer"]
    def lab(b):
        b = int(b)
        return f"{b//1024} KB" if b < 1024 * 1024 else f"{b//1024//1024} MB"
    labels = [lab(r["payload_bytes"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4)); bottom = [0.0] * len(rows)
    for st in stages:
        vals = [float(r.get(f"bob_{st}_median", 0) or 0) for r in rows]
        ax.bar(labels, vals, bottom=bottom, label=st); bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_ylabel("seconds (Bob timeline, median)"); ax.set_xlabel("payload size")
    ax.set_title("E5: stage time by file size (hybrid, N=8192)")
    ax.legend(fontsize=7, ncol=2); ax.grid(True, axis="y", alpha=0.3)
    _save(fig, "e5_stage_bars")


def fig_e6():
    p = RESULTS / "e6_message_bytes.csv"
    if not p.exists():
        return
    rows = _read(p)
    parts = ["hello_A", "hello_B", "finished_B", "finished_A"]
    fig, ax = plt.subplots(figsize=(6, 4)); bottom = [0.0] * len(rows)
    modes = [r["mode"] for r in rows]
    for part in parts:
        vals = [int(r[part]) for r in rows]
        ax.bar(modes, vals, bottom=bottom, label=part); bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_ylabel("framed bytes on the wire"); ax.set_xlabel("auth mode")
    ax.set_title("E6: handshake byte breakdown"); ax.legend(); ax.grid(True, axis="y", alpha=0.3)
    _save(fig, "e6_byte_breakdown")


def main():
    fig_e1(); fig_e2_stopping_check(); fig_e3_keylen(); fig_e5(); fig_e6()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
