#!/usr/bin/env python3
"""
Composable finite-key decoy-state rates vs distance (Phase 5a, numbers only).

    python scripts/decoy_finitekey.py [--max-km 150] [--step-km 2.5] [--n-ref 1e9]

For the GYS and KTH presets this sweeps the fibre length and, at each distance, optimises the
three-intensity decoy setup (signal mu1, decoy mu2, vacuum mu3 = 0; send-probabilities p1, p2, p3;
basis bias q_x) to maximise the Lim et al. composable finite-key length (core/decoy_finitekey.py,
PRA 89, 022307, 2014) at a fixed reference block size N = --n-ref. It overlays that composable
rate on the Phase 1 asymptotic envelopes from core/decoy.py (single-photon source, infinite decoy,
vacuum+weak), and tabulates the required N and ell to reach a 256-bit key at 0/25/50 km.

Two optimisation modes are used, both standard:
  * the rate-vs-distance curve optimises the setup per distance at the fixed block N = --n-ref
    (as in the paper's Fig 1), warm-started across distances for a smooth curve;
  * the required-N table fixes ONE setup per preset (optimised at 25 km, N = --n-ref) and finds
    the smallest N reaching 256 bits at each distance, so the table is monotonic and reports a
    single optimal intensity choice. The per-distance curve setups are written to the CSV too.

The composable bound uses eps_sec = 1e-10, eps_cor = 1e-15 (the single-photon path's values) and
f_EC = 1.16 (Lim et al.); the asymptotic overlays use decoy.py's defaults (f = 1.22). Outputs:
a CSV to experiments/results/decoy_finitekey/<run id>/ and a two-panel figure to
experiments/figures/decoy_finitekey_rate_vs_distance.pdf (+ .png). Pure numerics, no qiskit, no
processes. Needs the `experiments` extra (matplotlib). The run-id folder mirrors scripts/benchmark.py.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from scipy.optimize import minimize  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from qkd.core import decoy, decoy_finitekey as dfk  # noqa: E402
from qkd.core.channel_model import preset  # noqa: E402

PRESETS = ("GYS", "KTH")
EPS_SEC, EPS_COR = 1e-10, 1e-15
TABLE_DISTANCES = (0.0, 25.0, 50.0)

# Palette and styling borrowed from scripts/decoy_rates.py (validated categorical order).
CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
INK, INK_SECONDARY, INK_MUTED, GRID = "#0b0b0b", "#52514e", "#8a8985", "#e4e3df"

CURVE_COLUMNS = ["infinite_decoy", "vacuum_weak", "single_photon", "composable_finite"]
CURVE_LABELS = {
    "infinite_decoy": "Infinite decoy (asymptotic)",
    "vacuum_weak": "Vacuum+weak (asymptotic)",
    "single_photon": "Single-photon source (asymptotic)",
    "composable_finite": "Composable finite-key",
}
CURVE_COLORS = {"infinite_decoy": CATEGORICAL[2], "vacuum_weak": CATEGORICAL[3],
                "single_photon": CATEGORICAL[4], "composable_finite": CATEGORICAL[0]}
CURVE_STYLES = {"infinite_decoy": "--", "vacuum_weak": "--", "single_photon": "--",
                "composable_finite": "-"}

# Optimisation bounds for (mu1, mu2, q_x, p1, p2); mu3 = 0, p3 = 1 - p1 - p2.
BOUNDS = [(1e-3, 0.9), (1e-3, 0.9), (0.3, 0.97), (0.02, 0.95), (0.02, 0.95)]
STARTS = [(0.5, 0.1, 0.7, 0.5, 0.35), (0.6, 0.2, 0.85, 0.4, 0.4), (0.4, 0.08, 0.6, 0.5, 0.3)]


def style() -> None:
    plt.rcParams.update({
        "font.size": 9, "axes.edgecolor": INK_MUTED, "axes.labelcolor": INK,
        "axes.titlesize": 10, "axes.titleweight": "bold", "axes.titlecolor": INK,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
        "grid.color": GRID, "grid.linewidth": 0.6, "xtick.color": INK_SECONDARY,
        "ytick.color": INK_SECONDARY, "legend.frameon": False, "legend.fontsize": 8,
        "savefig.facecolor": "white", "figure.facecolor": "white", "pdf.fonttype": 42,
    })


def git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_id(started: datetime) -> str:
    commit = git("rev-parse", "HEAD") or "nocommit"
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    name = f"{started.strftime('%Y%m%dT%H%MZ')}_{commit[:7]}"
    return name + "-dirty" if dirty else name


# ── per-distance decoy-setup optimisation (maximise finite ell/N at N_ref) ────

def _clamp(x) -> list:
    return [min(max(v, lo), hi) for v, (lo, hi) in zip(x, BOUNDS)]


def _finite_rate(params, x, n_ref: float) -> float:
    """Composable ell/N for setup x = (mu1, mu2, q_x, p1, p2) at block size n_ref; -1 if invalid."""
    mu1, mu2, q_x, p1, p2 = x
    if not (mu2 < mu1 and p1 + p2 < 0.98):
        return -1.0
    try:
        counts = dfk.expected_counts(params, n_ref, (mu1, mu2, 0.0), (p1, p2, 1.0 - p1 - p2), q_x)
        return dfk.secure_key_length(counts, EPS_SEC, EPS_COR).raw / n_ref
    except (ValueError, ZeroDivisionError):
        return -1.0


def optimise_setup(params, n_ref: float, warm: Optional[list] = None) -> tuple[float, list]:
    """Best (rate_per_pulse, setup) maximising the composable ell/N at n_ref, warm-started."""
    starts = ([warm] + STARTS) if warm is not None else STARTS
    best_rate, best_x = -1.0, None
    for x0 in starts:
        res = minimize(lambda x: -_finite_rate(params, _clamp(x), n_ref), x0,
                       method="Nelder-Mead", options={"xatol": 1e-6, "fatol": 1e-12, "maxiter": 8000})
        if -res.fun > best_rate:
            best_rate, best_x = -res.fun, _clamp(res.x)
    return best_rate, best_x


# ── asymptotic overlays (decoy.py) ───────────────────────────────────────────

def asymptotic_rates(params, f_ec: float) -> dict[str, float]:
    out = {"single_photon": decoy.rate_single_photon(params, f=f_ec)}
    mu_inf = decoy.optimal_mu(params, "infinite_decoy", f=f_ec)
    out["infinite_decoy"] = decoy.rate_infinite_decoy(params, mu_inf, f=f_ec)
    mu_vw = decoy.optimal_mu(params, "vacuum_weak", nu=0.05, f=f_ec)
    out["vacuum_weak"] = decoy.rate_vacuum_weak(params, mu_vw, 0.05, f=f_ec)
    return out


# ── sweep + required-N table ─────────────────────────────────────────────────

def sweep(name: str, lengths: np.ndarray, n_ref: float) -> list[dict]:
    base = preset(name)
    rows, warm = [], None
    for length in lengths:
        params = base.at_length(float(length))
        rate, setup = optimise_setup(params, n_ref, warm)
        warm = setup
        asy = asymptotic_rates(params, decoy.F_EC_DEFAULT)
        mu1, mu2, q_x, p1, p2 = setup
        rows.append({
            "preset": name, "length_km": round(float(length), 4), "eta": params.eta,
            "composable_finite": max(0.0, rate), **asy,
            "mu1": mu1, "mu2": mu2, "q_x": q_x, "p1": p1, "p2": p2, "p3": 1.0 - p1 - p2,
        })
    return rows


def required_table(name: str, n_ref: float) -> tuple[list[dict], tuple]:
    """Optimise one setup at 25 km, then the smallest N for 256 bits at each table distance."""
    base = preset(name)
    _, setup = optimise_setup(base.at_length(25.0), n_ref)
    mu1, mu2, q_x, p1, p2 = setup
    intensities, probs = (mu1, mu2, 0.0), (p1, p2, 1.0 - p1 - p2)
    rows = []
    for req in dfk.required_N(base, list(TABLE_DISTANCES), intensities, probs,
                              EPS_SEC, EPS_COR, ell_min=256, q_x=q_x):
        rows.append({"preset": name, "length_km": req.length_km, "required_N": req.n_pulses,
                     "log2_N": (np.log2(req.n_pulses) if req.n_pulses else None),
                     "ell_at_N": req.ell_at_n, "feasible": req.feasible})
    return rows, (intensities, probs, q_x)


def max_distance(rows: list[dict], method: str) -> Optional[float]:
    positive = [r["length_km"] for r in rows if r[method] > 0.0]
    return max(positive) if positive else None


# ── output ───────────────────────────────────────────────────────────────────

def write_csv(path: Path, sweeps: dict[str, list[dict]], tables: dict[str, list[dict]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    curve_fields = ["preset", "length_km", "eta", *CURVE_COLUMNS,
                    "mu1", "mu2", "q_x", "p1", "p2", "p3"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=curve_fields)
        writer.writeheader()
        for name in PRESETS:
            for row in sweeps[name]:
                writer.writerow({k: row[k] for k in curve_fields})
    table_path = path.with_name("required_N.csv")
    with open(table_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["preset", "length_km", "required_N", "log2_N",
                                               "ell_at_N", "feasible"])
        writer.writeheader()
        for name in PRESETS:
            for row in tables[name]:
                writer.writerow(row)


def plot(sweeps: dict[str, list[dict]], out_pdf: Path, n_ref: float) -> dict:
    style()
    fig, axes = plt.subplots(1, len(PRESETS), figsize=(10, 4.2), sharey=True)
    if len(PRESETS) == 1:
        axes = [axes]
    maxima: dict = {}
    for ax, name in zip(axes, PRESETS):
        rows = sweeps[name]
        lengths = np.array([r["length_km"] for r in rows])
        maxima[name] = {}
        for method in CURVE_COLUMNS:
            rates = np.array([r[method] for r in rows])
            positive = rates > 0.0
            ax.plot(lengths[positive], rates[positive], color=CURVE_COLORS[method],
                    lw=1.8 if method == "composable_finite" else 1.4,
                    ls=CURVE_STYLES[method], label=CURVE_LABELS[method])
            maxima[name][method] = max_distance(rows, method)
        dmax = maxima[name]["composable_finite"]
        if dmax is not None:
            ax.axvline(dmax, color=CURVE_COLORS["composable_finite"], lw=0.7, ls=":", alpha=0.7)
        ax.set_yscale("log")
        ax.set_ylim(1e-8, 1e-1)
        ax.set_xlim(0, lengths.max())
        ax.set_title(name)
        ax.set_xlabel("Fibre length (km)")
    axes[0].set_ylabel("Secure key rate per pulse")
    axes[0].legend(loc="lower left")
    fig.suptitle(f"Decoy-state BB84: composable finite-key (N={n_ref:.0e}) vs asymptotic rate",
                 fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf)
    fig.savefig(out_pdf.with_suffix(".png"), dpi=150)
    plt.close(fig)
    return maxima


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Composable finite-key decoy rates vs distance.")
    parser.add_argument("--max-km", type=float, default=150.0, help="Longest fibre length (default: 150)")
    parser.add_argument("--step-km", type=float, default=2.5, help="Distance step (default: 2.5)")
    parser.add_argument("--n-ref", type=float, default=1e9, help="Reference block size N (default: 1e9)")
    args = parser.parse_args(argv)

    started = datetime.now(timezone.utc)
    lengths = np.arange(0.0, args.max_km + args.step_km / 2, args.step_km)

    sweeps = {name: sweep(name, lengths, args.n_ref) for name in PRESETS}
    tables, configs = {}, {}
    for name in PRESETS:
        tables[name], configs[name] = required_table(name, args.n_ref)

    out_dir = ROOT / "experiments" / "results" / "decoy_finitekey" / run_id(started)
    write_csv(out_dir / "rates.csv", sweeps, tables)
    fig_path = ROOT / "experiments" / "figures" / "decoy_finitekey_rate_vs_distance.pdf"
    maxima = plot(sweeps, fig_path, args.n_ref)

    print(f"CSV:    {out_dir / 'rates.csv'}  (+ required_N.csv)")
    print(f"Figure: {fig_path} (+ .png)")
    for name in PRESETS:
        intensities, probs, q_x = configs[name]
        print(f"\n[{name}] composable max distance (N={args.n_ref:.0e}): "
              f"{maxima[name]['composable_finite']} km   "
              f"(asymptotic: infinite_decoy {maxima[name]['infinite_decoy']} km)")
        print(f"    table setup: mu=({intensities[0]:.3f},{intensities[1]:.3f},0) "
              f"probs=({probs[0]:.2f},{probs[1]:.2f},{probs[2]:.2f}) q_x={q_x:.3f}")
        for row in tables[name]:
            n = row["required_N"]
            tag = f"{n:,} (2^{row['log2_N']:.1f}), ell={row['ell_at_N']}" if n else "infeasible"
            print(f"    {row['length_km']:>5.0f} km: required N = {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
