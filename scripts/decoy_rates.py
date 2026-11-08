#!/usr/bin/env python3
"""
Decoy-state key rate vs distance for the GYS and KTH presets (Phase 1, numbers only).

    python scripts/decoy_rates.py [--max-km 200] [--step-km 1.0] [--f-ec 1.22]

For each preset this sweeps the fibre length from 0 to --max-km and, at each distance,
computes four asymptotic key rates per pulse from qkd.core.decoy (Ma, Qi, Zhao, Lo,
PRA 72, 012326, 2005):

  single_photon   ideal single-photon source (what the current protocol assumes)
  no_decoy        weak coherent source, GLLP worst case (mu optimised per distance)
  vacuum_weak     vacuum + weak decoy bounds (mu optimised; nu = 0.05 and 0.10)
  infinite_decoy  true Y1, e1 (the upper limit; mu optimised per distance)

It writes a tidy CSV to experiments/results/decoy_rates/<run id>/rates.csv and a log-scale
figure (one subplot per preset, each method's maximum secure distance marked) to
experiments/figures/decoy_key_rate_vs_distance.pdf (and .png).

This script reads nothing the protocol writes and runs no processes; it is pure numerics.
Needs the `experiments` extra (matplotlib). The run-id folder mirrors scripts/benchmark.py.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from qkd.core import decoy  # noqa: E402
from qkd.core.channel_model import preset  # noqa: E402

PRESETS = ("GYS", "KTH")
NU_VALUES = (0.05, 0.10)

# Palette borrowed from scripts/plot_figures.py (validated categorical order).
CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#8a8985"
GRID = "#e4e3df"

# One colour per method series, in a fixed order so the two panels match.
METHOD_COLUMNS = ["single_photon", "no_decoy", "vacuum_weak_nu0.05", "vacuum_weak_nu0.10", "infinite_decoy"]
METHOD_LABELS = {
    "single_photon": "Single-photon source",
    "no_decoy": "No decoy (GLLP worst case)",
    "vacuum_weak_nu0.05": "Vacuum+weak (nu=0.05)",
    "vacuum_weak_nu0.10": "Vacuum+weak (nu=0.10)",
    "infinite_decoy": "Infinite decoy",
}
METHOD_COLORS = dict(zip(METHOD_COLUMNS, CATEGORICAL))


def style() -> None:
    plt.rcParams.update({
        "font.size": 9,
        "axes.edgecolor": INK_MUTED,
        "axes.labelcolor": INK,
        "axes.titlesize": 10,
        "axes.titleweight": "bold",
        "axes.titlecolor": INK,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.6,
        "xtick.color": INK_SECONDARY,
        "ytick.color": INK_SECONDARY,
        "legend.frameon": False,
        "legend.fontsize": 8,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
        "pdf.fonttype": 42,
    })


def git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_id(started: datetime) -> str:
    """Folder name for one invocation: UTC start, short commit, and -dirty if the tree is."""
    commit = git("rev-parse", "HEAD") or "nocommit"
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    name = f"{started.strftime('%Y%m%dT%H%MZ')}_{commit[:7]}"
    return name + "-dirty" if dirty else name


def rates_at(params, f_ec: float) -> dict[str, float]:
    """The four (five, counting both nu) rates at one distance, each with mu optimised."""
    out = {"single_photon": decoy.rate_single_photon(params, f=f_ec)}
    mu_nd = decoy.optimal_mu(params, "no_decoy", f=f_ec)
    out["no_decoy"] = decoy.rate_no_decoy(params, mu_nd, f=f_ec)
    mu_inf = decoy.optimal_mu(params, "infinite_decoy", f=f_ec)
    out["infinite_decoy"] = decoy.rate_infinite_decoy(params, mu_inf, f=f_ec)
    out["mu_no_decoy"] = mu_nd
    out["mu_infinite_decoy"] = mu_inf
    for nu in NU_VALUES:
        mu_vw = decoy.optimal_mu(params, "vacuum_weak", nu=nu, f=f_ec)
        out[f"vacuum_weak_nu{nu:.2f}"] = decoy.rate_vacuum_weak(params, mu_vw, nu, f=f_ec)
        out[f"mu_vacuum_weak_nu{nu:.2f}"] = mu_vw
    return out


def column_name(method: str) -> str:
    """Map a METHOD_COLUMNS id to its key in rates_at()'s output (nu formatting differs)."""
    if method == "vacuum_weak_nu0.05":
        return "vacuum_weak_nu0.05"
    if method == "vacuum_weak_nu0.10":
        return "vacuum_weak_nu0.10"
    return method


def sweep(preset_name: str, lengths: np.ndarray, f_ec: float) -> list[dict]:
    base = preset(preset_name)
    rows = []
    for length in lengths:
        params = base.at_length(float(length))
        row = {"preset": preset_name, "length_km": round(float(length), 4), "eta": params.eta}
        # Normalise the nu keys to the fixed "vacuum_weak_nu0.05" / "0.10" column ids.
        raw = rates_at(params, f_ec)
        row["single_photon"] = raw["single_photon"]
        row["no_decoy"] = raw["no_decoy"]
        row["infinite_decoy"] = raw["infinite_decoy"]
        row["vacuum_weak_nu0.05"] = raw["vacuum_weak_nu0.05"]
        row["vacuum_weak_nu0.10"] = raw["vacuum_weak_nu0.10"]
        row["mu_no_decoy"] = raw["mu_no_decoy"]
        row["mu_infinite_decoy"] = raw["mu_infinite_decoy"]
        row["mu_vacuum_weak_nu0.05"] = raw["mu_vacuum_weak_nu0.05"]
        row["mu_vacuum_weak_nu0.10"] = raw["mu_vacuum_weak_nu0.10"]
        rows.append(row)
    return rows


def max_distance(rows: list[dict], method: str) -> Optional[float]:
    """Largest length with a positive rate for that method, or None if never positive."""
    positive = [r["length_km"] for r in rows if r[method] > 0.0]
    return max(positive) if positive else None


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = ["preset", "length_km", "eta", *METHOD_COLUMNS,
              "mu_no_decoy", "mu_infinite_decoy", "mu_vacuum_weak_nu0.05", "mu_vacuum_weak_nu0.10"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in fields})


def plot(by_preset: dict[str, list[dict]], out_pdf: Path, f_ec: float) -> dict:
    style()
    fig, axes = plt.subplots(1, len(PRESETS), figsize=(10, 4.2), sharey=True)
    if len(PRESETS) == 1:
        axes = [axes]
    maxima: dict = {}
    for ax, name in zip(axes, PRESETS):
        rows = by_preset[name]
        lengths = np.array([r["length_km"] for r in rows])
        maxima[name] = {}
        for method in METHOD_COLUMNS:
            color = METHOD_COLORS[method]
            rates = np.array([r[method] for r in rows])
            positive = rates > 0.0
            ax.plot(lengths[positive], rates[positive], color=color, lw=1.6,
                    label=METHOD_LABELS[method])
            dmax = max_distance(rows, method)
            maxima[name][method] = dmax
            if dmax is not None:
                ax.axvline(dmax, color=color, lw=0.7, ls=":", alpha=0.7)
        ax.set_yscale("log")
        ax.set_ylim(1e-8, 1e-1)
        ax.set_xlim(0, lengths.max())
        ax.set_title(f"{name}  (f={f_ec})")
        ax.set_xlabel("Fibre length (km)")
    axes[0].set_ylabel("Secure key rate per pulse")
    axes[0].legend(loc="lower left")
    fig.suptitle("Decoy-state BB84: asymptotic key rate vs distance", fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf)
    fig.savefig(out_pdf.with_suffix(".png"), dpi=150)
    plt.close(fig)
    return maxima


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Decoy-state key rate vs distance (numbers only).")
    parser.add_argument("--max-km", type=float, default=200.0, help="Longest fibre length (default: 200)")
    parser.add_argument("--step-km", type=float, default=1.0, help="Distance step (default: 1.0)")
    parser.add_argument("--f-ec", type=float, default=decoy.F_EC_DEFAULT,
                        help=f"Error-correction inefficiency (default: {decoy.F_EC_DEFAULT})")
    args = parser.parse_args(argv)

    started = datetime.now(timezone.utc)
    lengths = np.arange(0.0, args.max_km + args.step_km / 2, args.step_km)

    by_preset = {name: sweep(name, lengths, args.f_ec) for name in PRESETS}

    out_dir = ROOT / "experiments" / "results" / "decoy_rates" / run_id(started)
    csv_path = out_dir / "rates.csv"
    write_csv(csv_path, [row for name in PRESETS for row in by_preset[name]])

    fig_path = ROOT / "experiments" / "figures" / "decoy_key_rate_vs_distance.pdf"
    maxima = plot(by_preset, fig_path, args.f_ec)

    print(f"CSV:    {csv_path}")
    print(f"Figure: {fig_path} (+ .png)")
    for name in PRESETS:
        print(f"[{name}] maximum secure distance (km):")
        for method in METHOD_COLUMNS:
            dmax = maxima[name][method]
            print(f"    {METHOD_LABELS[method]:<28} {('%.1f' % dmax) if dmax is not None else 'none':>8}")
        first = by_preset[name][0]
        print(f"    optimal mu at 0 km: no_decoy={first['mu_no_decoy']:.3f} "
              f"infinite_decoy={first['mu_infinite_decoy']:.3f} "
              f"vacuum_weak(0.05)={first['mu_vacuum_weak_nu0.05']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
