#!/usr/bin/env python3
"""
Render the figures defined in experiments/figures.yaml from experiments/results/*.csv.

    python scripts/plot_figures.py [--only FIGURE_ID]

Needs the `experiments` extra (pyyaml, matplotlib).
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import yaml  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "experiments"


def averaged(path: Path, x: str, y: str) -> tuple[list[float], list[float]]:
    groups: dict[float, list[float]] = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            groups[float(row[x])].append(float(row[y]))
    xs = sorted(groups)
    return xs, [sum(groups[k]) / len(groups[k]) for k in xs]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", help="Render a single figure id")
    args = parser.parse_args()

    figures = yaml.safe_load((EXPERIMENTS / "figures.yaml").read_text())["figures"]
    out_dir = EXPERIMENTS / "figures"
    out_dir.mkdir(exist_ok=True)

    for fig in figures:
        if args.only and fig["id"] != args.only:
            continue
        source = EXPERIMENTS / "results" / f"{fig['source']}.csv"
        if not source.exists():
            print(f"skip {fig['id']}: {source.relative_to(ROOT)} not found (run scripts/benchmark.py first)")
            continue
        xs, ys = averaged(source, fig["x"], fig["y"])
        ax = plt.figure(figsize=(6, 4)).gca()
        ax.plot(xs, ys, marker="o", color="#222222")
        ax.set(xlabel=fig["xlabel"], ylabel=fig["ylabel"], title=fig["title"])
        ax.grid(alpha=0.3)
        out = out_dir / f"{fig['id']}.png"
        plt.tight_layout()
        plt.savefig(out, dpi=150)
        plt.close()
        print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
