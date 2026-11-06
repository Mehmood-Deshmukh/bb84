#!/usr/bin/env python3
"""
Render the figures defined in experiments/figures.yaml from the benchmark summaries.

    python scripts/plot_figures.py [--only FIGURE_ID]

Each figure reads experiments/results/<source>/latest/summary.csv (the newest
paper-grade run id written by scripts/benchmark.py) and writes
experiments/figures/<id>.png and <id>.pdf. experiments/figures/sources.json records
which run id every figure was drawn from.

A figure may add `where: {column: value}` to filter summary rows, and a list `series: [a, b]`
to draw one series per combination.

Figure kinds:
  rate     an outcome rate per x, one line per series, Wilson 95% band; optional
           analytic overlay (dashed, same color)
  measure  a numeric column's median per x with its interquartile band; optional
           analytic curve and horizontal reference line
  stacked  outcome shares per x as stacked bars, one panel per facet value
  bytes    bytes on the wire by component, stacked per mode, one panel per payload

Colors follow a validated palette: categorical slots in fixed order for identity
(modes, outcomes, byte components), a one-hue ordinal ramp for ordered magnitudes
(Eve's intercept fraction). Text stays in ink colors, never series colors.

Needs the `experiments` extra (pyyaml, matplotlib).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import yaml  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "experiments"

# Validated with the dataviz palette checker (light mode): categorical order passes
# adjacent CVD and normal-vision gates; the ordinal ramp is one hue, monotone.
CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
ORDINAL = ["#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#8a8985"
GRID = "#e4e3df"

OUTCOME_LABELS = {
    "delivered": "Delivered",
    "qber_check": "QBER check",
    "finite_key": "Finite-key bound",
    "key_confirmation": "Key confirmation",
    "chunk_tag": "AES-GCM tag (file data)",
    "authentication": "Authentication",
    "other": "Other",
}
BYTE_COMPONENTS = [
    ("qubit_bytes", "Qubit stream (QASM)"),
    ("bb84_classical_bytes", "BB84 classical"),
    ("auth_overhead_bytes", "Hello + finished"),
    ("file_wire_bytes", "Encrypted file"),
]


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
        "pdf.fonttype": 42,  # embed TrueType so journals accept the PDF
    })


def summary_path(source: str) -> Path:
    return EXPERIMENTS / "results" / source / "latest" / "summary.csv"


def load(source: str) -> list[dict[str, Any]]:
    path = summary_path(source)
    with open(path) as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for k, v in row.items():
            try:
                row[k] = float(v)
            except (TypeError, ValueError):
                pass
    return rows


def prepare_rows(fig: dict, rows: list[dict]) -> list[dict]:
    """
    Apply a figure's optional `where` filter (column: value) and fold a list-valued `series`
    into one label per row ("a / b") so it can be drawn as ordinary series.
    """
    for column, wanted in (fig.get("where") or {}).items():
        rows = [r for r in rows if r[column] == wanted]
    if isinstance(fig.get("series"), list):
        for r in rows:
            r["__series"] = " / ".join(str(r[c]) for c in fig["series"])
        fig["series"] = "__series"
    return rows


def series_values(rows: list[dict], key: Optional[str], order: Optional[list] = None) -> list[Any]:
    """
    Distinct values of `key`. With `order`, values follow it (so a series keeps its
    color slot in every figure); otherwise they are sorted.
    """
    if key is None:
        return [None]
    seen: list[Any] = []
    for row in rows:
        if row[key] not in seen:
            seen.append(row[key])
    if order:
        return [v for v in order if v in seen] + [v for v in seen if v not in order]
    return sorted(seen, key=lambda v: (isinstance(v, str), v))


def colors_for(values: list[Any], ordinal: bool) -> list[str]:
    if ordinal:
        if len(values) > len(ORDINAL):
            raise ValueError("more ordinal steps than the ramp has")
        # Spread across the ramp so the steps stay visibly apart
        idx = [round(i * (len(ORDINAL) - 1) / max(1, len(values) - 1)) for i in range(len(values))]
        return [ORDINAL[i] for i in idx]
    if len(values) > len(CATEGORICAL):
        raise ValueError("more series than categorical slots; facet or fold instead")
    return CATEGORICAL[: len(values)]


def axes_setup(ax, fig: dict) -> None:
    if fig.get("xscale") == "log2":
        ax.set_xscale("log", base=2)
    elif fig.get("xscale"):
        ax.set_xscale(fig["xscale"])
    if fig.get("yscale"):
        ax.set_yscale(fig["yscale"])
    ax.set_xlabel(fig.get("xlabel", fig["x"]))
    ax.set_ylabel(fig.get("ylabel", ""))
    if fig.get("ylim"):
        ax.set_ylim(*fig["ylim"])
    if fig.get("yscale") == "log":
        # Plain numbers instead of 6x10^-2 style labels
        plain = FuncFormatter(lambda v, _: f"{v:g}")
        ax.yaxis.set_major_formatter(plain)
        ax.yaxis.set_minor_formatter(plain)
        ax.tick_params(axis="y", which="minor", labelsize=7)


def label_line_end(ax, x: float, y: float, text: str) -> None:
    """Direct label just past the last point, in secondary ink."""
    ax.annotate(text, (x, y), xytext=(4, 0), textcoords="offset points", va="center",
                fontsize=7.5, color=INK_SECONDARY)


# ── analytic overlays ───────────────────────────────────────────────────────

def detection_probability(sample: float, fraction: float, threshold: float = 0.11) -> float:
    """P[Binomial(k, f/4) >= threshold * k]: chance the QBER check fires for a sample of k bits."""
    k = int(round(sample))
    p = fraction / 4
    need = math.ceil(threshold * k - 1e-9)
    return sum(math.comb(k, j) * p**j * (1 - p) ** (k - j) for j in range(need, k + 1))


def secure_length_curve(num_qubits: float) -> float:
    """Predicted secure bits for N raw qubits: N/2 sift, the default fraction is sampled, QBER 0."""
    from qkd.core.config import EPS_COR, EPS_SEC, QBER_SAMPLE_FRACTION
    from qkd.core.finite_key import secure_key_length

    sifted = int(num_qubits) // 2
    sample = max(1, int(sifted * QBER_SAMPLE_FRACTION))
    return secure_key_length(sifted - sample, sample, 0.0, EPS_SEC, EPS_COR)


# Each takes (summary row, series value, figure spec)
ANALYTIC: dict[str, Callable[[dict, Any, dict], float]] = {
    "detection": lambda row, series, fig: detection_probability(row["sample_size_median"], float(series)),
    "secure_length": lambda row, series, fig: secure_length_curve(row[fig["x"]]),
}


# ── renderers ───────────────────────────────────────────────────────────────

def render_lines(fig: dict, rows: list[dict], centre: str, lo: str, hi: str) -> plt.Figure:
    figure, ax = plt.subplots(figsize=fig.get("size", (5.0, 3.4)))
    series_key = fig.get("series")
    values = series_values(rows, series_key, fig.get("series_order"))
    colors = colors_for(values, fig.get("ordinal", False))
    direct = fig.get("direct_labels", True) and series_key is not None and len(values) <= 4
    for value, color in zip(values, colors):
        pts = sorted((r for r in rows if series_key is None or r[series_key] == value), key=lambda r: r[fig["x"]])
        pts = [r for r in pts if r.get(centre) not in (None, "")]
        xs = [r[fig["x"]] for r in pts]
        label = fig.get("series_label", "{}").format(value) if series_key else fig.get("measured_label", "Measured")
        ax.fill_between(xs, [r[lo] for r in pts], [r[hi] for r in pts], color=color, alpha=0.15, linewidth=0)
        ax.plot(xs, [r[centre] for r in pts], color=color, linewidth=1.5, marker="o", markersize=4.5,
                markeredgecolor="white", markeredgewidth=0.8, label=label)
        if fig.get("analytic_column"):
            # A model value stored per point in the summary (e.g. model_qber), drawn dashed
            col = fig["analytic_column"] + "_median"
            ax.plot(xs, [r[col] * fig.get("scale", 1.0) for r in pts], color=color, linewidth=1.0,
                    linestyle="--", zorder=3)
        if fig.get("analytic"):
            fn = ANALYTIC[fig["analytic"]]
            # One series: the model is a separate reference, drawn in ink on top so it stays visible
            analytic_color = color if series_key else INK_SECONDARY
            ax.plot(xs, [fn(r, value, fig) for r in pts], color=analytic_color, linewidth=1.0,
                    linestyle="--", zorder=3)
        if direct and xs:
            label_line_end(ax, xs[-1], pts[-1][centre], label)
    if fig.get("hline") is not None:
        ax.axhline(fig["hline"], color=INK_MUTED, linewidth=1.0, linestyle=":")
        if fig.get("hline_label"):
            ax.annotate(fig["hline_label"], (0.01, fig["hline"]), xycoords=("axes fraction", "data"),
                        xytext=(0, 3), textcoords="offset points", fontsize=7.5, color=INK_SECONDARY)
    axes_setup(ax, fig)
    handles, labels = ax.get_legend_handles_labels()
    if fig.get("analytic") or fig.get("analytic_column"):
        handles.append(plt.Line2D([], [], color=INK_SECONDARY, linestyle="--", linewidth=1.0))
        labels.append(fig.get("analytic_label", "Analytic"))
    if len(handles) >= 2:
        if fig.get("legend_loc") == "outside":
            ax.legend(handles, labels, title=fig.get("legend_title"), loc="center left", bbox_to_anchor=(1.02, 0.5))
        else:
            ax.legend(handles, labels, title=fig.get("legend_title"), loc=fig.get("legend_loc", "best"))
    ax.set_title(fig["title"], loc="left")
    return figure


def render_rate(fig: dict, rows: list[dict]) -> plt.Figure:
    y = fig["y"]
    return render_lines(fig, rows, y, f"{y}_lo", f"{y}_hi")


def render_measure(fig: dict, rows: list[dict]) -> plt.Figure:
    y = fig["y"]
    scale = fig.get("scale", 1.0)
    for r in rows:
        for suffix in ("_median", "_q1", "_q3"):
            if r.get(y + suffix) not in (None, ""):
                r[f"__{suffix}"] = r[y + suffix] * scale
    return render_lines(fig, rows, "___median", "___q1", "___q3")


def render_stacked(fig: dict, rows: list[dict]) -> plt.Figure:
    facet_key = fig.get("facet")
    facets = series_values(rows, facet_key, fig.get("facet_order"))
    outcomes = [o for o in OUTCOME_LABELS if any(r.get(f"rate_{o}", 0) > 0 for r in rows)]
    # Fixed slot per outcome (OUTCOME_LABELS order), so an outcome keeps its color in
    # every figure, whichever other outcomes happen to be present
    colors = dict(zip(OUTCOME_LABELS, CATEGORICAL))
    figure, axes = plt.subplots(1, len(facets), figsize=fig.get("size", (3.2 * len(facets), 3.4)),
                                sharey=True, squeeze=False)
    for ax, facet in zip(axes[0], facets):
        pts = sorted((r for r in rows if facet_key is None or r[facet_key] == facet), key=lambda r: r[fig["x"]])
        positions = range(len(pts))
        bottom = [0.0] * len(pts)
        for outcome in outcomes:
            heights = [r.get(f"rate_{outcome}", 0.0) for r in pts]
            ax.bar(positions, heights, bottom=bottom, width=0.7, color=colors[outcome],
                   edgecolor="white", linewidth=1.0, label=OUTCOME_LABELS[outcome])
            bottom = [b + h for b, h in zip(bottom, heights)]
        ax.set_xticks(list(positions), [fig.get("x_format", "{}").format(r[fig["x"]]) for r in pts])
        if fig.get("x_rotation"):
            ax.tick_params(axis="x", labelrotation=fig["x_rotation"])
        ax.set_xlabel(fig.get("xlabel", fig["x"]))
        ax.set_title(fig.get("facet_label", "{}").format(facet), loc="left", fontsize=9)
        ax.grid(axis="x", visible=False)
        ax.set_ylim(0, 1)
    axes[0][0].set_ylabel(fig.get("ylabel", "Share of runs"))
    handles, labels = axes[0][0].get_legend_handles_labels()
    figure.legend(handles, labels, loc="lower center", ncol=min(len(labels), 3), bbox_to_anchor=(0.5, -0.02))
    figure.suptitle(fig["title"], x=0.02, ha="left", fontsize=10, fontweight="bold", color=INK)
    figure.tight_layout(rect=(0, 0.1, 1, 1))
    return figure


def render_bytes(fig: dict, rows: list[dict]) -> plt.Figure:
    facet_key = fig.get("facet", "payload_bytes")
    facets = [f for f in series_values(rows, facet_key) if f in fig.get("facet_values", [f])]
    components = [(c, label) for c, label in BYTE_COMPONENTS if any(r.get(f"{c}_median") for r in rows)]
    colors = colors_for(components, False)
    figure, axes = plt.subplots(1, len(facets), figsize=fig.get("size", (3.2 * len(facets), 3.4)), squeeze=False)
    unit = fig.get("unit", 1024)
    for ax, facet in zip(axes[0], facets):
        pts = [r for r in rows if r[facet_key] == facet]
        pts.sort(key=lambda r: ["none", "sign", "hybrid"].index(r["mode"]) if r["mode"] in ("none", "sign", "hybrid") else 9)
        bottom = [0.0] * len(pts)
        for (col, label), color in zip(components, colors):
            heights = [(r.get(f"{col}_median") or 0.0) / unit for r in pts]
            ax.bar(range(len(pts)), heights, bottom=bottom, width=0.6, color=color, edgecolor="white",
                   linewidth=1.0, label=label)
            bottom = [b + h for b, h in zip(bottom, heights)]
        ax.set_xticks(range(len(pts)), [r["mode"] for r in pts])
        ax.set_title(fig.get("facet_label", "{}").format(_human_bytes(facet)), loc="left", fontsize=9)
        ax.grid(axis="x", visible=False)
        ax.set_ylabel(fig.get("ylabel", "KiB on the wire"))
    handles, labels = axes[0][0].get_legend_handles_labels()
    figure.legend(handles, labels, loc="lower center", ncol=min(len(labels), 4), bbox_to_anchor=(0.5, -0.02))
    figure.suptitle(fig["title"], x=0.02, ha="left", fontsize=10, fontweight="bold", color=INK)
    figure.tight_layout(rect=(0, 0.08, 1, 1))
    return figure


def _human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:g} {unit}"
        n /= 1024
    return f"{n:g} TiB"


RENDERERS = {"rate": render_rate, "measure": render_measure, "stacked": render_stacked, "bytes": render_bytes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", help="Render a single figure id")
    args = parser.parse_args()

    style()
    figures = yaml.safe_load((EXPERIMENTS / "figures.yaml").read_text())["figures"]
    out_dir = EXPERIMENTS / "figures"
    out_dir.mkdir(exist_ok=True)

    sources_path = out_dir / "sources.json"
    sources = json.loads(sources_path.read_text()) if sources_path.exists() else {}
    for fig in figures:
        if args.only and fig["id"] != args.only:
            continue
        source = summary_path(fig["source"])
        if not source.exists():
            print(f"skip {fig['id']}: {source.relative_to(ROOT)} not found "
                  "(no paper-grade run yet; run scripts/benchmark.py with the config's repeats)")
            continue
        figure = RENDERERS[fig["kind"]](fig, prepare_rows(fig, load(fig["source"])))
        for ext in ("png", "pdf"):
            figure.savefig(out_dir / f"{fig['id']}.{ext}", dpi=200, bbox_inches="tight")
        plt.close(figure)
        run = source.parent.resolve().name
        sources[fig["id"]] = {"experiment": fig["source"], "run_id": run,
                              "rendered": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        print(f"wrote experiments/figures/{fig['id']}.png and .pdf (from {fig['source']}/{run})")
    sources_path.write_text(json.dumps(sources, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
