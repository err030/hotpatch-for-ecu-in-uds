#!/usr/bin/env python3
"""Generate the revised, engineering-style Chapter 5 evaluation figures."""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
RESULTS = ROOT / "01_software_level" / "results"
FINAL_TIMING_RESULTS = RESULTS / "final_firmware_timing"

DIRS = {name: OUT / name for name in ("pdf", "source_data")}
for directory in DIRS.values():
    directory.mkdir(parents=True, exist_ok=True)


# Conventional engineering palette (MATLAB blue plus neutral greys).
BLUE = "#0072BD"
DARK_BLUE = "#005A91"
GREY = "#595959"
MID_GREY = "#8C8C8C"
LIGHT_GREY = "#D9D9D9"
GRID = "#E6E6E6"
BLACK = "#1A1A1A"
WHITE = "#FFFFFF"

plt.rcParams.update(
    {
        "figure.facecolor": WHITE,
        "axes.facecolor": WHITE,
        "savefig.facecolor": WHITE,
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman", "LM Roman 10", "DejaVu Serif"],
        "mathtext.fontset": "cm",
        "font.size": 8.5,
        "axes.labelsize": 9,
        "axes.titlesize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "axes.linewidth": 0.8,
        "axes.edgecolor": BLACK,
        "xtick.color": BLACK,
        "ytick.color": BLACK,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "legend.frameon": False,
        "svg.fonttype": "none",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(name: str, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if not rows:
        return
    fields = fieldnames or list(rows[0].keys())
    with (DIRS["source_data"] / name).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def truth(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "pass"}


def export(fig: plt.Figure, stem: str) -> None:
    fig.savefig(DIRS["pdf"] / f"{stem}.pdf", bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)


def panel_label(ax: plt.Axes, label: str, x: float = -0.12, y: float = 1.04) -> None:
    ax.text(x, y, label, transform=ax.transAxes, fontsize=10, fontweight="bold", ha="left", va="bottom", color=BLACK)


def standard_axes(ax: plt.Axes, grid_axis: str | None = "y") -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if grid_axis:
        ax.grid(axis=grid_axis, color=GRID, linewidth=0.6, linestyle=":", zorder=0)
    ax.set_axisbelow(True)


def grouped_bars(ax, labels, before, after, ylabel, n_labels=None, horizontal=False):
    """Traditional grouped bars; no lines imply temporal trajectories."""
    positions = np.arange(len(labels))
    width = 0.34
    if horizontal:
        ax.barh(positions + width / 2, before, height=width, facecolor=WHITE, edgecolor=GREY, linewidth=1.0, hatch="///", label="Before patch", zorder=2)
        ax.barh(positions - width / 2, after, height=width, color=BLUE, edgecolor=BLACK, linewidth=0.5, label="After patch", zorder=2)
        ax.set_yticks(positions, labels)
        ax.set_xlabel(ylabel)
        ax.set_xlim(0, 107)
        standard_axes(ax, "x")
    else:
        ax.bar(positions - width / 2, before, width=width, facecolor=WHITE, edgecolor=GREY, linewidth=1.0, hatch="///", label="Before patch", zorder=2)
        ax.bar(positions + width / 2, after, width=width, color=BLUE, edgecolor=BLACK, linewidth=0.5, label="After patch", zorder=2)
        ax.set_xticks(positions, labels)
        ax.set_ylabel(ylabel)
        ax.set_ylim(0, 108)
        standard_axes(ax, "y")
    return positions, width


def diagram_box(ax, xy, width, height, text, subtext="", face=WHITE):
    x, y = xy
    rect = Rectangle((x, y), width, height, transform=ax.transAxes, facecolor=face, edgecolor=BLACK, linewidth=0.9)
    ax.add_patch(rect)
    multiline = "\n" in subtext
    title_y = 0.68 if multiline else (0.59 if subtext else 0.5)
    ax.text(x + width / 2, y + height * title_y, text, transform=ax.transAxes, ha="center", va="center", fontsize=9)
    if subtext:
        ax.text(
            x + width / 2,
            y + height * (0.24 if multiline else 0.28),
            subtext,
            transform=ax.transAxes,
            ha="center",
            va="center",
            fontsize=7.2,
            linespacing=0.9,
            color=GREY,
        )


def diagram_arrow(ax, start, end, color=BLACK, style="-"):
    ax.add_patch(FancyArrowPatch(start, end, transform=ax.transAxes, arrowstyle="-|>", mutation_scale=9, linewidth=0.9, color=color, linestyle=style))


def fig51_data_flow() -> None:
    fig, ax = plt.subplots(figsize=(7.0, 2.7))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    diagram_box(ax, (0.03, 0.55), 0.18, 0.25, "Host", "SocketCAN / can0")
    diagram_box(ax, (0.28, 0.55), 0.18, 0.25, "CANable", "USB–CAN")
    diagram_box(ax, (0.55, 0.55), 0.18, 0.25, "CAN bus", "UDS traffic", face="#F2F2F2")
    diagram_box(ax, (0.79, 0.55), 0.20, 0.25, "nRF52840", "FreeRTOS /\nMCP2515")
    diagram_arrow(ax, (0.21, 0.675), (0.28, 0.675))
    diagram_arrow(ax, (0.46, 0.675), (0.55, 0.675))
    diagram_arrow(ax, (0.73, 0.675), (0.79, 0.675))

    # Passive tap and independent clock path.
    ax.plot([0.64, 0.64], [0.55, 0.36], color=BLACK, linewidth=0.9, transform=ax.transAxes)
    diagram_box(ax, (0.52, 0.12), 0.24, 0.24, "NUCLEO-G474RE", "listen-only CAN\nobserver")
    diagram_arrow(ax, (0.76, 0.24), (0.84, 0.24), color=BLUE)
    diagram_box(ax, (0.84, 0.12), 0.13, 0.24, "Host log", "ST-LINK\nVCP")

    ax.text(0.12, 0.47, "Host monotonic timestamps\n(request-to-response RTT)", transform=ax.transAxes, ha="center", va="top", fontsize=7.5, color=GREY)
    ax.text(0.64, 0.05, "250 kbit/s; request 0x7E0; response 0x7E8", transform=ax.transAxes, ha="center", va="top", fontsize=7.5, color=GREY)
    export(fig, "fig51_measurement_paths")


def load_fuzz_data():
    hardware = read_csv(RESULTS / "hardware_fuzz" / "hardware_fuzz_paired_detail.csv")
    vcan = read_csv(RESULTS / "vcan" / "vcan_paired_detail.csv")
    return hardware, vcan


def success_rate(rows, state, condition=None):
    selected = [r for r in rows if r["patch_state"] == state and (condition(r) if condition else True)]
    return 100 * sum(truth(r["attack_success"]) for r in selected) / len(selected), len(selected)


def fig52_attack_success() -> None:
    hardware, vcan = load_fuzz_data()
    categories = [
        ("Target-DID\nattacks", hardware, lambda r: r["mutation_kind"] == "target_did_random_data"),
        ("Mixed hardware\ncorpus", hardware, None),
        ("vcan\ncorpus", vcan, None),
    ]
    rows = []
    accepted = []
    rejected = []
    bar_labels = []
    n_per_bar = []
    for label, data, condition in categories:
        b, nb = success_rate(data, "before", condition)
        a, na = success_rate(data, "after", condition)
        for state, value, n in (("Before", b, nb), ("After", a, na)):
            accepted.append(value)
            rejected.append(100 - value)
            bar_labels.append(f"{label}\n{state}")
            n_per_bar.append(n)
        rows.append({"workload": label.replace("\n", " "), "before_pct": f"{b:.6f}", "after_pct": f"{a:.6f}", "before_rejected_pct": f"{100-b:.6f}", "after_rejected_pct": f"{100-a:.6f}", "n_before": nb, "n_after": na})
    write_csv("fig52_attack_success.csv", rows)

    fig, ax = plt.subplots(figsize=(7.0, 3.75))
    x = np.arange(len(accepted))
    bars_accepted = ax.bar(x, accepted, width=0.64, facecolor=WHITE, edgecolor=GREY, linewidth=0.9, hatch="///", label="Accepted")
    bars_rejected = ax.bar(x, rejected, bottom=accepted, width=0.64, color=BLUE, edgecolor=BLACK, linewidth=0.5, label="Rejected")
    ax.set_xticks(x, bar_labels)
    ax.set_ylabel("Outcome composition (%)")
    ax.set_ylim(0, 100)
    standard_axes(ax, "y")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2)
    for xi, acc, rej, n in zip(x, accepted, rejected, n_per_bar):
        if acc >= 8:
            ax.text(xi, acc / 2, f"{acc:.1f}%", ha="center", va="center", fontsize=7.6, color=BLACK)
        else:
            ax.text(xi, 5.0, f"0/{n:,}\naccepted", ha="center", va="center", fontsize=6.6, color=WHITE, linespacing=0.9)
        if rej >= 8:
            ax.text(xi, acc + rej / 2, f"{rej:.1f}%", ha="center", va="center", fontsize=7.6, color=WHITE)
    # Visually separate the three workloads without implying continuity.
    ax.axvline(1.5, color=LIGHT_GREY, linewidth=0.7)
    ax.axvline(3.5, color=LIGHT_GREY, linewidth=0.7)
    fig.subplots_adjust(bottom=0.27, left=0.10, right=0.98, top=0.87)
    export(fig, "fig52_attack_success")


def verdict_matrix(
    ax,
    row_labels,
    column_labels,
    values,
    note="",
    *,
    left=0.47,
    right=0.94,
    header_fontsize=8.5,
):
    """Plain LaTeX-style property matrix using ticks/crosses."""
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    top = 0.84
    row_h = 0.105 if len(row_labels) >= 6 else 0.145
    col_w = (right - left) / len(column_labels)
    ax.text(0.03, top + 0.085, "Property", ha="left", va="center", fontweight="bold")
    for j, label in enumerate(column_labels):
        ax.text(
            left + (j + 0.5) * col_w,
            top + 0.085,
            label,
            ha="center",
            va="center",
            fontweight="bold",
            fontsize=header_fontsize,
            linespacing=0.9,
        )
    ax.plot([0.03, right], [top + 0.035, top + 0.035], color=BLACK, linewidth=0.8)
    for i, (label, row) in enumerate(zip(row_labels, values)):
        y = top - i * row_h - row_h / 2
        ax.text(0.03, y, label, ha="left", va="center")
        for j, present in enumerate(row):
            x = left + (j + 0.5) * col_w
            ax.text(x, y, r"$\checkmark$" if present else r"$\times$", ha="center", va="center", fontsize=15, color=BLUE if present else MID_GREY)
        ax.plot([0.03, right], [top - (i + 1) * row_h, top - (i + 1) * row_h], color=GRID, linewidth=0.6)
    ax.plot([0.03, right], [top - len(row_labels) * row_h, top - len(row_labels) * row_h], color=BLACK, linewidth=0.8)
    if note:
        ax.text(0.03, 0.055, note, ha="left", va="bottom", fontsize=7.5, color=GREY)


def fig53_state_integrity() -> None:
    detail = [r for r in read_csv(FINAL_TIMING_RESULTS / "real_can_state_integrity.csv") if not truth(r["warmup"])]
    rows = []
    before, after = [], []
    for state in ("before", "after"):
        selected = [r for r in detail if r["patch_state"] == state]
        changed = sum(truth(r["state_changed"]) for r in selected)
        rows.append({"patch_state": state, "trials": len(selected), "state_changed": changed, "state_changed_pct": 100 * changed / len(selected)})
        (before if state == "before" else after).append(100 * changed / len(selected))
    write_csv("fig53_state_integrity.csv", rows)

    before_rows = [r for r in detail if r["patch_state"] == "before"]
    after_rows = [r for r in detail if r["patch_state"] == "after"]
    properties = [
        "Positive write response (6E 1234)",
        "NRC 0x31 returned (7F 2E 31)",
        "Target DID modified",
        "Original value preserved",
    ]
    values = [
        [all(r["write_response"].upper().startswith("6E1234") for r in before_rows), all(r["write_response"].upper().startswith("6E1234") for r in after_rows)],
        [all(r["write_response"].upper() == "7F2E31" for r in before_rows), all(r["write_response"].upper() == "7F2E31" for r in after_rows)],
        [all(truth(r["state_changed"]) for r in before_rows), all(truth(r["state_changed"]) for r in after_rows)],
        [all(r["value_after"] == r["value_before"] for r in before_rows), all(r["value_after"] == r["value_before"] for r in after_rows)],
    ]
    fig, ax = plt.subplots(figsize=(6.4, 3.25))
    verdict_matrix(ax, properties, ["Before patch", "After patch"], values, note="Non-warm-up trials: n=500 per patch state. Ticks indicate that the named property was observed in every trial.")
    export(fig, "fig53_state_integrity")


def fig54_reproducibility() -> None:
    hardware, _ = load_fuzz_data()
    by_run = defaultdict(lambda: defaultdict(list))
    seed_map = {}
    for row in hardware:
        by_run[row["run_id"]][row["patch_state"]].append(row)
        seed_map[row["run_id"]] = row["random_seed"]
    run_ids = sorted(by_run)
    before, after, rows = [], [], []
    for run_id in run_ids:
        b = 100 * sum(truth(r["attack_success"]) for r in by_run[run_id]["before"]) / len(by_run[run_id]["before"])
        a = 100 * sum(truth(r["attack_success"]) for r in by_run[run_id]["after"]) / len(by_run[run_id]["after"])
        before.append(b); after.append(a)
        rows.append({"run_id": run_id, "random_seed": seed_map[run_id], "before_pct": b, "after_pct": a, "cases_per_state": len(by_run[run_id]["before"])})
    write_csv("fig54_fuzz_reproducibility.csv", rows)

    fig, ax = plt.subplots(figsize=(6.0, 3.35))
    y = np.arange(len(run_ids))[::-1]
    ax.scatter(before, y, s=46, facecolor=WHITE, edgecolor=GREY, linewidth=1.1, marker="o", label="Before patch", zorder=3)
    ax.scatter(after, y, s=42, color=BLUE, edgecolor=BLACK, linewidth=0.5, marker="s", label="After patch", zorder=3)
    for yi, b, a in zip(y, before, after):
        ax.text(b + 2.0, yi, f"{b:.1f}%", ha="left", va="center", fontsize=8)
        ax.text(a + 2.0, yi, f"{a:.0f}%", ha="left", va="center", fontsize=8, color=DARK_BLUE)
    ax.set_yticks(y, [f"Run {i+1}" for i in range(len(run_ids))])
    ax.set_xlabel("Attack success (%)")
    ax.set_xlim(-3, 88)
    ax.set_ylim(-0.65, len(run_ids) - 0.35)
    standard_axes(ax, "x")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2)
    ax.text(0.99, 0.04, "1,000 cases per state and run", transform=ax.transAxes, ha="right", va="bottom", fontsize=7.5, color=GREY)
    fig.subplots_adjust(left=0.14, right=0.97, bottom=0.17, top=0.86)
    export(fig, "fig54_fuzz_reproducibility")


def styled_boxplot(ax, data, positions, colors, vert=True, widths=0.52, whis=(2.5, 97.5)):
    box = ax.boxplot(data, positions=positions, vert=vert, widths=widths, patch_artist=True, showfliers=False, whis=whis, medianprops={"color": BLACK, "linewidth": 1.2}, whiskerprops={"color": GREY, "linewidth": 0.8}, capprops={"color": GREY, "linewidth": 0.8})
    for patch, face in zip(box["boxes"], colors):
        patch.set_facecolor(face)
        patch.set_edgecolor(BLACK)
        patch.set_linewidth(0.8)
    return box


def fig55_latency() -> None:
    detail = [r for r in read_csv(FINAL_TIMING_RESULTS / "real_can_latency_detail.csv") if not truth(r["warmup"])]
    paired = read_csv(FINAL_TIMING_RESULTS / "real_can_latency_paired_delta.csv")
    target = {state: np.asarray([float(r["latency_ms"]) for r in detail if r["patch_state"] == state and r["step"] == "write_target"]) for state in ("before", "after")}
    source_target = []
    for state in ("before", "after"):
        for i, value in enumerate(target[state], 1):
            source_target.append({"patch_state": state, "observation": i, "latency_ms": f"{value:.6f}"})
    write_csv("fig55_target_latency.csv", source_target)

    step_order = ["session_reset", "enter_extended_session", "request_security_seed", "send_security_key", "read_target_before", "write_target", "read_target_after"]
    labels = ["Session reset", "Extended session", "Security seed", "Security key", "Read before", "Target write", "Read after"]
    deltas = {step: np.asarray([float(r["delta_after_minus_before_ms"]) * 1000 for r in paired if r["step"] == step]) for step in step_order}
    stats = []
    for step in step_order:
        values = deltas[step]
        stats.append({"step": step, "n": len(values), "median_us": f"{np.median(values):.6f}", "q25_us": f"{np.quantile(values, .25):.6f}", "q75_us": f"{np.quantile(values, .75):.6f}", "q025_us": f"{np.quantile(values, .025):.6f}", "q975_us": f"{np.quantile(values, .975):.6f}"})
    write_csv("fig55_paired_latency_delta.csv", stats)

    fig = plt.figure(figsize=(7.0, 3.85))
    gs = fig.add_gridspec(1, 2, width_ratios=[0.80, 1.45], wspace=0.42)
    ax_a = fig.add_subplot(gs[0, 0]); ax_b = fig.add_subplot(gs[0, 1])

    styled_boxplot(ax_a, [target["before"], target["after"]], [0, 1], [WHITE, "#B8D9EE"], vert=True)
    ax_a.set_xticks([0, 1], ["Before patch", "After patch"])
    ax_a.set_ylabel("Target 0x2E latency (ms)")
    standard_axes(ax_a, "y")
    for x, state in enumerate(("before", "after")):
        med = np.median(target[state])
        ax_a.text(x, np.quantile(target[state], .98) + 0.025, f"median {med:.3f}", ha="center", fontsize=7.5)
    ax_a.text(0.02, 0.02, "n=500/state", transform=ax_a.transAxes, fontsize=7.2, color=GREY)
    panel_label(ax_a, "a", -0.22, 1.02)

    y_positions = np.arange(len(step_order))[::-1]
    styled_boxplot(ax_b, [deltas[s] for s in step_order], y_positions, ["#D9D9D9"] * len(step_order), vert=False, widths=0.50)
    ax_b.axvline(0, color=BLACK, linewidth=0.8)
    ax_b.set_yticks(y_positions, labels)
    ax_b.set_xlabel(r"Paired latency difference, after $-$ before ($\mu$s)")
    ax_b.set_xlim(-650, 650)
    standard_axes(ax_b, "x")
    for y, step in zip(y_positions, step_order):
        ax_b.text(625, y, f"{np.median(deltas[step]):+.1f}", ha="right", va="center", fontsize=7, color=GREY)
    panel_label(ax_b, "b", -0.20, 1.02)
    fig.subplots_adjust(left=0.10, right=0.98, bottom=0.17, top=0.95)
    export(fig, "fig55_real_can_latency")


def fig56_activation() -> None:
    rows = read_csv(FINAL_TIMING_RESULTS / "patch_activation_detail.csv")
    activation = np.asarray([float(r["activation_latency_ms"]) for r in rows])
    stage_names = ["Validation", "Scheduling", "Application"]
    stage_cols = ["validation_rtt_ms", "scheduling_rtt_ms", "application_rtt_ms"]
    stages = [np.asarray([float(r[col]) for r in rows]) for col in stage_cols]
    write_csv("fig56_activation_detail.csv", [{"trial": r["trial"], "activation_latency_ms": r["activation_latency_ms"], "validation_rtt_ms": r["validation_rtt_ms"], "scheduling_rtt_ms": r["scheduling_rtt_ms"], "application_rtt_ms": r["application_rtt_ms"], "protected": r["protected"]} for r in rows])

    fig = plt.figure(figsize=(6.8, 3.45))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.15, 0.85], wspace=0.42)
    ax_a = fig.add_subplot(gs[0, 0]); ax_b = fig.add_subplot(gs[0, 1])
    ax_a.hist(activation, bins=10, color="#B8D9EE", edgecolor=BLACK, linewidth=0.6)
    med = np.median(activation); p95 = np.quantile(activation, .95)
    ax_a.axvline(med, color=BLACK, linewidth=1.1, label=f"Median = {med:.2f} ms")
    ax_a.axvline(p95, color=BLUE, linewidth=1.1, linestyle="--", label=f"P95 = {p95:.2f} ms")
    ax_a.set_xlabel("Host-observed activation latency (ms)")
    ax_a.set_ylabel("Activation trials")
    standard_axes(ax_a, "y")
    ax_a.legend(loc="upper left")
    ax_a.text(0.98, 0.95, "n=100", transform=ax_a.transAxes, ha="right", va="top", fontsize=7.5, color=GREY)
    panel_label(ax_a, "a", -0.18, 1.02)

    styled_boxplot(ax_b, stages, [0, 1, 2], [WHITE, "#D9D9D9", "#B8D9EE"], vert=True)
    ax_b.set_xticks([0, 1, 2], stage_names, rotation=18, ha="right")
    ax_b.set_ylabel("Diagnostic transaction RTT (ms)")
    standard_axes(ax_b, "y")
    for x, values in enumerate(stages):
        ax_b.text(x, np.quantile(values, .98) + 0.025, f"{np.median(values):.2f}", ha="center", fontsize=7.2)
    panel_label(ax_b, "b", -0.22, 1.02)
    fig.subplots_adjust(left=0.11, right=0.98, bottom=0.22, top=0.95)
    export(fig, "fig56_patch_activation")


def fig57_observer_matrix() -> None:
    hardware, _ = load_fuzz_data()
    grouped = defaultdict(list)
    for row in hardware:
        grouped[(row["run_id"], row["patch_state"])].append(row)
    matrix_rows = []
    for run_id in sorted({k[0] for k in grouped}):
        for state in ("before", "after"):
            selected = grouped[(run_id, state)]
            matrix_rows.append({"condition": f"{run_id.replace('_', ' ').title()} — {state}", "request_seen": sum(truth(r["observer_request_seen"]) for r in selected), "response_seen": sum(truth(r["observer_response_seen"]) for r in selected), "consistent": sum(truth(r["observer_consistent"]) for r in selected), "total": len(selected)})
    write_csv("fig57_observer_validation.csv", matrix_rows)

    timing_rows = []
    for row in hardware:
        if row["latency_ms"] and row["observer_latency_ms"]:
            observer_interval = float(row["observer_latency_ms"])
            interval_valid = 0.0 < observer_interval <= 20.0
            timing_rows.append({
                "run_id": row["run_id"],
                "patch_state": row["patch_state"],
                "case_id": row["case_id"],
                "mutation_kind": row["mutation_kind"],
                "host_latency_ms": row["latency_ms"],
                "observer_interval_ms": row["observer_latency_ms"],
                "observer_consistent": row["observer_consistent"],
                "interval_valid_for_timing_plot": str(interval_valid).lower(),
                "timing_plot_exclusion_reason": "" if interval_valid else "observer_counter_reset_or_wrap_boundary",
            })
    write_csv("fig57_observer_timing.csv", timing_rows)

    fig = plt.figure(figsize=(7.2, 4.0))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.08, 1.42], wspace=0.34)
    ax_a = fig.add_subplot(gs[0, 0])
    ax_b = fig.add_subplot(gs[0, 1])

    row_labels = [r["condition"].replace("Run ", "R").replace(" — ", " ") for r in matrix_rows]
    values = [[r["request_seen"] == r["total"], r["response_seen"] == r["total"], r["consistent"] == r["total"]] for r in matrix_rows]
    verdict_matrix(
        ax_a,
        row_labels,
        ["Request\nobserved", "Response\nobserved", "Classification\nagreement"],
        values,
        note="6,000/6,000 classification-consistent transactions",
        left=0.35,
        right=0.99,
        header_fontsize=6.4,
    )
    panel_label(ax_a, "a", -0.06, 1.01)

    for state, color, marker, label in (("before", GREY, "o", "Before patch"), ("after", BLUE, "s", "After patch")):
        selected = [r for r in timing_rows if r["patch_state"] == state and r["interval_valid_for_timing_plot"] == "true"]
        x = [float(r["host_latency_ms"]) for r in selected]
        y = [float(r["observer_interval_ms"]) for r in selected]
        ax_b.scatter(x, y, s=7, color=color, marker=marker, alpha=0.18, edgecolors="none", label=label, rasterized=True)
    ax_b.set_xlabel("Host can0 latency (ms)")
    ax_b.set_ylabel("Nucleo observer interval (ms)")
    standard_axes(ax_b, "both")
    ax_b.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2, markerscale=2.0)
    ax_b.text(0.01, -0.20, "Independent clock domains; not an overhead estimate. n=5,999 valid intervals; one counter-reset boundary excluded.", transform=ax_b.transAxes, ha="left", va="top", fontsize=7.0, color=GREY)
    panel_label(ax_b, "b", -0.17, 1.01)
    fig.subplots_adjust(left=0.07, right=0.98, bottom=0.20, top=0.87)
    export(fig, "fig57_observer_validation")


def fleet_data():
    base = RESULTS / "fleet_main"
    ts = read_csv(base / "fleet_ota_exposure_paired_hardware_1000v_60d_timeseries.csv")
    summary = read_csv(base / "fleet_ota_exposure_paired_hardware_1000v_60d_summary.csv")
    return ts, summary


def fig58_fleet_exposure() -> None:
    ts, summary = fleet_data()
    series = defaultdict(lambda: [[], []])
    source_ts = []
    for row in ts:
        day = float(row["time_hour"]) / 24
        count = float(row["vulnerable_vehicle_count"])
        series[row["strategy"]][0].append(day); series[row["strategy"]][1].append(count)
        source_ts.append({"time_day": f"{day:.6f}", "strategy": row["strategy"], "vulnerable_vehicles": int(count)})
    write_csv("fig58_fleet_timeseries.csv", source_ts)
    source_summary = [{"strategy": r["strategy"], "cumulative_exposure_vehicle_days": r["cumulative_exposure_vehicle_days"], "time_to_80pct_protection_h": f"{float(r['time_to_80pct_protection_min'])/60:.6f}", "time_to_full_protection_h": f"{float(r['time_to_full_protection_min'])/60:.6f}"} for r in summary]
    write_csv("fig58_fleet_summary.csv", source_summary)

    fig = plt.figure(figsize=(7.0, 3.75))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.55, 0.80], wspace=0.36)
    ax_a = fig.add_subplot(gs[0, 0]); ax_b = fig.add_subplot(gs[0, 1])
    styles = {"ota_only": (GREY, "--", "OTA-only"), "hotpatch_first": (BLUE, "-", "Hotpatch-first")}
    for strategy in ("ota_only", "hotpatch_first"):
        x = np.asarray(series[strategy][0]); y = np.asarray(series[strategy][1]); mask = x <= 20
        color, linestyle, label = styles[strategy]
        ax_a.plot(x[mask], y[mask], color=color, linestyle=linestyle, linewidth=1.6, label=label)
    ax_a.set_xlim(0, 20); ax_a.set_ylim(0, 1030)
    ax_a.set_xlabel("Time after disclosure (days)"); ax_a.set_ylabel("Vulnerable vehicles")
    standard_axes(ax_a, "both"); ax_a.legend(loc="upper right")
    hot = next(r for r in source_summary if r["strategy"] == "hotpatch_first")
    t80 = float(hot["time_to_80pct_protection_h"]) / 24
    ax_a.axvline(t80, color=BLUE, linewidth=0.9, linestyle=":")
    ax_a.text(t80 + 0.25, 760, "80% protected\n16.9 h", fontsize=7.5, color=DARK_BLUE)
    ax_a.text(0.01, 0.025, "60-day horizon; first 20 days shown (both curves reach zero by day 19.0)", transform=ax_a.transAxes, fontsize=6.8, color=GREY)
    panel_label(ax_a, "a", -0.17, 1.02)

    exposure = {r["strategy"]: float(r["cumulative_exposure_vehicle_days"]) for r in summary}
    values = [exposure["ota_only"], exposure["hotpatch_first"]]
    ax_b.bar([0, 1], values, width=0.55, color=[WHITE, BLUE], edgecolor=[GREY, BLACK], linewidth=0.9, hatch=["///", None])
    ax_b.set_xticks([0, 1], ["OTA-only", "Hotpatch-first"], rotation=12)
    ax_b.set_ylabel("Cumulative exposure (vehicle-days)")
    standard_axes(ax_b, "y")
    for x, value in enumerate(values): ax_b.text(x, value + 220, f"{value:,.0f}", ha="center", fontsize=8)
    reduction = 100 * (1 - values[1] / values[0])
    ax_b.text(0.98, 0.94, f"Reduction: {reduction:.1f}%", transform=ax_b.transAxes, ha="right", va="top", fontsize=8.5)
    panel_label(ax_b, "b", -0.25, 1.02)
    fig.subplots_adjust(left=0.10, right=0.98, bottom=0.18, top=0.95)
    export(fig, "fig58_fleet_exposure")


def fig59_sensitivity() -> None:
    all_rows = read_csv(RESULTS / "fleet_event_sensitivity" / "fleet_event_sensitivity_detail.csv")
    selected = [
        {
            "hotpatch_capable_pct": 100 * float(row["hotpatch_capable_ratio"]),
            "additional_delivery_delay_h": float(row["additional_delivery_delay_h"]),
            "exposure_reduction_pct": 100 * float(row["exposure_reduction_fraction"]),
            "hotpatch_first_exposure_vehicle_days": float(row["hotpatch_first_exposure_vehicle_days"]),
            "fleet_size": int(row["fleet_size"]),
            "horizon_days": int(row["horizon_days"]),
            "random_seed": int(row["random_seed"]),
            "ota_slots": int(row["ota_slots"]),
            "hotpatch_slots": int(row["hotpatch_slots"]),
            "ota_duration_min": int(row["ota_duration_min"]),
            "hotpatch_duration_min": int(row["hotpatch_duration_min"]),
            "model": row["model"],
        }
        for row in all_rows
    ]
    selected.sort(key=lambda r: (r["hotpatch_capable_pct"], r["additional_delivery_delay_h"]))
    write_csv("fig59_fleet_sensitivity.csv", selected)
    success = [70, 85, 95, 100]; delays = [0, 6, 24, 72]
    lookup = {(round(r["hotpatch_capable_pct"]), round(r["additional_delivery_delay_h"])): r["exposure_reduction_pct"] for r in selected}
    matrix = np.asarray([[lookup[(s, d)] for d in delays] for s in success])

    fig, ax = plt.subplots(figsize=(5.2, 3.75))
    image = ax.imshow(matrix, cmap="Blues", vmin=15, vmax=96, aspect="auto")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ax.text(j, i, f"{matrix[i,j]:.1f}", ha="center", va="center", color=WHITE if matrix[i,j] > 65 else BLACK, fontsize=8)
    # Exact base-case cell: 85% capable, zero extra delivery delay.
    ax.add_patch(Rectangle((-0.5, 0.5), 1, 1, fill=False, edgecolor=BLACK, linewidth=1.5))
    ax.text(0, 1.32, "base", ha="center", va="center", fontsize=6.8, color=BLACK)
    ax.set_xticks(range(4), delays); ax.set_yticks(range(4), success)
    ax.set_xlabel("Additional hotpatch delivery delay (h)"); ax.set_ylabel("Hotpatch-capable vehicles (%)")
    ax.tick_params(length=0)
    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    colorbar.set_label("Exposure reduction (%)")
    ax.text(0.0, -0.22, "Same event model as the base-case fleet analysis", transform=ax.transAxes, fontsize=6.9, color=GREY)
    fig.subplots_adjust(left=0.18, right=0.88, bottom=0.27, top=0.96)
    export(fig, "fig59_fleet_sensitivity")


def main() -> None:
    fig51_data_flow()
    fig52_attack_success()
    fig53_state_integrity()
    fig54_reproducibility()
    fig55_latency()
    fig56_activation()
    fig57_observer_matrix()
    fig58_fleet_exposure()
    fig59_sensitivity()
    print(f"Generated revised figures in {OUT}")


if __name__ == "__main__":
    main()
