"""Generate thesis-ready PDF figures from the current UDS hotpatch artifacts."""

from __future__ import annotations

import csv
import os
from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402


CHARTS = ROOT / "charts"
OUT = ROOT / "thesis_figures" / "pdf"

BLUE = "#0072BD"
ORANGE = "#D95319"
YELLOW = "#EDB120"
PURPLE = "#7E2F8E"
GREEN = "#77AC30"
CYAN = "#4DBEEE"
RED = "#A2142F"
GRAY = "#6E6E6E"
LIGHT_GRAY = "#E6E6E6"
TEXT = "#202020"


def apply_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.labelsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "legend.fontsize": 9,
            "figure.titlesize": 13,
            "axes.grid": True,
            "grid.color": "#D9D9D9",
            "grid.linewidth": 0.7,
            "grid.alpha": 0.9,
            "axes.edgecolor": "#404040",
            "axes.linewidth": 0.8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def read_key_value_csv(path: Path) -> dict[str, float]:
    values: dict[str, float] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            values[row["metric"]] = float(row["value"])
    return values


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def save(fig: plt.Figure, filename: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / filename
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def add_box(
    ax,
    xy: tuple[float, float],
    width: float,
    height: float,
    title: str,
    body: str = "",
    *,
    facecolor: str = "#F7F7F7",
    edgecolor: str = "#303030",
) -> None:
    box = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.018,rounding_size=0.018",
        facecolor=facecolor,
        edgecolor=edgecolor,
        linewidth=1.0,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + width / 2,
        xy[1] + height * 0.63,
        title,
        ha="center",
        va="center",
        fontsize=10,
        fontweight="bold",
        color=TEXT,
    )
    if body:
        ax.text(
            xy[0] + width / 2,
            xy[1] + height * 0.32,
            body,
            ha="center",
            va="center",
            fontsize=8.5,
            color=TEXT,
            linespacing=1.25,
        )


def add_arrow(ax, start: tuple[float, float], end: tuple[float, float], label: str = "") -> None:
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=12,
        linewidth=1.1,
        color="#303030",
        shrinkA=4,
        shrinkB=4,
    )
    ax.add_patch(arrow)
    if label:
        ax.text(
            (start[0] + end[0]) / 2,
            (start[1] + end[1]) / 2 + 0.035,
            label,
            ha="center",
            va="bottom",
            fontsize=8,
            color="#303030",
        )


def fig_system_architecture() -> Path:
    fig, ax = plt.subplots(figsize=(8.6, 4.2))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Gateway-Routed UDS Hotpatch Testbed", pad=12, fontweight="bold")

    add_box(ax, (0.04, 0.56), 0.18, 0.22, "Tester", "Python tools\nUDS requests", facecolor="#F3F7FF")
    add_box(ax, (0.29, 0.56), 0.18, 0.22, "CAN Interface", "CANable2.0\nSocketCAN can0", facecolor="#F6FBFF")
    add_box(ax, (0.54, 0.56), 0.18, 0.22, "Gateway ECU", "routed diagnostics\npolicy boundary", facecolor="#FFF8E8")
    add_box(ax, (0.79, 0.56), 0.18, 0.22, "Target ECU", "UDS state machine\nDID storage", facecolor="#F4FBF0")
    add_box(ax, (0.54, 0.18), 0.18, 0.22, "Kintsugi Runtime", "manager / slot\napplicator", facecolor="#F7F0FA")
    add_box(ax, (0.79, 0.18), 0.18, 0.22, "Hotpatch Policy", "SecurityAccess\nDID quarantine", facecolor="#F4FBF0")

    add_arrow(ax, (0.22, 0.67), (0.29, 0.67))
    add_arrow(ax, (0.47, 0.67), (0.54, 0.67))
    add_arrow(ax, (0.72, 0.67), (0.79, 0.67))
    add_arrow(ax, (0.63, 0.56), (0.63, 0.40))
    add_arrow(ax, (0.72, 0.29), (0.79, 0.29))
    add_arrow(ax, (0.88, 0.40), (0.88, 0.56))
    ax.text(0.255, 0.50, "UDS/CAN", ha="center", fontsize=8, color=GRAY)
    ax.text(0.505, 0.50, "external ID", ha="center", fontsize=8, color=GRAY)
    ax.text(0.755, 0.50, "internal ID", ha="center", fontsize=8, color=GRAY)
    ax.text(0.60, 0.445, "trigger", ha="right", fontsize=8, color=GRAY)
    ax.text(0.755, 0.225, "apply", ha="center", fontsize=8, color=GRAY)
    ax.text(0.91, 0.48, "enforce", ha="left", fontsize=8, color=GRAY)

    ax.text(
        0.04,
        0.07,
        "Main evidence path: the gateway forwards protocol-valid diagnostics; the ECU-local hotpatch blocks high-risk DID writes.",
        fontsize=8.5,
        color=GRAY,
    )
    return save(fig, "fig01_system_architecture.pdf")


def fig_attack_sequence() -> Path:
    fig, ax = plt.subplots(figsize=(8.6, 5.2))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("UDS SecurityAccess-Derived 0x2E Attack Chain", pad=12, fontweight="bold")

    xs = [0.12, 0.50, 0.86]
    labels = ["Tester", "Gateway", "Target ECU"]
    for x, label in zip(xs, labels):
        ax.text(x, 0.92, label, ha="center", va="center", fontsize=10, fontweight="bold")
        ax.plot([x, x], [0.12, 0.88], color="#909090", linewidth=0.8)

    def seq_arrow(x1: float, x2: float, y: float, label: str, *, dashed: bool = False) -> None:
        patch = FancyArrowPatch(
            (x1, y),
            (x2, y),
            arrowstyle="-|>",
            mutation_scale=12,
            linewidth=1.0,
            linestyle="--" if dashed else "-",
            color="#303030",
        )
        ax.add_patch(patch)
        if label:
            ax.text((x1 + x2) / 2, y + 0.018, label, ha="center", va="bottom", fontsize=8.3, color=TEXT)

    steps = [
        (0.81, "0x10 extended session", "0x50 0x03"),
        (0.69, "0x27 request seed", "0x67 0x01 seed"),
        (0.57, "0x27 send key", "0x67 0x02"),
        (0.45, "0x2E write DID 0x1234", "0x6E / 0x7F 2E 31"),
        (0.33, "0x22 read back DID", "0x62 DID value"),
    ]
    for y, request_label, response_label in steps:
        seq_arrow(xs[0], xs[1], y, request_label)
        seq_arrow(xs[1], xs[2], y, "")
        seq_arrow(xs[2], xs[1], y - 0.04, response_label, dashed=True)
        seq_arrow(xs[1], xs[0], y - 0.04, "", dashed=True)

    ax.add_patch(Rectangle((0.08, 0.15), 0.84, 0.07, facecolor="#FFF3E8", edgecolor=ORANGE, linewidth=0.9))
    ax.text(0.50, 0.185, "Before hotpatch: weak seed/key unlocks SecurityAccess; 0x2E succeeds\nand readback confirms the write.", ha="center", va="center", fontsize=8.0)
    ax.add_patch(Rectangle((0.08, 0.055), 0.84, 0.07, facecolor="#F0FAF0", edgecolor=GREEN, linewidth=0.9))
    ax.text(0.50, 0.090, "After hotpatch: SecurityAccess may still unlock, but DID 0x1234\nis quarantined with 7F 2E 31.", ha="center", va="center", fontsize=8.0)
    return save(fig, "fig02_uds_attack_sequence.pdf")


def fig_gateway_defense_boundary() -> Path:
    fig, ax = plt.subplots(figsize=(8.6, 4.0))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Gateway Policy vs. ECU-Local Hotpatch Boundary", pad=12, fontweight="bold")

    columns = [
        ("Restricted Gateway", "0x2E is dropped\nbefore ECU", "#F3F7FF", "Perimeter defense\nbreaks some diagnostic flows"),
        ("Permissive Gateway", "0x27 and 0x2E\nreach ECU", "#FFF8E8", "Attack can look\nprotocol-valid"),
        ("Hotpatched ECU", "0x27 still unlocks\n0x2E DID quarantined", "#F4FBF0", "Defense at the\nstateful ECU policy"),
    ]
    for i, (title, body, color, note) in enumerate(columns):
        x = 0.06 + i * 0.31
        add_box(ax, (x, 0.47), 0.25, 0.28, title, body, facecolor=color)
        ax.text(x + 0.125, 0.29, note, ha="center", va="center", fontsize=8.5, color=GRAY, linespacing=1.3)
    add_arrow(ax, (0.31, 0.61), (0.37, 0.61), "contrast")
    add_arrow(ax, (0.62, 0.61), (0.68, 0.61), "mitigate")
    ax.text(
        0.50,
        0.12,
        "The thesis focuses on ECU-local mitigation because service-ID-only gateway blocking cannot distinguish every authorized-looking write.",
        ha="center",
        va="center",
        fontsize=8.5,
        color=GRAY,
    )
    return save(fig, "fig03_gateway_defense_boundary.pdf")


def fig_kintsugi_lifecycle() -> Path:
    fig, ax = plt.subplots(figsize=(9.2, 3.8))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Kintsugi Runtime Hotpatch Workflow Used by the Board Profile", pad=12, fontweight="bold")

    stages = [
        ("Control DID", "0x2E F190 01"),
        ("Receive", "copy patch\ninto quarantine"),
        ("Validate", "manager + slot\nmetadata"),
        ("Schedule", "pending patch\nidentifier"),
        ("Apply Gate", "applicator writes\nRAM gate"),
        ("Enforce", "DID 0x1234\nquarantine"),
    ]
    for i, (title, body) in enumerate(stages):
        x = 0.035 + i * 0.158
        add_box(ax, (x, 0.50), 0.118, 0.24, title, body, facecolor="#F7F7FF" if i < 4 else "#F0FAF0")
        if i < len(stages) - 1:
            add_arrow(ax, (x + 0.118, 0.62), (x + 0.158, 0.62))

    ax.add_patch(Rectangle((0.12, 0.16), 0.76, 0.15, facecolor="#FAFAFA", edgecolor=LIGHT_GRAY, linewidth=0.9))
    ax.text(
        0.50,
        0.235,
        "Integration boundary: Kintsugi manager/slot/applicator are reused;\nthe board bridge provides an explicit safe point.",
        ha="center",
        va="center",
        fontsize=8.5,
        color=GRAY,
    )
    return save(fig, "fig04_kintsugi_hotpatch_lifecycle.pdf")


def fig_mutation_success_rate() -> Path:
    rows = read_rows(CHARTS / "uds_2e_mutation_attack_summary.csv")
    profiles = [row["profile"].replace("_", " ") for row in rows]
    rates = [float(row["attack_success_rate"]) * 100 for row in rows]

    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    bars = ax.bar(profiles, rates, color=[ORANGE, GREEN], edgecolor="#303030", linewidth=0.8, width=0.55)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Mutation Campaign: 0x27 -> 0x2E Attack Success", fontweight="bold")
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    for bar, value in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 2.0, f"{value:.1f}%", ha="center", va="bottom", fontweight="bold")
    ax.text(
        0.5,
        -0.22,
        "Deterministic 1000-case corpus; post-hotpatch result is observed for this corpus.",
        transform=ax.transAxes,
        ha="center",
        va="top",
        fontsize=8.5,
        color=GRAY,
    )
    return save(fig, "fig05_mutation_attack_success_rate.pdf")


def fig_control_group_success_rates() -> Path:
    rows = read_rows(CHARTS / "uds_control_group_summary.csv")
    by_profile_workload = {
        (row["profile"], row["workload"]): float(row["success_rate"]) * 100
        for row in rows
    }
    profiles = [("before_hotpatch", "Before hotpatch"), ("after_hotpatch", "After hotpatch")]
    benign = [by_profile_workload[(profile, "benign_diagnostic")] for profile, _ in profiles]
    attack = [by_profile_workload[(profile, "attack_mutation")] for profile, _ in profiles]
    x = range(len(profiles))

    fig, ax = plt.subplots(figsize=(7.0, 4.1))
    width = 0.34
    benign_bars = ax.bar(
        [i - width / 2 for i in x],
        benign,
        width,
        label="Benign diagnostics",
        color=BLUE,
        edgecolor="#303030",
        linewidth=0.7,
    )
    attack_bars = ax.bar(
        [i + width / 2 for i in x],
        attack,
        width,
        label="Attack mutations",
        color=ORANGE,
        edgecolor="#303030",
        linewidth=0.7,
    )
    ax.set_ylim(0, 112)
    ax.set_xticks(list(x), [label for _, label in profiles])
    ax.set_ylabel("Successful requests / attacks (%)")
    ax.set_title("Control Group: Benign Diagnostics vs. Attack Mutations", fontweight="bold")
    ax.legend(frameon=True, loc="upper center", ncol=2)
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    for bars, values in ((benign_bars, benign), (attack_bars, attack)):
        for bar, value in zip(bars, values):
            if value >= 95.0:
                label_y = value - 4.0
                va = "top"
                color = "white"
            elif value <= 1.0:
                label_y = value + 2.0
                va = "bottom"
                color = TEXT
            else:
                label_y = value + 2.0
                va = "bottom"
                color = TEXT
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                label_y,
                f"{value:.1f}%",
                ha="center",
                va=va,
                fontweight="bold",
                fontsize=9,
                color=color,
            )
    ax.text(
        0.5,
        -0.22,
        "Benign workload: session control, DID reads and SecurityAccess unlock. Attack workload: mutated 0x27 -> 0x2E chains.",
        transform=ax.transAxes,
        ha="center",
        va="top",
        fontsize=8.2,
        color=GRAY,
    )
    return save(fig, "fig11_control_group_success_rates.pdf")


def classify_response_payload(payload: str) -> tuple[str, str]:
    if payload == "<none>" or payload == "":
        return "timeout", "timeout"
    if payload.startswith("7F") and len(payload) >= 6:
        return "negative", f"NRC {payload[4:6]}"
    if payload.startswith("7F"):
        return "negative", "negative"
    return "positive", "positive"


def short_step_label(step: str) -> str:
    labels = {
        "trigger_kintsugi_hotpatch": "trigger\n0x2E F190",
        "enter_extended_session": "session\n0x10",
        "reset_default_session": "reset\n0x10",
        "request_security_seed": "seed\n0x27",
        "send_key_from_weak_transform": "key\n0x27",
        "write_did_after_security_access": "write\n0x2E",
        "read_back_written_did": "read\n0x22",
        "read_back_quarantined_did": "read\n0x22",
        "read_back_did_0x1234": "read\n0x22",
    }
    return labels.get(step, step.replace("_", "\n"))


def timeline_source_rows() -> list[dict[str, str]]:
    real_sources = [
        (
            "before_hotpatch_attack_succeeds",
            "Before hotpatch: attack succeeds",
            CHARTS / "can0_request_timeline_latest.csv",
        ),
        (
            "after_kintsugi_hotpatch_blocks",
            "After Kintsugi hotpatch: attack blocked",
            CHARTS / "can0_request_timeline_kintsugi_after_latest.csv",
        ),
    ]
    if all(path.exists() for _, _, path in real_sources):
        rows: list[dict[str, str]] = []
        for scenario_id, scenario_label, path in real_sources:
            for row in read_rows(path):
                if row["response_payload"] == "<none>":
                    continue
                rows.append(
                    {
                        "scenario_id": scenario_id,
                        "scenario_label": scenario_label,
                        "step_index": row["step_index"],
                        "step": row["step"],
                        "request_payload": row["request_payload"],
                        "response_payload": row["response_payload"],
                        "response_class": row["response_class"],
                        "outcome": row["nrc"] if row["nrc"] else row["response_class"],
                        "elapsed_start_ms": row["elapsed_start_ms"],
                        "elapsed_end_ms": row["elapsed_end_ms"],
                        "latency_ms": row["latency_ms"],
                        "source": path.name,
                    }
                )
        if rows:
            return rows

    artifact_sources = [
        (
            "before_hotpatch_attack_succeeds",
            "Before hotpatch: attack succeeds",
            CHARTS / "uds_2e_security_access_attack_kintsugi_before_latest.csv",
        ),
        (
            "after_kintsugi_hotpatch_blocks",
            "After Kintsugi hotpatch: attack blocked",
            CHARTS / "uds_2e_security_access_attack_kintsugi_after_latest.csv",
        ),
    ]
    rows: list[dict[str, str]] = []
    for scenario_id, scenario_label, path in artifact_sources:
        for index, row in enumerate(read_rows(path), start=1):
            response_class, outcome = classify_response_payload(row["response_payload"])
            rows.append(
                {
                    "scenario_id": scenario_id,
                    "scenario_label": scenario_label,
                    "step_index": str(index),
                    "step": row["step"],
                    "request_payload": row["request_payload"],
                    "response_payload": row["response_payload"],
                    "response_class": response_class,
                    "outcome": outcome,
                    "elapsed_start_ms": str(index - 1),
                    "elapsed_end_ms": str(index),
                    "latency_ms": "",
                    "source": path.name,
                }
            )
    return rows


def write_timeline_summary_csv(rows: list[dict[str, str]]) -> None:
    path = CHARTS / "uds_request_response_timeline_summary.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "scenario_id",
            "scenario_label",
            "step_index",
            "step",
            "request_payload",
            "response_payload",
            "response_class",
            "outcome",
            "elapsed_start_ms",
            "elapsed_end_ms",
            "latency_ms",
            "source",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def fig_request_response_timeline() -> Path:
    rows = timeline_source_rows()
    write_timeline_summary_csv(rows)
    scenario_order = [
        "before_hotpatch_attack_succeeds",
        "after_kintsugi_hotpatch_blocks",
    ]
    scenario_titles = {
        row["scenario_id"]: row["scenario_label"]
        for row in rows
    }
    colors = {
        "positive": GREEN,
        "negative": ORANGE,
        "timeout": RED,
    }
    markers = {
        "positive": "o",
        "negative": "s",
        "timeout": "x",
    }

    real_latency = all(row["latency_ms"] for row in rows)
    fig, axes = plt.subplots(2, 1, figsize=(9.2, 5.4), sharex=False)
    title = "Real CAN0 UDS Request-Response Timeline" if real_latency else "CAN0 UDS Request Timeline from Hardware CSV Artifacts"
    fig.suptitle(title, fontweight="bold", y=0.99)

    for ax, scenario_id in zip(axes, scenario_order):
        scenario_rows = [row for row in rows if row["scenario_id"] == scenario_id]
        starts = [float(row["elapsed_start_ms"]) for row in scenario_rows]
        ends = [float(row["elapsed_end_ms"]) for row in scenario_rows]
        xmax = max(ends)
        ax.hlines(0, min(starts), xmax, color="#808080", linewidth=1.0)
        for row in scenario_rows:
            start = float(row["elapsed_start_ms"])
            end = float(row["elapsed_end_ms"])
            x = (start + end) / 2.0
            response_class = row["response_class"]
            ax.hlines(0, start, end, color=colors[response_class], linewidth=5, alpha=0.85)
            ax.scatter(
                [x],
                [0],
                s=75,
                marker=markers[response_class],
                color=colors[response_class],
                edgecolor="#303030",
                linewidth=0.6,
                zorder=3,
            )
            ax.text(
                x,
                0.20,
                short_step_label(row["step"]),
                ha="center",
                va="bottom",
                fontsize=8,
            )
            ax.text(
                x,
                -0.22,
                f"req {row['request_payload']}\nresp {row['response_payload']}"
                + (f"\n{float(row['latency_ms']):.2f} ms" if row["latency_ms"] else ""),
                ha="center",
                va="top",
                fontsize=7.2,
                color=TEXT,
            )
        ax.set_ylim(-0.45, 0.45)
        ax.set_xlim(-8.0, xmax + max(5.0, xmax * 0.04))
        ax.set_yticks([])
        ax.set_xlabel("Elapsed time since first request send (ms)" if real_latency else "Request order")
        ax.set_title(scenario_titles[scenario_id], loc="left", fontsize=10, fontweight="bold")
        ax.grid(axis="x")
        ax.grid(axis="y", visible=False)

    legend_handles = [
        Line2D([0], [0], marker="o", color="w", label="positive response", markerfacecolor=GREEN, markeredgecolor="#303030", markersize=8),
        Line2D([0], [0], marker="s", color="w", label="negative response", markerfacecolor=ORANGE, markeredgecolor="#303030", markersize=8),
        Line2D([0], [0], marker="x", color=RED, label="timeout", markersize=8),
    ]
    fig.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, 0.94), frameon=True, ncol=3)
    fig.text(
        0.01,
        0.015,
        "Timeline measured over can0 after CANable restart; labels show request, response, and per-request latency."
        if real_latency
        else "Timeline uses request order from successful can0 hardware CSV artifacts; it is not a latency measurement.",
        fontsize=8,
        color=GRAY,
    )
    fig.tight_layout(rect=[0, 0.04, 1, 0.90])
    return save(fig, "fig12_can0_request_timeline.pdf")


def mutation_category(row: dict[str, str]) -> str:
    if row["valid_attack_shape"] == "true":
        return "valid attack shape"
    if row["gateway_mode"] == "restricted":
        return "gateway restricted"
    if row["session_strategy"] != "extended":
        return "session ordering"
    if row["key_strategy"] != "correct_seed_key":
        return "SecurityAccess key"
    if row["did"] != "0x1234":
        return "DID selection"
    if int(row["data_length"]) < 1 or int(row["data_length"]) > 4:
        return "payload length"
    return "other mutation"


def fig_mutation_breakdown() -> Path:
    rows = [row for row in read_rows(CHARTS / "uds_2e_mutation_attack_detail.csv") if row["profile"] == "before_hotpatch"]
    counts = Counter(mutation_category(row) for row in rows)
    order = [
        "valid attack shape",
        "payload length",
        "SecurityAccess key",
        "DID selection",
        "session ordering",
        "gateway restricted",
        "other mutation",
    ]
    values = [counts[label] for label in order]
    colors = [BLUE, YELLOW, ORANGE, PURPLE, CYAN, RED, GRAY]

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    bars = ax.barh(order[::-1], values[::-1], color=colors[::-1], edgecolor="#303030", linewidth=0.6)
    ax.set_xlabel("Number of cases")
    ax.set_title("Mutation Corpus Composition (1000 Cases)", fontweight="bold")
    ax.grid(axis="x")
    ax.grid(axis="y", visible=False)
    for bar, value in zip(bars, values[::-1]):
        ax.text(value + 8, bar.get_y() + bar.get_height() / 2, str(value), va="center", fontsize=8.5)
    ax.set_xlim(0, max(values) * 1.18)
    return save(fig, "fig06_mutation_corpus_breakdown.pdf")


def pass_count(path: Path) -> tuple[int, int]:
    rows = read_rows(path)
    passed = sum(1 for row in rows if row.get("passed", "").lower() == "true")
    return passed, len(rows)


def fig_hardware_matrix() -> Path:
    entries = [
        ("secure", "strict ECU, permissive gateway", CHARTS / "hardware_secure_security_latest.csv", "19 security checks"),
        ("vulnerable", "0x2E without unlock allowed", CHARTS / "hardware_vulnerable_security_latest.csv", "19 security checks"),
        ("hotpatched", "DID quarantine pre-applied", CHARTS / "hardware_hotpatched_security_latest.csv", "19 security checks"),
        ("kintsugi before", "runtime profile before trigger", CHARTS / "uds_2e_security_access_attack_kintsugi_before_latest.csv", "attack succeeds"),
        ("kintsugi after", "runtime profile after trigger", CHARTS / "uds_2e_security_access_attack_kintsugi_after_latest.csv", "attack blocked"),
    ]
    table_rows = []
    for profile, description, path, evidence in entries:
        passed, total = pass_count(path)
        table_rows.append([profile, description, f"{passed}/{total}", evidence])

    fig, ax = plt.subplots(figsize=(8.8, 3.4))
    ax.set_axis_off()
    ax.set_title("Hardware Validation Matrix", pad=12, fontweight="bold")
    table = ax.table(
        cellText=table_rows,
        colLabels=["Profile", "Expected behavior", "Passed", "Evidence"],
        cellLoc="left",
        colLoc="left",
        loc="center",
        colWidths=[0.17, 0.42, 0.12, 0.25],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.35)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#A0A0A0")
        cell.set_linewidth(0.5)
        if row == 0:
            cell.set_facecolor("#EAF2F8")
            cell.set_text_props(weight="bold")
        elif row % 2 == 0:
            cell.set_facecolor("#F7F7F7")
    return save(fig, "fig07_hardware_validation_matrix.pdf")


def fig_timing_overhead() -> Path:
    rows = read_rows(CHARTS / "timing_metrics_default.csv")
    metrics = {
        row["metric"]: (float(row["vulnerable"]), float(row["patched"]))
        for row in rows
        if row["metric"] in {
            "total_attack_chain_latency_ms",
            "write_handler_latency_ms",
            "periodic_task_jitter_ms",
        }
    }
    labels = ["Attack chain", "0x2E handler", "Periodic jitter"]
    keys = ["total_attack_chain_latency_ms", "write_handler_latency_ms", "periodic_task_jitter_ms"]
    vulnerable = [metrics[key][0] for key in keys]
    patched = [metrics[key][1] for key in keys]
    x = range(len(labels))

    fig, ax = plt.subplots(figsize=(7.0, 4.0))
    width = 0.35
    ax.bar([i - width / 2 for i in x], vulnerable, width, label="Before", color=ORANGE, edgecolor="#303030", linewidth=0.6)
    ax.bar([i + width / 2 for i in x], patched, width, label="After", color=GREEN, edgecolor="#303030", linewidth=0.6)
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("Latency / jitter (ms)")
    ax.set_title("Timing Impact of the Hotpatch Policy", fontweight="bold")
    ax.legend(frameon=True)
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    return save(fig, "fig08_timing_overhead.pdf")


def fig_resource_footprint() -> Path:
    values = read_key_value_csv(CHARTS / "hotpatch_evaluation_default.csv")
    labels = ["Reserved\nmemory", "Peak\nquarantine", "Peak active\ncode"]
    data = [
        values["reserved_memory_bytes"],
        values["peak_quarantine_bytes"],
        values["peak_active_code_bytes"],
    ]

    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    bars = ax.bar(labels, data, color=[BLUE, PURPLE, CYAN], edgecolor="#303030", linewidth=0.8, width=0.55)
    ax.set_ylabel("Bytes")
    ax.set_title("Hotpatch Memory Footprint", fontweight="bold")
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    for bar, value in zip(bars, data):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 18, f"{int(value)} B", ha="center", va="bottom", fontweight="bold")
    ax.set_ylim(0, max(data) * 1.25)
    return save(fig, "fig09_hotpatch_resource_footprint.pdf")


def fig_fleet_exposure() -> Path:
    rows = read_rows(CHARTS / "fleet_metrics_default.csv")
    metrics = {row["metric"]: (float(row["ota_only"]), float(row["hotpatch_first"])) for row in rows}
    labels = ["First\nprotection", "80%\nprotection", "Cumulative\nexposure", "Response\nunavailable"]
    keys = [
        "time_to_first_protection_min",
        "time_to_80_percent_protection_min",
        "cumulative_exposure_window_min",
        "response_unavailable_vehicle_min",
    ]
    ota = [metrics[key][0] for key in keys]
    hotpatch = [metrics[key][1] for key in keys]
    x = range(len(labels))

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    width = 0.35
    ax.bar([i - width / 2 for i in x], ota, width, label="OTA-only", color=ORANGE, edgecolor="#303030", linewidth=0.6)
    ax.bar([i + width / 2 for i in x], hotpatch, width, label="Hotpatch-first", color=GREEN, edgecolor="#303030", linewidth=0.6)
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("Minutes")
    ax.set_yscale("log")
    ax.set_title("Fleet-Level Exposure Reduction Model", fontweight="bold")
    ax.legend(frameon=True)
    ax.grid(axis="y", which="both")
    ax.grid(axis="x", visible=False)
    ax.text(0.02, 0.03, "Log scale used because metrics span from minutes to thousands of minutes.", transform=ax.transAxes, fontsize=8, color=GRAY)
    return save(fig, "fig10_fleet_exposure_reduction.pdf")


def write_manifest(paths: list[Path]) -> Path:
    manifest = ROOT / "thesis_figures" / "FIGURE_MANIFEST_zh.md"
    lines = [
        "# Thesis PDF Figure Manifest",
        "",
        "输出目录：`software level/thesis_figures/pdf/`",
        "",
        "| File | Suggested chapter | Purpose |",
        "|---|---|---|",
        "| `fig01_system_architecture.pdf` | System Design | 总体硬件/软件工作流 |",
        "| `fig02_uds_attack_sequence.pdf` | Threat Model / Attack Design | UDS 0x27 -> 0x2E 攻击链 |",
        "| `fig03_gateway_defense_boundary.pdf` | Design Rationale | gateway 与 ECU-local hotpatch 边界 |",
        "| `fig04_kintsugi_hotpatch_lifecycle.pdf` | Implementation | Kintsugi runtime hotpatch 流程 |",
        "| `fig05_mutation_attack_success_rate.pdf` | Evaluation | hotpatch 前后攻击成功率 |",
        "| `fig06_mutation_corpus_breakdown.pdf` | Evaluation | mutation corpus 组成，解释为何前置成功率不是 100% |",
        "| `fig07_hardware_validation_matrix.pdf` | Evaluation | 硬件 profile 验证矩阵 |",
        "| `fig08_timing_overhead.pdf` | Evaluation | latency / jitter 开销 |",
        "| `fig09_hotpatch_resource_footprint.pdf` | Evaluation | hotpatch 内存资源占用 |",
        "| `fig10_fleet_exposure_reduction.pdf` | Discussion / Evaluation | fleet-level exposure model |",
        "| `fig11_control_group_success_rates.pdf` | Evaluation | 普通诊断请求对照组与攻击 mutation 对比 |",
        "| `fig12_can0_request_timeline.pdf` | Evaluation | can0 硬件 artifact 的请求-响应时间轴 |",
        "",
        "Note: `fig12_can0_request_timeline.pdf` is generated from the successful",
        "`uds_2e_security_access_attack_kintsugi_before_latest.csv` and",
        "`uds_2e_security_access_attack_kintsugi_after_latest.csv` hardware artifacts.",
        "It is a request-order timeline, not a real latency measurement. The optional",
        "`measure_can0_request_timeline.py` tool can collect real can0 timing when the",
        "board is responding on `0x7E8`.",
        "",
        "LaTeX 示例：",
        "",
        "```latex",
        r"\includegraphics[width=0.92\linewidth]{\detokenize{software level/thesis_figures/pdf/fig05_mutation_attack_success_rate.pdf}}",
        "```",
        "",
        "Generated files:",
        "",
    ]
    lines.extend(f"- `{path.name}`" for path in paths)
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    apply_style()
    paths = [
        fig_system_architecture(),
        fig_attack_sequence(),
        fig_gateway_defense_boundary(),
        fig_kintsugi_lifecycle(),
        fig_mutation_success_rate(),
        fig_mutation_breakdown(),
        fig_hardware_matrix(),
        fig_timing_overhead(),
        fig_resource_footprint(),
        fig_fleet_exposure(),
        fig_control_group_success_rates(),
        fig_request_response_timeline(),
    ]
    manifest = write_manifest(paths)
    for path in paths:
        print(path)
    print(manifest)


if __name__ == "__main__":
    sys.exit(main())
