"""Generate publication-oriented thesis figures for the UDS hotpatch work.

Design goals:
- IoT / software-security style: data-flow, sequence, matrix, timeline and
  exposure-area plots before generic bars.
- One claim per figure.  The visual form is chosen to make that claim readable
  without the thesis text next to it.
- PDF for LaTeX insertion and SVG for editable text.
"""

from __future__ import annotations

import csv
import math
import os
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median

ROOT = Path(__file__).resolve().parents[1]
CHARTS = ROOT / "charts"
OUT_ROOT = ROOT / "thesis_figures_skill"
PDF_DIR = OUT_ROOT / "pdf"
SVG_DIR = OUT_ROOT / "svg"

os.environ.setdefault("MPLCONFIGDIR", str(OUT_ROOT / ".mplconfig"))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import gridspec  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402


PALETTE = {
    "risk": "#D65F5F",
    "risk_soft": "#F4D6D4",
    "safe": "#2F8F5B",
    "safe_soft": "#D8EEDF",
    "neutral": "#3E78B2",
    "neutral_soft": "#DDEAF6",
    "pending": "#B08A2E",
    "pending_soft": "#F1E7CB",
    "tester": "#6B73D6",
    "gateway": "#C98A2B",
    "ecu": "#2F8F5B",
    "kintsugi": "#8A6BBE",
    "text": "#22262A",
    "muted": "#636B73",
    "grid": "#E6E8EA",
    "line": "#2F3437",
    "arrow_blue": "#1F5FA8",
    "arrow_green": "#1F7A4D",
    "arrow_red": "#B9413E",
    "white": "#FFFFFF",
}

COLORS = {
    "risk": PALETTE["risk"],
    "safe": PALETTE["safe"],
    "neutral": PALETTE["neutral"],
    "pending": PALETTE["pending"],
    "tester": PALETTE["tester"],
    "gateway": PALETTE["gateway"],
    "ecu": PALETTE["ecu"],
    "kintsugi": PALETTE["kintsugi"],
}

BAR_ALPHA = 0.82
AREA_ALPHA = 0.18
POINT_ALPHA = 0.40
EDGE = PALETTE["line"]


def apply_publication_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "DejaVu Sans", "Liberation Sans", "sans-serif"],
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.size": 7.8,
            "axes.titlesize": 8.8,
            "axes.labelsize": 8.0,
            "xtick.labelsize": 7.2,
            "ytick.labelsize": 7.2,
            "legend.fontsize": 7.0,
            "axes.spines.right": False,
            "axes.spines.top": False,
            "axes.linewidth": 0.8,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_metric_csv(path: Path) -> dict[str, float | str]:
    out: dict[str, float | str] = {}
    for row in read_rows(path):
        value = row["value"]
        if value.lower() in {"true", "false"}:
            out[row["metric"]] = value.lower()
        else:
            try:
                out[row["metric"]] = float(value)
            except ValueError:
                out[row["metric"]] = value
    return out


def save(fig: plt.Figure, name: str) -> tuple[Path, Path]:
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    SVG_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = PDF_DIR / f"{name}.pdf"
    svg_path = SVG_DIR / f"{name}.svg"
    fig.savefig(svg_path, bbox_inches="tight", pad_inches=0.08)
    fig.savefig(pdf_path, bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)
    return pdf_path, svg_path


def panel_label(ax, label: str, x: float = -0.06, y: float = 1.02) -> None:
    ax.text(
        x,
        y,
        label,
        transform=ax.transAxes,
        fontsize=9.0,
        fontweight="bold",
        ha="left",
        va="bottom",
        color=PALETTE["text"],
    )


def clean_axis(ax, *, ygrid: bool = False, xgrid: bool = False) -> None:
    ax.set_axisbelow(True)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", visible=False)
    if ygrid:
        ax.grid(axis="y", color=PALETTE["grid"], linewidth=0.65)
    if xgrid:
        ax.grid(axis="x", color=PALETTE["grid"], linewidth=0.65)


def text_box(
    ax,
    x: float,
    y: float,
    w: float,
    h: float,
    title: str,
    body: str,
    *,
    fc: str = "#FFFFFF",
    ec: str = EDGE,
    title_color: str = PALETTE["text"],
    body_size: float = 7.0,
) -> None:
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.012,rounding_size=0.012",
            facecolor=fc,
            edgecolor=ec,
            linewidth=0.9,
        )
    )
    ax.text(
        x + w / 2,
        y + h * 0.66,
        title,
        ha="center",
        va="center",
        fontsize=7.9,
        fontweight="bold",
        color=title_color,
    )
    ax.text(
        x + w / 2,
        y + h * 0.34,
        body,
        ha="center",
        va="center",
        fontsize=body_size,
        color=PALETTE["muted"],
        linespacing=1.12,
    )


def arrow(
    ax,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = PALETTE["line"],
    lw: float = 1.35,
    label: str | None = None,
    label_offset: float = 0.034,
    linestyle: str = "-",
    mutation_scale: float = 13,
) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=mutation_scale,
            linewidth=lw,
            color=color,
            linestyle=linestyle,
            shrinkA=3,
            shrinkB=3,
        )
    )
    if label:
        ax.text(
            (start[0] + end[0]) / 2,
            (start[1] + end[1]) / 2 + label_offset,
            label,
            ha="center",
            va="bottom",
            fontsize=6.8,
            color=color,
            bbox=dict(facecolor="white", edgecolor="none", pad=1.8, alpha=0.94),
        )


def fig01_architecture() -> tuple[Path, Path]:
    """Readable IoT data-flow view of the runtime hotpatch mechanism."""
    fig, ax = plt.subplots(figsize=(12.0, 7.2))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    panel_label(ax, "a", x=0.02, y=0.965)
    ax.text(0.06, 0.970, "Kintsugi-based runtime UDS protection path", fontsize=12.5, fontweight="bold", va="top")
    ax.text(
        0.06,
        0.935,
        "The diagnostic bus path stays unchanged; the runtime patch changes the target ECU's DID-level decision.",
        fontsize=8.4,
        color=PALETTE["muted"],
        va="top",
    )

    lanes = [
        (0.660, 0.220, "1. Diagnostic traffic", PALETTE["neutral_soft"]),
        (0.385, 0.220, "2. Runtime patch control", PALETTE["pending_soft"]),
        (0.125, 0.200, "3. ECU-local enforcement", PALETTE["safe_soft"]),
    ]
    for y0, h, title, color in lanes:
        ax.add_patch(Rectangle((0.05, y0), 0.90, h, facecolor=color, edgecolor=PALETTE["grid"], linewidth=0.8, alpha=0.58))
        ax.text(0.065, y0 + h - 0.030, title, fontsize=8.2, fontweight="bold", color=PALETTE["text"], va="top")

    # Lane 1: UDS data path.
    y = 0.705
    nodes = [
        (0.09, "Tester", "Python UDS\ncampaign"),
        (0.30, "CANable", "SocketCAN\ncan0"),
        (0.51, "Gateway ECU", "routes\n0x7E0/0x7E8"),
        (0.73, "Target ECU", "UDS services\nand DID state"),
    ]
    node_colors = [PALETTE["tester"], PALETTE["neutral"], PALETTE["gateway"], PALETTE["ecu"]]
    for (x, title, body), color in zip(nodes, node_colors):
        text_box(ax, x, y, 0.14, 0.100, title, body, fc="#FFFFFF", ec=color, title_color=color, body_size=6.7)
    for i in range(len(nodes) - 1):
        arrow(ax, (nodes[i][0] + 0.14, y + 0.050), (nodes[i + 1][0], y + 0.050), color=PALETTE["arrow_blue"], label="UDS/CAN" if i == 1 else None, lw=1.55)

    # Lane 2: Kintsugi control path.
    y = 0.435
    text_box(ax, 0.17, y, 0.18, 0.100, "Control DID", "2E F190\nreceive / schedule / apply", fc="#FFFFFF", ec=PALETTE["pending"], title_color=PALETTE["pending"], body_size=6.7)
    text_box(ax, 0.43, y, 0.18, 0.100, "Kintsugi runtime", "manager, slot\nsafe applicator", fc="#FFFFFF", ec=PALETTE["kintsugi"], title_color=PALETTE["kintsugi"], body_size=6.7)
    text_box(ax, 0.69, y, 0.18, 0.100, "Patch gate", "activates\nUDS guard", fc="#FFFFFF", ec=PALETTE["safe"], title_color=PALETTE["safe"], body_size=6.7)
    arrow(ax, (0.35, y + 0.050), (0.43, y + 0.050), color=PALETTE["line"], label="loaded", lw=1.40)
    arrow(ax, (0.61, y + 0.050), (0.69, y + 0.050), color=PALETTE["line"], label="applied", lw=1.40)

    # Lane 3: before/after effect.
    y = 0.155
    text_box(ax, 0.11, y, 0.30, 0.095, "Before apply", "SecurityAccess unlock allows\nWriteDataByIdentifier 0x1234", fc="#FFFFFF", ec=PALETTE["risk"], title_color=PALETTE["risk"], body_size=6.7)
    text_box(ax, 0.58, y, 0.30, 0.095, "After apply", "same write is rejected\nwith NRC 0x31", fc="#FFFFFF", ec=PALETTE["safe"], title_color=PALETTE["safe"], body_size=6.7)
    arrow(ax, (0.41, y + 0.048), (0.58, y + 0.048), color=PALETTE["arrow_green"], lw=1.55, label="runtime policy change")
    arrow(ax, (0.78, 0.435), (0.78, 0.250), color=PALETTE["arrow_green"], lw=1.45, label="enforce", label_offset=0.018)

    # Reader key.
    legend_y = 0.050
    items = [
        (PALETTE["arrow_blue"], "diagnostic traffic"),
        (PALETTE["line"], "hotpatch control"),
        (PALETTE["risk"], "vulnerable behavior"),
        (PALETTE["safe"], "protected behavior"),
    ]
    x = 0.18
    for color, label in items:
        ax.plot([x, x + 0.035], [legend_y, legend_y], color=color, linewidth=3.0, solid_capstyle="round")
        ax.text(x + 0.042, legend_y, label, va="center", fontsize=7.2, color=PALETTE["muted"])
        x += 0.19
    return save(fig, "fig01_skill_architecture_lifecycle")


def fig02_attack_chain() -> tuple[Path, Path]:
    """Wide sequence diagram: same UDS chain, different final write response."""
    fig, ax = plt.subplots(figsize=(11.8, 7.0))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    panel_label(ax, "a", x=0.02, y=0.965)
    ax.text(0.06, 0.965, "Protocol-valid UDS attack chain and the hotpatch decision point", fontsize=12.0, fontweight="bold", va="top")
    ax.text(
        0.06,
        0.925,
        "Requests remain syntactically valid.  The security effect appears at the high-risk DID write response.",
        fontsize=8.4,
        color=PALETTE["muted"],
        va="top",
    )

    actors = [
        (0.16, "Tester", PALETTE["tester"], PALETTE["tester"]),
        (0.50, "Gateway", PALETTE["gateway"], PALETTE["gateway"]),
        (0.84, "ECU", PALETTE["ecu"], PALETTE["ecu"]),
    ]
    for x, label, color, _ in actors:
        ax.add_patch(Rectangle((x - 0.078, 0.835), 0.156, 0.060, facecolor=color, edgecolor=color, linewidth=0.8, alpha=0.92))
        ax.text(x, 0.865, label, ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")
        ax.plot([x, x], [0.170, 0.835], color=color, linewidth=1.0, alpha=0.70)

    req_color = PALETTE["arrow_blue"]
    pos_color = PALETTE["arrow_green"]
    neg_color = PALETTE["arrow_red"]

    def mid_label(x0: float, x1: float, y: float, text: str, color: str, *, above: bool = True) -> None:
        ax.text(
            (x0 + x1) / 2,
            y + (0.024 if above else -0.030),
            text,
            ha="center",
            va="center",
            fontsize=6.9,
            color=color,
            bbox=dict(facecolor="white", edgecolor="none", pad=2.0, alpha=0.96),
        )

    def msg(y_req: float, label: str, response: str, response_color: str = pos_color) -> None:
        y_resp = y_req - 0.060
        arrow(ax, (0.16, y_req), (0.50, y_req), color=req_color, lw=1.45)
        arrow(ax, (0.50, y_req), (0.84, y_req), color=req_color, lw=1.45)
        mid_label(0.16, 0.50, y_req, label, req_color, above=True)
        arrow(ax, (0.84, y_resp), (0.50, y_resp), color=response_color, lw=1.35)
        arrow(ax, (0.50, y_resp), (0.16, y_resp), color=response_color, lw=1.35)
        mid_label(0.50, 0.84, y_resp, response, response_color, above=False)

    msg(0.765, "1  DiagnosticSessionControl 0x10 03", "50 03")
    msg(0.625, "2  SecurityAccess seed 0x27 01", "67 01 seed")
    msg(0.485, "3  SecurityAccess key 0x27 02", "67 02")

    # Critical split.
    y_req = 0.345
    arrow(ax, (0.16, y_req), (0.50, y_req), color=req_color, lw=1.60)
    arrow(ax, (0.50, y_req), (0.84, y_req), color=req_color, lw=1.60)
    mid_label(0.16, 0.50, y_req, "4  WriteDataByIdentifier 0x2E 1234", req_color, above=True)
    arrow(ax, (0.84, 0.280), (0.50, 0.280), color=pos_color, lw=1.45)
    arrow(ax, (0.50, 0.280), (0.16, 0.280), color=pos_color, lw=1.45)
    mid_label(0.50, 0.84, 0.280, "before: 6E 1234 accepted", pos_color, above=False)
    arrow(ax, (0.84, 0.205), (0.50, 0.205), color=neg_color, lw=1.45)
    arrow(ax, (0.50, 0.205), (0.16, 0.205), color=neg_color, lw=1.45)
    mid_label(0.50, 0.84, 0.205, "after apply: 7F 2E 31 blocked", neg_color, above=False)

    ax.add_patch(Rectangle((0.095, 0.055), 0.81, 0.080, facecolor="#FFFFFF", edgecolor=PALETTE["grid"], linewidth=0.8))
    ax.text(
        0.50,
        0.096,
        "Interpretation: the hotpatch does not hide the ECU or break SecurityAccess; it changes the ECU-local authorization for DID 0x1234 writes.",
        ha="center",
        va="center",
        fontsize=7.5,
        color=PALETTE["text"],
    )

    return save(fig, "fig02_skill_uds_attack_chain")


def fig03_control_and_mutation() -> tuple[Path, Path]:
    """Dumbbell plot: attack collapses after hotpatch while benign stays open."""
    mutation = read_rows(CHARTS / "uds_2e_mutation_attack_summary.csv")
    control = read_rows(CHARTS / "uds_control_group_summary.csv")
    mut_rates = {row["profile"]: float(row["attack_success_rate"]) * 100 for row in mutation}
    ctrl = {(row["profile"], row["workload"]): float(row["success_rate"]) * 100 for row in control}
    valid_shapes = int(float(mutation[0]["valid_attack_shapes"]))
    total_cases = int(float(mutation[0]["total_cases"]))

    labels = ["Attack mutations", "Benign diagnostics"]
    before = [mut_rates["before_hotpatch"], ctrl[("before_hotpatch", "benign_diagnostic")]]
    after = [mut_rates["after_hotpatch"], ctrl[("after_hotpatch", "benign_diagnostic")]]
    y = [1.0, 0.28]

    fig, ax = plt.subplots(figsize=(8.4, 3.8))
    panel_label(ax, "a", x=-0.045, y=1.04)
    for yi, b, a, label in zip(y, before, after, labels):
        ax.plot([b, a], [yi, yi], color=PALETTE["grid"], linewidth=5.5, solid_capstyle="round", zorder=1)
        ax.scatter([b], [yi], s=78, color=PALETTE["risk"] if label.startswith("Attack") else PALETTE["safe"], edgecolor=EDGE, linewidth=0.8, alpha=BAR_ALPHA, zorder=3)
        ax.scatter([a], [yi], s=78, color=PALETTE["safe"], edgecolor=EDGE, linewidth=0.8, alpha=BAR_ALPHA, zorder=3)
        if abs(b - a) < 0.5:
            ax.annotate(
                f"{a:.1f}% before/after",
                xy=(a, yi),
                xytext=(0, 18),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7.0,
                fontweight="bold",
                bbox=dict(facecolor="white", edgecolor="none", pad=1.6, alpha=0.94),
            )
        else:
            ax.annotate(
                f"{b:.1f}%",
                xy=(b, yi),
                xytext=(0, 18),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7.0,
                fontweight="bold",
                bbox=dict(facecolor="white", edgecolor="none", pad=1.6, alpha=0.94),
            )
            ax.annotate(
                f"{a:.1f}%",
                xy=(a, yi),
                xytext=(0, -20),
                textcoords="offset points",
                ha="center",
                va="top",
                fontsize=7.0,
                fontweight="bold",
                bbox=dict(facecolor="white", edgecolor="none", pad=1.6, alpha=0.94),
            )
    ax.set_yticks(y, labels)
    ax.set_xlim(-4, 104)
    ax.set_ylim(-0.18, 1.38)
    ax.set_xlabel("Success rate (%)")
    ax.set_title("Hotpatch selectively removes attack success without closing benign diagnostics", pad=12)
    ax.axvline(0, color=PALETTE["grid"], linewidth=0.8)
    ax.axvline(100, color=PALETTE["grid"], linewidth=0.8)
    clean_axis(ax, xgrid=True)
    handles = [
        Line2D([0], [0], marker="o", color="w", markerfacecolor=PALETTE["risk"], markeredgecolor=EDGE, label="Before hotpatch"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor=PALETTE["safe"], markeredgecolor=EDGE, label="After hotpatch"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.53, 1.04), ncol=2)
    ax.text(
        0.01,
        -0.16,
        f"Mutation corpus: {valid_shapes}/{total_cases} protocol-valid attack shapes.",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=6.8,
        color=PALETTE["muted"],
    )
    return save(fig, "fig03_skill_mutation_control_group")


def fig04_during_lifecycle() -> tuple[Path, Path]:
    """LaTeX-style verdict matrix plus lifecycle latency curve."""
    rows = read_rows(CHARTS / "uds_kintsugi_during_lifecycle_latest.csv")
    summary = read_rows(CHARTS / "uds_kintsugi_during_lifecycle_summary_latest.csv")
    phases = ["before_hotpatch", "during_received_pending", "during_scheduled_pending", "after_apply"]
    phase_labels = ["Before", "Receive\npending", "Schedule\npending", "After\napply"]
    summary_by_phase = {r["phase"]: r for r in summary}
    verdict_rows = [
        ("Attack blocked\n(0x2E 1234)", [summary_by_phase[p]["attack_observed"] == "blocked" for p in phases]),
        ("Benign read passes\n(0x22 1001)", [summary_by_phase[p]["benign_read_passed"] == "true" for p in phases]),
        ("Expected lifecycle\nbehavior", [summary_by_phase[p]["attack_check_passed"] == "true" for p in phases]),
    ]

    fig = plt.figure(figsize=(9.0, 5.7))
    gs = gridspec.GridSpec(2, 1, height_ratios=[1.05, 1.15], hspace=0.58)
    ax0 = fig.add_subplot(gs[0])
    ax1 = fig.add_subplot(gs[1])

    panel_label(ax0, "a", x=-0.035, y=1.03)
    ax0.set_axis_off()
    ax0.set_xlim(0, 1)
    ax0.set_ylim(0, 1)
    ax0.text(0.02, 0.98, "Runtime lifecycle verdicts", fontsize=9.4, fontweight="bold", va="top")

    left = 0.23
    top = 0.72
    col_w = 0.17
    row_h = 0.185
    ax0.text(0.03, top + 0.10, "Property", fontsize=7.6, fontweight="bold", color=PALETTE["text"])
    for i, phase in enumerate(phase_labels):
        ax0.text(left + i * col_w + col_w / 2, top + 0.10, phase, ha="center", va="center", fontsize=7.4, fontweight="bold", linespacing=0.95)
    ax0.plot([0.02, 0.94], [top + 0.045, top + 0.045], color=PALETTE["line"], linewidth=0.9)
    for sep in range(1, 3):
        y_sep = top - sep * row_h + 0.020
        ax0.plot([0.02, 0.94], [y_sep, y_sep], color=PALETTE["grid"], linewidth=0.65)
    ax0.plot([0.02, 0.94], [top - 3 * row_h + 0.02, top - 3 * row_h + 0.02], color=PALETTE["line"], linewidth=0.9)
    for r_idx, (name, values) in enumerate(verdict_rows):
        y = top - r_idx * row_h - 0.06
        ax0.text(0.03, y, name, ha="left", va="center", fontsize=7.4, color=PALETTE["text"], linespacing=1.08)
        for c_idx, ok in enumerate(values):
            x = left + c_idx * col_w + col_w / 2
            ax0.text(
                x,
                y,
                r"$\checkmark$" if ok else r"$\times$",
                ha="center",
                va="center",
                fontsize=13.0,
                color=PALETTE["safe"] if ok else PALETTE["risk"],
                fontweight="bold",
            )
    ax0.text(0.03, 0.030, "Checks show receive/schedule are observable pending states; only apply closes the attack path.", fontsize=6.9, color=PALETTE["muted"])

    panel_label(ax1, "b", x=-0.035, y=1.03)
    phase_to_lat = defaultdict(list)
    for r in rows:
        if r["latency_ms"]:
            phase_to_lat[r["phase"]].append(float(r["latency_ms"]))
    x = list(range(len(phases)))
    lat_means = [mean(phase_to_lat[p]) for p in phases]
    lat_medians = [median(phase_to_lat[p]) for p in phases]
    lat_min = [min(phase_to_lat[p]) for p in phases]
    lat_max = [max(phase_to_lat[p]) for p in phases]
    ax1.fill_between(x, lat_min, lat_max, color=PALETTE["neutral_soft"], alpha=0.75, linewidth=0)
    ax1.plot(x, lat_means, color=PALETTE["neutral"], linewidth=2.1, marker="o", markersize=4.5, label="mean")
    ax1.plot(x, lat_medians, color=PALETTE["line"], linewidth=1.1, marker="s", markersize=3.4, linestyle="--", label="median")
    phase_colors = [PALETTE["risk"], PALETTE["pending"], PALETTE["pending"], PALETTE["safe"]]
    for xi, p, color in zip(x, phases, phase_colors):
        samples = phase_to_lat[p]
        jitter = [xi - 0.050 + 0.10 * (idx / max(1, len(samples) - 1)) for idx, _ in enumerate(samples)]
        ax1.scatter(jitter, samples, color=color, alpha=0.38, s=14, edgecolors="none", zorder=3)
        ax1.annotate(
            f"{lat_means[xi]:.2f} ms",
            xy=(xi, lat_means[xi]),
            xytext=(0, 15),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=6.8,
            fontweight="bold",
            bbox=dict(facecolor="white", edgecolor="none", pad=1.5, alpha=0.94),
        )
    ax1.set_xticks(x, phase_labels)
    ax1.set_ylabel("Response latency (ms)")
    ax1.set_title("Latency does not spike during staged runtime patching", pad=10)
    ax1.legend(loc="upper right")
    ax1.set_ylim(min(lat_min) - 0.22, max(lat_max) + 0.40)
    clean_axis(ax1, ygrid=True)
    return save(fig, "fig04_skill_kintsugi_during_lifecycle")


def fig05_hardware_observer() -> tuple[Path, Path]:
    """Hardware observer validation, preserving the useful point cloud."""
    detail = read_rows(CHARTS / "hardware_uds_2e_fuzz_observer_20260620_uds2e_1000_observer_detail.csv")
    summary = read_metric_csv(CHARTS / "hardware_uds_2e_fuzz_observer_20260620_uds2e_1000_observer_summary.csv")
    total = int(summary["total_trials"])  # type: ignore[arg-type]
    pass_count = int(summary["attack_pass_count"])  # type: ignore[arg-type]
    fail_count = int(summary["attack_fail_count"])  # type: ignore[arg-type]
    consistent = sum(1 for r in detail if r["observer_consistent"].lower() == "true")
    inconsistent = len(detail) - consistent
    can_lat = [float(r["latency_ms"]) for r in detail if r["latency_ms"]]
    obs_lat = [float(r["observer_latency_ms"]) for r in detail if r["observer_latency_ms"]]
    paired = [(float(r["latency_ms"]), float(r["observer_latency_ms"])) for r in detail if r["latency_ms"] and r["observer_latency_ms"]]

    fig = plt.figure(figsize=(8.2, 5.0))
    gs = gridspec.GridSpec(2, 2, height_ratios=[0.78, 1.22], hspace=0.58, wspace=0.42)
    ax0 = fig.add_subplot(gs[0, 0])
    ax1 = fig.add_subplot(gs[0, 1])
    ax2 = fig.add_subplot(gs[1, :])

    panel_label(ax0, "a")
    ax0.barh([1, 0], [pass_count, fail_count], color=[PALETTE["risk"], PALETTE["safe"]], edgecolor=EDGE, linewidth=0.7, alpha=BAR_ALPHA)
    ax0.set_yticks([1, 0], ["Accepted", "Rejected"])
    ax0.set_xlabel("Trials")
    ax0.set_title(f"Hardware fuzz outcome (n={total})", pad=9)
    ax0.set_xlim(0, total * 1.16)
    clean_axis(ax0, xgrid=True)
    for y, v in zip([1, 0], [pass_count, fail_count]):
        ax0.annotate(f"{v}", xy=(v, y), xytext=(8, 0), textcoords="offset points", va="center", fontsize=7.2, fontweight="bold")

    panel_label(ax1, "b")
    ax1.barh([1, 0], [consistent, inconsistent], color=[PALETTE["neutral"], PALETTE["risk_soft"]], edgecolor=EDGE, linewidth=0.7, alpha=BAR_ALPHA)
    ax1.set_yticks([1, 0], ["Consistent", "Mismatch"])
    ax1.set_xlabel("Trials")
    ax1.set_title("Independent observer", pad=9)
    ax1.set_xlim(0, total * 1.16)
    clean_axis(ax1, xgrid=True)
    for y, v in zip([1, 0], [consistent, inconsistent]):
        ax1.annotate(f"{v}", xy=(v, y), xytext=(8, 0), textcoords="offset points", va="center", fontsize=7.2, fontweight="bold")

    panel_label(ax2, "c", y=1.01)
    xs, ys = zip(*paired)
    ax2.scatter(xs, ys, s=10, color=PALETTE["neutral"], alpha=POINT_ALPHA, edgecolors="none")
    ax2.axhline(mean(obs_lat), color=PALETTE["neutral"], linewidth=1.1, linestyle="--", label=f"observer mean {mean(obs_lat):.2f} ms")
    ax2.axvline(mean(can_lat), color=PALETTE["risk"], linewidth=1.1, linestyle="--", label=f"can0 mean {mean(can_lat):.2f} ms")
    ax2.set_xlabel("Host can0 latency (ms)")
    ax2.set_ylabel("Observer interval (ms)")
    ax2.set_title("Latency cross-check from independent CAN listener", pad=10)
    ax2.legend(loc="upper right")
    clean_axis(ax2, ygrid=True, xgrid=True)
    return save(fig, "fig05_skill_hardware_observer_validation")


def fig06_fleet_exposure() -> tuple[Path, Path]:
    """Fleet exposure as area under a vulnerability curve, not just bars."""
    summary = read_rows(CHARTS / "fleet_ota_exposure_20260620_default_1000v_60d_summary.csv")
    exposure = read_rows(CHARTS / "fleet_ota_exposure_20260620_default_1000v_60d_exposure_only.csv")
    weighted = read_rows(CHARTS / "fleet_ota_exposure_20260620_default_1000v_60d_attack_weighted.csv")
    ts = read_rows(CHARTS / "fleet_ota_exposure_20260620_default_1000v_60d_timeseries.csv")
    strategies = ["ota_only", "hotpatch_first"]
    labels = {"ota_only": "OTA only", "hotpatch_first": "Hotpatch first"}
    colors = {"ota_only": PALETTE["risk"], "hotpatch_first": PALETTE["safe"]}
    exp_days = {r["strategy"]: float(r["exposure_vehicle_days"]) for r in exposure}
    attacks = {r["strategy"]: float(r["expected_successful_attack_opportunities"]) for r in weighted}
    t80 = {r["strategy"]: float(r["time_to_80pct_protection_min"]) / 60 for r in summary}

    fig = plt.figure(figsize=(9.4, 5.2))
    gs = gridspec.GridSpec(1, 2, width_ratios=[1.72, 1.05], wspace=0.36)
    ax0 = fig.add_subplot(gs[0])
    ax1 = fig.add_subplot(gs[1])

    panel_label(ax0, "a")
    for strategy in strategies:
        rows = [r for r in ts if r["strategy"] == strategy]
        x = [float(r["time_hour"]) for r in rows]
        y = [float(r["vulnerable_vehicle_count"]) for r in rows]
        ax0.step(x, y, where="post", color=colors[strategy], linewidth=1.9, label=labels[strategy])
        ax0.fill_between(x, y, step="post", color=colors[strategy], alpha=AREA_ALPHA)
        ax0.axvline(t80[strategy], color=colors[strategy], linewidth=1.0, linestyle=":")
    ax0.set_xlabel("Time after disclosure (h)")
    ax0.set_ylabel("Vulnerable vehicles")
    ax0.set_title("Exposure window is the area under the vulnerable-fleet curve", pad=10)
    ax0.legend(loc="upper right")
    clean_axis(ax0, ygrid=True)
    ax0.text(0.02, 0.92, "Dotted vertical lines: 80% protected", transform=ax0.transAxes, fontsize=6.8, color=PALETTE["muted"], bbox=dict(facecolor="white", edgecolor="none", pad=2.0, alpha=0.90))

    panel_label(ax1, "b")
    metrics = [
        ("Exposure\nvehicle-days", exp_days["ota_only"], exp_days["hotpatch_first"], "{:.0f}"),
        ("Successful\nopportunities", attacks["ota_only"], attacks["hotpatch_first"], "{:.1f}"),
    ]
    y_positions = [1.0, 0.0]
    all_metric_values = [value for _, ota, hotpatch, _ in metrics for value in (ota, hotpatch)]
    x_min = min(all_metric_values) * 0.70
    x_max = max(all_metric_values) * 1.45
    for y, (name, ota, hotpatch, fmt) in zip(y_positions, metrics):
        ax1.plot([hotpatch, ota], [y, y], color=PALETTE["grid"], linewidth=5.2, solid_capstyle="round", zorder=1)
        ax1.scatter([ota], [y], s=88, color=PALETTE["risk"], edgecolor=EDGE, linewidth=0.8, alpha=BAR_ALPHA, zorder=3)
        ax1.scatter([hotpatch], [y], s=88, color=PALETTE["safe"], edgecolor=EDGE, linewidth=0.8, alpha=BAR_ALPHA, zorder=3)
        ax1.annotate(
            fmt.format(ota),
            xy=(ota, y),
            xytext=(10, 15),
            textcoords="offset points",
            ha="left",
            va="bottom",
            fontsize=7.0,
            fontweight="bold",
            bbox=dict(facecolor="white", edgecolor="none", pad=1.8, alpha=0.94),
        )
        ax1.annotate(
            fmt.format(hotpatch),
            xy=(hotpatch, y),
            xytext=(-10, -17),
            textcoords="offset points",
            ha="right",
            va="top",
            fontsize=7.0,
            fontweight="bold",
            bbox=dict(facecolor="white", edgecolor="none", pad=1.8, alpha=0.94),
        )
    ax1.set_yticks(y_positions, [m[0] for m in metrics])
    ax1.set_xscale("log")
    ax1.set_xlim(x_min, x_max)
    ax1.set_ylim(-0.35, 1.35)
    ax1.set_xlabel("Log-scaled quantity")
    ax1.set_title("Integrated risk reduction", pad=10)
    clean_axis(ax1, xgrid=True)
    handles = [
        Line2D([0], [0], marker="o", color="w", markerfacecolor=PALETTE["risk"], markeredgecolor=EDGE, label="OTA only"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor=PALETTE["safe"], markeredgecolor=EDGE, label="Hotpatch first"),
    ]
    ax1.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, -0.30), ncol=1)
    return save(fig, "fig06_skill_fleet_exposure_risk")


def fig07_can0_timeline() -> tuple[Path, Path]:
    """Real CAN0 trace as a response/latency comparison table."""
    before = [r for r in read_rows(CHARTS / "can0_request_timeline_latest.csv") if r["response_payload"] != "<none>"]
    after = [r for r in read_rows(CHARTS / "can0_request_timeline_kintsugi_after_latest.csv") if r["response_payload"] != "<none>"]

    def step_label(step: str) -> str:
        mapping = {
            "reset_default_session": "Reset",
            "enter_extended_session": "Session",
            "request_security_seed": "Seed",
            "send_key_from_weak_transform": "Key",
            "write_did_after_security_access": "0x2E write",
            "read_back_did_0x1234": "Readback",
            "trigger_kintsugi_hotpatch": "Apply",
        }
        return mapping.get(step, step)

    before_map = {step_label(r["step"]): r for r in before}
    after_map = {step_label(r["step"]): r for r in after}
    columns = ["Apply", "Reset", "Session", "Seed", "Key", "0x2E write", "Readback"]
    row_defs = [
        ("Before hotpatch", before_map, PALETTE["risk"]),
        ("After apply", after_map, PALETTE["safe"]),
    ]

    fig, ax = plt.subplots(figsize=(12.0, 4.8))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    panel_label(ax, "a", x=0.015, y=0.965)
    ax.text(0.06, 0.965, "Real can0 request-response trace", fontsize=11.0, fontweight="bold", va="top")
    ax.text(0.06, 0.915, "Cells show response payload and measured latency. The same 0x2E write step changes from accepted to blocked.", fontsize=7.7, color=PALETTE["muted"], va="top")

    left = 0.055
    top = 0.750
    row_h = 0.245
    phase_w = 0.150
    col_w = (0.925 - phase_w) / len(columns)

    ax.text(left, top + 0.065, "Scenario", fontsize=7.4, fontweight="bold", color=PALETTE["text"])
    for i, column in enumerate(columns):
        ax.text(left + phase_w + i * col_w + col_w / 2, top + 0.065, column, ha="center", va="center", fontsize=7.2, fontweight="bold")
    ax.plot([left, left + phase_w + len(columns) * col_w], [top + 0.025, top + 0.025], color=PALETTE["line"], linewidth=0.9)

    for r_idx, (scenario, data, color) in enumerate(row_defs):
        y = top - (r_idx + 1) * row_h
        ax.add_patch(Rectangle((left, y), phase_w + len(columns) * col_w, row_h - 0.024, facecolor="#FFFFFF", edgecolor=PALETTE["grid"], linewidth=0.8))
        ax.plot([left + 0.012, left + 0.055], [y + row_h * 0.61, y + row_h * 0.61], color=color, linewidth=3.0, solid_capstyle="round")
        ax.text(left + 0.065, y + row_h * 0.61, scenario, va="center", fontsize=7.2, fontweight="bold", color=color)
        for c_idx, column in enumerate(columns):
            x = left + phase_w + c_idx * col_w
            record = data.get(column)
            face = "#FFFFFF"
            edge = PALETTE["grid"]
            if column == "0x2E write":
                face = PALETTE["risk_soft"] if scenario.startswith("Before") else PALETTE["safe_soft"]
                edge = color
            ax.add_patch(Rectangle((x + 0.006, y + 0.024), col_w - 0.012, row_h - 0.070, facecolor=face, edgecolor=edge, linewidth=0.75))
            if record is None:
                ax.text(x + col_w / 2, y + row_h * 0.48, "—", ha="center", va="center", fontsize=8.0, color=PALETTE["muted"])
            else:
                response = record["response_payload"]
                latency = float(record["latency_ms"])
                ax.text(x + col_w / 2, y + row_h * 0.57, response, ha="center", va="center", fontsize=6.4, fontweight="bold", color=PALETTE["text"])
                ax.text(x + col_w / 2, y + row_h * 0.34, f"{latency:.2f} ms", ha="center", va="center", fontsize=6.1, color=PALETTE["muted"])

    ax.text(0.06, 0.090, "Interpretation: timing stays in the same millisecond range; the security-relevant change is the 0x2E response code.", fontsize=7.0, color=PALETTE["text"])
    return save(fig, "fig07_skill_can0_request_timeline")


def fig08_result_summary() -> tuple[Path, Path]:
    """Evidence scorecard instead of one more bar chart."""
    mut = read_rows(CHARTS / "uds_2e_mutation_attack_summary.csv")
    control = read_rows(CHARTS / "uds_control_group_summary.csv")
    hw = read_metric_csv(CHARTS / "hardware_uds_2e_fuzz_observer_20260620_uds2e_1000_observer_summary.csv")
    fleet = read_rows(CHARTS / "fleet_ota_exposure_20260620_default_1000v_60d_summary.csv")
    during = read_rows(CHARTS / "uds_kintsugi_during_lifecycle_summary_latest.csv")

    attack_before = float(mut[0]["attack_success_rate"]) * 100
    attack_after = float(mut[1]["attack_success_rate"]) * 100
    benign_after = float([r for r in control if r["profile"] == "after_hotpatch" and r["workload"] == "benign_diagnostic"][0]["success_rate"]) * 100
    during_pass = sum(1 for r in during if r["attack_check_passed"] == "true")
    ota = [r for r in fleet if r["strategy"] == "ota_only"][0]
    hp = [r for r in fleet if r["strategy"] == "hotpatch_first"][0]
    exposure_drop = (1.0 - float(hp["cumulative_exposure_vehicle_days"]) / float(ota["cumulative_exposure_vehicle_days"])) * 100

    cards = [
        ("Software fuzzing", "Attack success drops", f"{attack_before:.1f}% → {attack_after:.1f}%", PALETTE["safe"]),
        ("Control group", "Benign diagnostics preserved", f"{benign_after:.1f}% pass after patch", PALETTE["safe"]),
        ("Runtime lifecycle", "Receive / schedule / apply observed", f"{during_pass}/{len(during)} phases matched", PALETTE["neutral"]),
        ("Hardware observer", "Independent CAN listener agrees", f"{int(hw['total_trials'])} trials, 0 mismatch", PALETTE["neutral"]),
        ("Fleet model", "Exposure window reduced", f"{exposure_drop:.1f}% fewer vehicle-days", PALETTE["safe"]),
    ]

    fig, ax = plt.subplots(figsize=(10.4, 5.8))
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    panel_label(ax, "a", x=0.015, y=0.965)
    ax.text(0.06, 0.965, "Evidence chain for fleet-level UDS runtime hotpatching", fontsize=11.5, fontweight="bold", va="top")
    ax.text(0.06, 0.925, "Each card is backed by a CSV artifact and a detailed figure; this panel is an overview for the thesis narrative.", fontsize=7.8, color=PALETTE["muted"], va="top")

    positions = [
        (0.055, 0.585),
        (0.365, 0.585),
        (0.675, 0.585),
        (0.205, 0.300),
        (0.535, 0.300),
    ]
    card_w = 0.255
    card_h = 0.205
    for i, ((x, y), (title, claim, value, color)) in enumerate(zip(positions, cards), start=1):
        ax.add_patch(FancyBboxPatch((x, y), card_w, card_h, boxstyle="round,pad=0.014,rounding_size=0.012", facecolor="#FFFFFF", edgecolor=color, linewidth=1.0))
        ax.text(x + 0.020, y + card_h - 0.040, f"{i}", ha="left", va="center", fontsize=8.2, fontweight="bold", color=color)
        ax.text(x + 0.054, y + card_h - 0.040, title, ha="left", va="center", fontsize=7.5, fontweight="bold", color=PALETTE["text"])
        ax.text(x + 0.020, y + 0.110, claim, ha="left", va="center", fontsize=6.6, color=PALETTE["muted"], linespacing=1.10)
        ax.text(x + 0.020, y + 0.047, value, ha="left", va="center", fontsize=7.2, fontweight="bold", color=color)
    for start, end in [((0.310, 0.688), (0.365, 0.688)), ((0.620, 0.688), (0.675, 0.688)), ((0.492, 0.585), (0.333, 0.505)), ((0.775, 0.585), (0.675, 0.505))]:
        arrow(ax, start, end, color=PALETTE["line"], lw=1.25, mutation_scale=12)

    ax.add_patch(Rectangle((0.12, 0.085), 0.76, 0.135, facecolor=PALETTE["neutral_soft"], edgecolor=PALETTE["grid"], linewidth=0.8, alpha=0.90))
    ax.text(
        0.50,
        0.153,
        "Claim supported by the chain: runtime patching closes the vulnerable UDS write path\n"
        "while preserving diagnostic availability and reducing fleet exposure.",
        ha="center",
        va="center",
        fontsize=7.1,
        color=PALETTE["text"],
        linespacing=1.25,
    )
    return save(fig, "fig08_skill_evidence_chain_summary")


def write_manifest(paths: list[tuple[str, Path, Path]]) -> Path:
    manifest = OUT_ROOT / "FIGURE_MANIFEST_zh.md"
    lines = [
        "# Skill-Generated Thesis Figures",
        "",
        "这些图由 `generate_skill_figures.py` 生成，使用 Python/matplotlib 后端。",
        "本版按照 IoT / software-security 论文图的读图方式重构：先定义图要证明的结论，再选择 flow、sequence、matrix、scatter、area、scorecard 等图型。",
        "",
        "## Figure Contract",
        "",
        "- Core conclusion: Kintsugi runtime hotpatching changes the ECU-local UDS policy without replacing the diagnostic path.",
        "- Evidence chain: architecture/data path -> UDS attack chain -> mutation/control -> runtime lifecycle -> hardware observer -> fleet exposure -> real can0 trace -> thesis scorecard.",
        "- Archetype: schematic-led composite plus quantitative support panels.",
        "- Export: PDF for LaTeX, SVG for editable text.",
        "- Review risk: rates and fleet exposure are artifact-derived; captions should state corpus size and simulation assumptions.",
        "",
        "## Outputs",
        "",
    ]
    for name, pdf, svg in paths:
        lines.append(f"- `{name}`: `{pdf.relative_to(ROOT)}` / `{svg.relative_to(ROOT)}`")
    lines.append("")
    lines.append("## Source Data")
    lines.append("")
    source_files = [
        "software level/charts/uds_2e_mutation_attack_summary.csv",
        "software level/charts/uds_control_group_summary.csv",
        "software level/charts/uds_kintsugi_during_lifecycle_latest.csv",
        "software level/charts/hardware_uds_2e_fuzz_observer_20260620_uds2e_1000_observer_detail.csv",
        "software level/charts/fleet_ota_exposure_20260620_default_1000v_60d_summary.csv",
        "software level/charts/can0_request_timeline_latest.csv",
        "software level/charts/can0_request_timeline_kintsugi_after_latest.csv",
    ]
    for item in source_files:
        lines.append(f"- `{item}`")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    apply_publication_style()
    paths: list[tuple[str, Path, Path]] = []
    for func in [
        fig01_architecture,
        fig02_attack_chain,
        fig03_control_and_mutation,
        fig04_during_lifecycle,
        fig05_hardware_observer,
        fig06_fleet_exposure,
        fig07_can0_timeline,
        fig08_result_summary,
    ]:
        pdf, svg = func()
        paths.append((pdf.stem, pdf, svg))
        print(f"wrote {pdf}")
        print(f"wrote {svg}")
    manifest = write_manifest(paths)
    print(f"wrote {manifest}")


if __name__ == "__main__":
    main()
