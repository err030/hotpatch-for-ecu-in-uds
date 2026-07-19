#!/usr/bin/env python3
"""Plot validation of Nucleo observer agreement with SocketCAN fuzzing records."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path


def load_detail(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_summary(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["metric"]: row["value"] for row in csv.DictReader(handle)}


def as_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def generate(detail_csv: Path, summary_csv: Path, pdf_path: Path, title: str) -> None:
    rows = load_detail(detail_csv)
    summary = load_summary(summary_csv)
    if not rows:
        raise RuntimeError(f"no rows in {detail_csv}")

    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.titlesize": 11,
            "axes.labelsize": 9,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": "#D9D9D9",
            "grid.linewidth": 0.7,
        }
    )

    trials = np.array([int(row["trial"]) for row in rows])
    request_seen = np.array([as_bool(row["observer_request_seen"]) for row in rows], dtype=int)
    response_seen = np.array([as_bool(row["observer_response_seen"]) for row in rows], dtype=int)
    payload_match = np.array([as_bool(row["observer_consistent"]) for row in rows], dtype=int)
    attack_pass = np.array([as_bool(row["attack_pass"]) for row in rows], dtype=int)
    can0_latency = np.array([float(row["latency_ms"]) for row in rows if row["latency_ms"]])
    observer_latency = np.array([float(row["observer_latency_ms"]) for row in rows if row["observer_latency_ms"]])
    latency_delta = observer_latency[: len(can0_latency)] - can0_latency[: len(observer_latency)]

    fig, axes = plt.subplots(2, 2, figsize=(9.2, 6.6), gridspec_kw={"height_ratios": [1.05, 1.0]})
    fig.suptitle(title, fontweight="bold", y=0.98)

    ax = axes[0][0]
    ax.set_axisbelow(True)
    metrics = [
        ("request seen", int(request_seen.sum())),
        ("response seen", int(response_seen.sum())),
        ("payload match", int(payload_match.sum())),
    ]
    total = len(rows)
    ax.bar(
        [item[0] for item in metrics],
        [item[1] for item in metrics],
        color=["#0072BD", "#4DBEEE", "#2E7D32"],
        edgecolor="#303030",
        linewidth=0.7,
        zorder=3,
    )
    ax.axhline(total, color="#404040", linewidth=0.8, linestyle="--", zorder=4)
    ax.set_ylim(0, total * 1.12)
    ax.set_ylabel("Trials")
    ax.set_title("Independent observer coverage", loc="left")
    for index, (_, value) in enumerate(metrics):
        ax.text(index, value + total * 0.025, f"{value}/{total}", ha="center", va="bottom", fontweight="bold", zorder=4)

    ax = axes[0][1]
    outcome_matrix = np.vstack([request_seen, response_seen, payload_match, attack_pass])
    cmap = matplotlib.colors.ListedColormap(["#A2142F", "#2E7D32"])
    ax.imshow(outcome_matrix, aspect="auto", interpolation="nearest", cmap=cmap, vmin=0, vmax=1)
    ax.set_yticks([0, 1, 2, 3], ["req seen", "resp seen", "match", "attack pass"])
    ax.set_xlabel("Trial index")
    ax.set_title("Per-trial agreement matrix", loc="left")
    ax.grid(False)
    ax.set_xticks([0, 249, 499, 749, 999], ["1", "250", "500", "750", "1000"])

    ax = axes[1][0]
    ax.set_axisbelow(True)
    fail_idx = attack_pass == 0
    pass_idx = attack_pass == 1
    ax.scatter(trials[fail_idx], can0_latency[fail_idx], s=10, color="#A2142F", alpha=0.55, label="attack fail", zorder=3)
    ax.scatter(trials[pass_idx], can0_latency[pass_idx], s=10, color="#2E7D32", alpha=0.55, label="attack pass", zorder=3)
    ax.set_xlabel("Trial")
    ax.set_ylabel("can0 response latency (ms)")
    ax.set_title("Baseline pass/fail with response delay", loc="left")
    ax.legend(frameon=False, loc="upper right")

    ax = axes[1][1]
    ax.set_axisbelow(True)
    ax.hist(latency_delta, bins=32, color="#7E2F8E", edgecolor="#303030", linewidth=0.5, zorder=3)
    ax.axvline(float(np.mean(latency_delta)), color="#D95319", linewidth=1.2, label=f"mean {np.mean(latency_delta):.2f} ms", zorder=4)
    ax.set_xlabel("Nucleo observer latency - can0 latency (ms)")
    ax.set_ylabel("Trials")
    ax.set_title("Independent timestamp offset distribution", loc="left")
    ax.legend(frameon=False, loc="upper right")

    subtitle = (
        f"payload agreement={float(summary['observer_consistency_rate']) * 100:.2f}%  "
        f"attack pass={float(summary['attack_pass_rate']) * 100:.2f}%  "
        f"can0 avg={float(summary['can0_latency_avg_ms']):.3f} ms  "
        f"nucleo avg={float(summary['observer_latency_avg_ms']):.3f} ms"
    )
    fig.text(0.01, 0.014, subtitle, fontsize=8, color="#606060")
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detail", required=True, help="Input fuzz detail CSV.")
    parser.add_argument("--summary", required=True, help="Input fuzz summary CSV.")
    parser.add_argument("--pdf", required=True, help="Output PDF.")
    parser.add_argument("--title", default="NUCLEO Observer Validation Against SocketCAN Baseline")
    args = parser.parse_args()

    generate(Path(args.detail), Path(args.summary), Path(args.pdf), args.title)
    print(f"wrote {args.pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
