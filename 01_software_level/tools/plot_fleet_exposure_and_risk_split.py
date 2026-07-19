#!/usr/bin/env python3
"""Generate separate fleet exposure and attack-risk figures from simulation CSVs."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path


STRATEGY_OTA_ONLY = "ota_only"
STRATEGY_HOTPATCH_FIRST = "hotpatch_first"


def read_summary(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["strategy"]: row for row in csv.DictReader(handle)}


def read_timeseries(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def minutes_to_hours(value: float) -> float:
    return value / 60.0


def write_split_csvs(summary: dict[str, dict[str, str]], exposure_csv: Path, risk_csv: Path) -> None:
    exposure_csv.parent.mkdir(parents=True, exist_ok=True)
    risk_csv.parent.mkdir(parents=True, exist_ok=True)

    with exposure_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["strategy", "fleet_size", "time_to_80pct_h", "time_to_95pct_h", "time_to_full_h", "exposure_vehicle_days"])
        for strategy, row in summary.items():
            writer.writerow(
                [
                    strategy,
                    row["fleet_size"],
                    f"{minutes_to_hours(float(row['time_to_80pct_protection_min'])):.6f}",
                    f"{minutes_to_hours(float(row['time_to_95pct_protection_min'])):.6f}",
                    f"{minutes_to_hours(float(row['time_to_full_protection_min'])):.6f}",
                    row["cumulative_exposure_vehicle_days"],
                ]
            )

    with risk_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["strategy", "expected_attack_attempts", "expected_successful_attack_opportunities"])
        for strategy, row in summary.items():
            writer.writerow(
                [
                    strategy,
                    row["expected_attack_attempts"],
                    row["expected_successful_attack_opportunities"],
                ]
            )


def configure_matplotlib():
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

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
    return plt


def plot_exposure_only(summary: dict[str, dict[str, str]], timeseries: list[dict[str, str]], pdf_path: Path) -> None:
    plt = configure_matplotlib()
    colors = {STRATEGY_OTA_ONLY: "#A2142F", STRATEGY_HOTPATCH_FIRST: "#0072BD"}
    labels = {STRATEGY_OTA_ONLY: "OTA-only", STRATEGY_HOTPATCH_FIRST: "Hotpatch-first"}

    fig, axes = plt.subplots(1, 3, figsize=(10.0, 3.4), gridspec_kw={"width_ratios": [1.55, 1.05, 0.9]})
    fig.suptitle("Fleet Exposure Window Before Full OTA Completion", fontweight="bold", y=1.03)

    ax = axes[0]
    for strategy in (STRATEGY_OTA_ONLY, STRATEGY_HOTPATCH_FIRST):
        rows = [row for row in timeseries if row["strategy"] == strategy]
        ax.plot(
            [float(row["time_hour"]) for row in rows],
            [int(row["vulnerable_vehicle_count"]) for row in rows],
            color=colors[strategy],
            linewidth=2.0,
            label=labels[strategy],
            zorder=3,
        )
    ax.set_xlabel("Time since disclosure (h)")
    ax.set_ylabel("Vulnerable vehicles")
    ax.set_title("Exposure decay over time", loc="left")
    ax.legend(frameon=False)

    ax = axes[1]
    milestones = ["80%", "95%", "100%"]
    fields = ["time_to_80pct_protection_min", "time_to_95pct_protection_min", "time_to_full_protection_min"]
    x_positions = list(range(len(milestones)))
    width = 0.36
    ota_values = [minutes_to_hours(float(summary[STRATEGY_OTA_ONLY][field])) for field in fields]
    hotpatch_values = [minutes_to_hours(float(summary[STRATEGY_HOTPATCH_FIRST][field])) for field in fields]
    ax.bar([x - width / 2 for x in x_positions], ota_values, width, color=colors[STRATEGY_OTA_ONLY], edgecolor="#303030", label="OTA-only", zorder=3)
    ax.bar([x + width / 2 for x in x_positions], hotpatch_values, width, color=colors[STRATEGY_HOTPATCH_FIRST], edgecolor="#303030", label="Hotpatch-first", zorder=3)
    ax.set_xticks(x_positions, milestones)
    ax.set_ylabel("Hours")
    ax.set_title("Protection milestones", loc="left")

    ax = axes[2]
    exposure_values = [
        float(summary[STRATEGY_OTA_ONLY]["cumulative_exposure_vehicle_days"]),
        float(summary[STRATEGY_HOTPATCH_FIRST]["cumulative_exposure_vehicle_days"]),
    ]
    bars = ax.bar(["OTA-only", "Hotpatch-first"], exposure_values, color=[colors[STRATEGY_OTA_ONLY], colors[STRATEGY_HOTPATCH_FIRST]], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Vehicle-days")
    ax.set_title("Cumulative exposure", loc="left")
    ax.tick_params(axis="x", rotation=15)
    for bar, value in zip(bars, exposure_values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + max(exposure_values) * 0.025, f"{value:.0f}", ha="center", va="bottom", zorder=4)

    reduction = 1.0 - exposure_values[1] / exposure_values[0]
    fig.text(0.01, -0.01, f"Exposure reduction from hotpatch-first: {reduction * 100:.1f}%", fontsize=8, color="#606060")
    fig.tight_layout()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def plot_risk_with_attack_probability(summary: dict[str, dict[str, str]], pdf_path: Path) -> None:
    plt = configure_matplotlib()
    colors = {STRATEGY_OTA_ONLY: "#A2142F", STRATEGY_HOTPATCH_FIRST: "#0072BD"}

    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.4))
    fig.suptitle("Fleet Exposure Weighted by Measured UDS Attack Probability", fontweight="bold", y=1.03)

    labels = ["OTA-only", "Hotpatch-first"]
    attempts = [
        float(summary[STRATEGY_OTA_ONLY]["expected_attack_attempts"]),
        float(summary[STRATEGY_HOTPATCH_FIRST]["expected_attack_attempts"]),
    ]
    successes = [
        float(summary[STRATEGY_OTA_ONLY]["expected_successful_attack_opportunities"]),
        float(summary[STRATEGY_HOTPATCH_FIRST]["expected_successful_attack_opportunities"]),
    ]

    ax = axes[0]
    bars = ax.bar(labels, attempts, color=[colors[STRATEGY_OTA_ONLY], colors[STRATEGY_HOTPATCH_FIRST]], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Expected attempts")
    ax.set_title("Exposure-derived attack attempts", loc="left")
    ax.tick_params(axis="x", rotation=12)
    for bar, value in zip(bars, attempts):
        ax.text(bar.get_x() + bar.get_width() / 2, value + max(attempts) * 0.025, f"{value:.1f}", ha="center", va="bottom", zorder=4)

    ax = axes[1]
    bars = ax.bar(labels, successes, color=[colors[STRATEGY_OTA_ONLY], colors[STRATEGY_HOTPATCH_FIRST]], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Expected successful opportunities")
    ax.set_title("After multiplying hardware pass rate", loc="left")
    ax.tick_params(axis="x", rotation=12)
    for bar, value in zip(bars, successes):
        ax.text(bar.get_x() + bar.get_width() / 2, value + max(successes) * 0.025, f"{value:.1f}", ha="center", va="bottom", zorder=4)

    attack_rate = successes[0] / attempts[0] if attempts[0] else 0.0
    reduction = 1.0 - successes[1] / successes[0] if successes[0] else 0.0
    fig.text(
        0.01,
        -0.01,
        f"Hardware fuzzing pass rate={attack_rate * 100:.1f}%; expected-success reduction={reduction * 100:.1f}%",
        fontsize=8,
        color="#606060",
    )
    fig.tight_layout()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--timeseries", required=True)
    parser.add_argument("--exposure-pdf", required=True)
    parser.add_argument("--risk-pdf", required=True)
    parser.add_argument("--exposure-csv", required=True)
    parser.add_argument("--risk-csv", required=True)
    args = parser.parse_args()

    summary = read_summary(Path(args.summary))
    timeseries = read_timeseries(Path(args.timeseries))
    write_split_csvs(summary, Path(args.exposure_csv), Path(args.risk_csv))
    plot_exposure_only(summary, timeseries, Path(args.exposure_pdf))
    plot_risk_with_attack_probability(summary, Path(args.risk_pdf))
    print(f"wrote {args.exposure_csv}")
    print(f"wrote {args.risk_csv}")
    print(f"wrote {args.exposure_pdf}")
    print(f"wrote {args.risk_pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
