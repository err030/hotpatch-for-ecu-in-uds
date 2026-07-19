#!/usr/bin/env python3
"""Simulate fleet-level OTA exposure windows for UDS hotpatch motivation."""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
from dataclasses import dataclass
from pathlib import Path


STRATEGY_OTA_ONLY = "ota_only"
STRATEGY_HOTPATCH_FIRST = "hotpatch_first"
DEFAULT_ATTACK_SUMMARY = "01_software_level/results/hardware_fuzz/hardware_fuzz_paired_summary.csv"


@dataclass(frozen=True)
class Window:
    start_min: int
    end_min: int

    def can_fit(self, start_min: int, duration_min: int) -> bool:
        return self.start_min <= start_min and start_min + duration_min <= self.end_min


@dataclass(frozen=True)
class Vehicle:
    vehicle_id: str
    windows: tuple[Window, ...]
    hotpatch_capable: bool
    priority: int


@dataclass(frozen=True)
class Action:
    strategy: str
    vehicle_id: str
    action_kind: str
    start_min: int
    end_min: int
    slot_index: int

    @property
    def duration_min(self) -> int:
        return self.end_min - self.start_min


@dataclass(frozen=True)
class StrategyResult:
    strategy: str
    actions: tuple[Action, ...]
    protected_at: dict[str, int]
    ota_finished_at: dict[str, int]


def minutes_to_hours(value: float) -> float:
    return value / 60.0


def minutes_to_days(value: float) -> float:
    return value / (60.0 * 24.0)


def fmt_hours(value_min: int | float) -> str:
    return f"{minutes_to_hours(float(value_min)):.2f}"


def read_attack_success_probability(path: Path, fallback: float) -> float:
    if not path.exists():
        return fallback
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if rows and "metric" in rows[0] and "value" in rows[0]:
        metrics = {row["metric"]: row["value"] for row in rows}
        try:
            return float(metrics["attack_pass_rate"])
        except (KeyError, ValueError):
            return fallback
    baseline = [row for row in rows if row.get("patch_state") == "before"]
    try:
        total = sum(int(row["total_cases"]) for row in baseline)
        successes = sum(int(row["attack_successes"]) for row in baseline)
        return successes / total if total else fallback
    except (KeyError, ValueError):
        return fallback


def build_synthetic_fleet(
    *,
    fleet_size: int,
    horizon_min: int,
    seed: int,
    hotpatch_capable_ratio: float,
    min_short_windows_per_day: int,
    max_short_windows_per_day: int,
    short_window_min: int,
    short_window_max: int,
    overnight_window_min: int,
    overnight_window_max: int,
) -> tuple[Vehicle, ...]:
    rng = random.Random(seed)
    vehicles: list[Vehicle] = []
    horizon_days = math.ceil(horizon_min / 1440)
    hotpatch_capable_count = round(fleet_size * hotpatch_capable_ratio)

    for index in range(fleet_size):
        windows: list[Window] = []
        vehicle_jitter = rng.randint(0, 90)
        for day in range(horizon_days):
            day_base = day * 1440
            short_count = rng.randint(min_short_windows_per_day, max_short_windows_per_day)
            for _ in range(short_count):
                center = rng.choice([8 * 60, 12 * 60, 16 * 60, 19 * 60]) + rng.randint(-90, 90)
                start = day_base + max(0, center + vehicle_jitter - rng.randint(0, 60))
                length = rng.randint(short_window_min, short_window_max)
                if start < horizon_min:
                    windows.append(Window(start, min(start + length, horizon_min)))

            overnight_start = day_base + 21 * 60 + rng.randint(0, 150)
            overnight_len = rng.randint(overnight_window_min, overnight_window_max)
            if overnight_start < horizon_min:
                windows.append(Window(overnight_start, min(overnight_start + overnight_len, horizon_min)))

        windows.sort(key=lambda window: (window.start_min, window.end_min))
        vehicles.append(
            Vehicle(
                vehicle_id=f"vehicle-{index:04d}",
                windows=tuple(windows),
                hotpatch_capable=index < hotpatch_capable_count,
                priority=0 if index < hotpatch_capable_count else 1,
            )
        )
    return tuple(vehicles)


def schedule_action(
    *,
    strategy: str,
    vehicle: Vehicle,
    action_kind: str,
    duration_min: int,
    ready_min: int,
    slot_available: list[int],
) -> Action:
    best: Action | None = None
    for slot_index, slot_free in enumerate(slot_available):
        for window in vehicle.windows:
            candidate_start = max(ready_min, slot_free, window.start_min)
            if not window.can_fit(candidate_start, duration_min):
                continue
            candidate = Action(
                strategy=strategy,
                vehicle_id=vehicle.vehicle_id,
                action_kind=action_kind,
                start_min=candidate_start,
                end_min=candidate_start + duration_min,
                slot_index=slot_index,
            )
            if best is None or candidate.end_min < best.end_min:
                best = candidate
            break
    if best is None:
        raise RuntimeError(f"cannot schedule {action_kind} for {vehicle.vehicle_id}; increase horizon or windows")
    return best


def schedule_many(
    *,
    strategy: str,
    vehicles: tuple[Vehicle, ...],
    action_kind: str,
    duration_min: int,
    slot_count: int,
    ready_by_vehicle: dict[str, int],
) -> tuple[tuple[Action, ...], dict[str, int]]:
    slot_available = [0 for _ in range(slot_count)]
    actions: list[Action] = []
    finished_at: dict[str, int] = {}
    for vehicle in sorted(vehicles, key=lambda item: (item.priority, item.vehicle_id)):
        action = schedule_action(
            strategy=strategy,
            vehicle=vehicle,
            action_kind=action_kind,
            duration_min=duration_min,
            ready_min=ready_by_vehicle[vehicle.vehicle_id],
            slot_available=slot_available,
        )
        actions.append(action)
        finished_at[vehicle.vehicle_id] = action.end_min
        slot_available[action.slot_index] = action.end_min
    return tuple(actions), finished_at


def simulate_ota_only(
    vehicles: tuple[Vehicle, ...],
    *,
    ota_slots: int,
    ota_duration_min: int,
) -> StrategyResult:
    ready = {vehicle.vehicle_id: 0 for vehicle in vehicles}
    actions, ota_finished = schedule_many(
        strategy=STRATEGY_OTA_ONLY,
        vehicles=vehicles,
        action_kind="ota",
        duration_min=ota_duration_min,
        slot_count=ota_slots,
        ready_by_vehicle=ready,
    )
    return StrategyResult(
        strategy=STRATEGY_OTA_ONLY,
        actions=actions,
        protected_at=dict(ota_finished),
        ota_finished_at=dict(ota_finished),
    )


def simulate_hotpatch_first(
    vehicles: tuple[Vehicle, ...],
    *,
    ota_slots: int,
    hotpatch_slots: int,
    ota_duration_min: int,
    hotpatch_duration_min: int,
) -> StrategyResult:
    capable = tuple(vehicle for vehicle in vehicles if vehicle.hotpatch_capable)
    hotpatch_ready = {vehicle.vehicle_id: 0 for vehicle in capable}
    hotpatch_actions, hotpatch_finished = schedule_many(
        strategy=STRATEGY_HOTPATCH_FIRST,
        vehicles=capable,
        action_kind="hotpatch",
        duration_min=hotpatch_duration_min,
        slot_count=hotpatch_slots,
        ready_by_vehicle=hotpatch_ready,
    )

    ota_ready = {
        vehicle.vehicle_id: hotpatch_finished.get(vehicle.vehicle_id, 0)
        for vehicle in vehicles
    }
    ota_actions, ota_finished = schedule_many(
        strategy=STRATEGY_HOTPATCH_FIRST,
        vehicles=vehicles,
        action_kind="ota",
        duration_min=ota_duration_min,
        slot_count=ota_slots,
        ready_by_vehicle=ota_ready,
    )

    protected_at = dict(ota_finished)
    for vehicle_id, finish_min in hotpatch_finished.items():
        protected_at[vehicle_id] = finish_min
    return StrategyResult(
        strategy=STRATEGY_HOTPATCH_FIRST,
        actions=hotpatch_actions + ota_actions,
        protected_at=protected_at,
        ota_finished_at=dict(ota_finished),
    )


def milestone_time(protected_times: list[int], ratio: float) -> int:
    index = max(0, math.ceil(len(protected_times) * ratio) - 1)
    return sorted(protected_times)[index]


def vulnerable_count_at(result: StrategyResult, time_min: int) -> int:
    return sum(1 for protected_min in result.protected_at.values() if protected_min > time_min)


def summarize_result(
    result: StrategyResult,
    *,
    fleet_size: int,
    attack_success_probability: float,
    attack_attempt_rate_per_vehicle_day: float,
) -> dict[str, float | int | str]:
    protected_times = sorted(result.protected_at.values())
    exposure_vehicle_min = sum(protected_times)
    exposure_vehicle_days = minutes_to_days(exposure_vehicle_min)
    expected_attempts = exposure_vehicle_days * attack_attempt_rate_per_vehicle_day
    expected_successes = expected_attempts * attack_success_probability
    response_unavailable = sum(
        action.duration_min
        for action in result.actions
        if result.protected_at[action.vehicle_id] == action.end_min
    )
    total_unavailable = sum(action.duration_min for action in result.actions)
    return {
        "strategy": result.strategy,
        "fleet_size": fleet_size,
        "time_to_first_protection_min": protected_times[0],
        "time_to_50pct_protection_min": milestone_time(protected_times, 0.50),
        "time_to_80pct_protection_min": milestone_time(protected_times, 0.80),
        "time_to_95pct_protection_min": milestone_time(protected_times, 0.95),
        "time_to_full_protection_min": protected_times[-1],
        "cumulative_exposure_vehicle_min": exposure_vehicle_min,
        "cumulative_exposure_vehicle_hours": minutes_to_hours(exposure_vehicle_min),
        "cumulative_exposure_vehicle_days": exposure_vehicle_days,
        "expected_attack_attempts": expected_attempts,
        "expected_successful_attack_opportunities": expected_successes,
        "response_unavailable_vehicle_min": response_unavailable,
        "total_unavailable_vehicle_min": total_unavailable,
        "scheduled_actions": len(result.actions),
    }


def write_summary_csv(path: Path, summaries: list[dict[str, float | int | str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(summaries[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for summary in summaries:
            writer.writerow(summary)


def write_actions_csv(path: Path, results: tuple[StrategyResult, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["strategy", "vehicle_id", "action_kind", "start_min", "end_min", "duration_min", "slot_index"],
        )
        writer.writeheader()
        for result in results:
            for action in result.actions:
                writer.writerow(
                    {
                        "strategy": action.strategy,
                        "vehicle_id": action.vehicle_id,
                        "action_kind": action.action_kind,
                        "start_min": action.start_min,
                        "end_min": action.end_min,
                        "duration_min": action.duration_min,
                        "slot_index": action.slot_index,
                    }
                )


def write_vehicle_csv(path: Path, vehicles: tuple[Vehicle, ...], results: tuple[StrategyResult, ...]) -> None:
    by_strategy = {result.strategy: result for result in results}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "vehicle_id",
                "hotpatch_capable",
                "ota_only_protected_min",
                "hotpatch_first_protected_min",
                "exposure_reduction_min",
                "ota_only_ota_finished_min",
                "hotpatch_first_ota_finished_min",
            ],
        )
        writer.writeheader()
        for vehicle in vehicles:
            ota_only = by_strategy[STRATEGY_OTA_ONLY]
            hotpatch_first = by_strategy[STRATEGY_HOTPATCH_FIRST]
            ota_protected = ota_only.protected_at[vehicle.vehicle_id]
            hotpatch_protected = hotpatch_first.protected_at[vehicle.vehicle_id]
            writer.writerow(
                {
                    "vehicle_id": vehicle.vehicle_id,
                    "hotpatch_capable": "true" if vehicle.hotpatch_capable else "false",
                    "ota_only_protected_min": ota_protected,
                    "hotpatch_first_protected_min": hotpatch_protected,
                    "exposure_reduction_min": ota_protected - hotpatch_protected,
                    "ota_only_ota_finished_min": ota_only.ota_finished_at[vehicle.vehicle_id],
                    "hotpatch_first_ota_finished_min": hotpatch_first.ota_finished_at[vehicle.vehicle_id],
                }
            )


def write_timeseries_csv(path: Path, results: tuple[StrategyResult, ...], horizon_min: int, step_min: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["time_min", "time_hour", "strategy", "vulnerable_vehicle_count"])
        writer.writeheader()
        for result in results:
            for time_min in range(0, horizon_min + 1, step_min):
                writer.writerow(
                    {
                        "time_min": time_min,
                        "time_hour": f"{minutes_to_hours(time_min):.3f}",
                        "strategy": result.strategy,
                        "vulnerable_vehicle_count": vulnerable_count_at(result, time_min),
                    }
                )


def generate_pdf(
    *,
    summary_csv: Path,
    timeseries_csv: Path,
    pdf_path: Path,
    title: str,
) -> None:
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    summaries = list(csv.DictReader(summary_csv.open(newline="", encoding="utf-8")))
    series = list(csv.DictReader(timeseries_csv.open(newline="", encoding="utf-8")))
    by_strategy = {row["strategy"]: row for row in summaries}

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

    colors = {STRATEGY_OTA_ONLY: "#A2142F", STRATEGY_HOTPATCH_FIRST: "#0072BD"}
    labels = {STRATEGY_OTA_ONLY: "OTA-only", STRATEGY_HOTPATCH_FIRST: "Hotpatch-first"}

    fig, axes = plt.subplots(2, 2, figsize=(9.4, 6.8))
    fig.suptitle(title, fontweight="bold", y=0.98)

    ax = axes[0][0]
    for strategy in (STRATEGY_OTA_ONLY, STRATEGY_HOTPATCH_FIRST):
        rows = [row for row in series if row["strategy"] == strategy]
        ax.plot(
            [float(row["time_hour"]) for row in rows],
            [int(row["vulnerable_vehicle_count"]) for row in rows],
            label=labels[strategy],
            color=colors[strategy],
            linewidth=2.0,
            zorder=3,
        )
    ax.set_xlabel("Time since disclosure (h)")
    ax.set_ylabel("Vulnerable vehicles")
    ax.set_title("Fleet exposure window over time", loc="left")
    ax.legend(frameon=False)

    ax = axes[0][1]
    milestone_names = ["50%", "80%", "95%", "100%"]
    milestone_fields = [
        "time_to_50pct_protection_min",
        "time_to_80pct_protection_min",
        "time_to_95pct_protection_min",
        "time_to_full_protection_min",
    ]
    x_positions = list(range(len(milestone_names)))
    width = 0.36
    ota_values = [minutes_to_hours(float(by_strategy[STRATEGY_OTA_ONLY][field])) for field in milestone_fields]
    hotpatch_values = [minutes_to_hours(float(by_strategy[STRATEGY_HOTPATCH_FIRST][field])) for field in milestone_fields]
    ax.bar([x - width / 2 for x in x_positions], ota_values, width, label="OTA-only", color=colors[STRATEGY_OTA_ONLY], edgecolor="#303030", zorder=3)
    ax.bar([x + width / 2 for x in x_positions], hotpatch_values, width, label="Hotpatch-first", color=colors[STRATEGY_HOTPATCH_FIRST], edgecolor="#303030", zorder=3)
    ax.set_xticks(x_positions, milestone_names)
    ax.set_ylabel("Hours")
    ax.set_title("Protection rollout milestones", loc="left")
    ax.legend(frameon=False)

    ax = axes[1][0]
    exposure_values = [
        float(by_strategy[STRATEGY_OTA_ONLY]["cumulative_exposure_vehicle_days"]),
        float(by_strategy[STRATEGY_HOTPATCH_FIRST]["cumulative_exposure_vehicle_days"]),
    ]
    bars = ax.bar(["OTA-only", "Hotpatch-first"], exposure_values, color=[colors[STRATEGY_OTA_ONLY], colors[STRATEGY_HOTPATCH_FIRST]], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Vehicle-days")
    ax.set_title("Cumulative exposure", loc="left")
    for bar, value in zip(bars, exposure_values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + max(exposure_values) * 0.025, f"{value:.1f}", ha="center", va="bottom", zorder=4)

    ax = axes[1][1]
    expected_values = [
        float(by_strategy[STRATEGY_OTA_ONLY]["expected_successful_attack_opportunities"]),
        float(by_strategy[STRATEGY_HOTPATCH_FIRST]["expected_successful_attack_opportunities"]),
    ]
    bars = ax.bar(["OTA-only", "Hotpatch-first"], expected_values, color=[colors[STRATEGY_OTA_ONLY], colors[STRATEGY_HOTPATCH_FIRST]], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Expected successes")
    ax.set_title("Expected successful attack opportunities", loc="left")
    for bar, value in zip(bars, expected_values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + max(expected_values) * 0.025, f"{value:.2f}", ha="center", va="bottom", zorder=4)

    ota_exp = float(by_strategy[STRATEGY_OTA_ONLY]["cumulative_exposure_vehicle_days"])
    hp_exp = float(by_strategy[STRATEGY_HOTPATCH_FIRST]["cumulative_exposure_vehicle_days"])
    reduction = 1.0 - hp_exp / ota_exp if ota_exp else 0.0
    subtitle = (
        f"exposure reduction={reduction * 100:.1f}%  "
        f"OTA-only full={float(by_strategy[STRATEGY_OTA_ONLY]['time_to_full_protection_min']) / 60:.1f} h  "
        f"hotpatch-first 80%={float(by_strategy[STRATEGY_HOTPATCH_FIRST]['time_to_80pct_protection_min']) / 60:.1f} h"
    )
    fig.text(0.01, 0.014, subtitle, fontsize=8, color="#606060")
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def write_references(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Fleet OTA Exposure Simulation References",
                "",
                "This simulation is a lightweight discrete-event fleet rollout model. It does not import a traffic simulator directly because the thesis metric is a security exposure window, not route choice or passenger assignment.",
                "",
                "Open-source projects used as modeling references:",
                "",
                "- Eclipse SUMO: open-source microscopic traffic simulation for large road networks. Useful as context for traffic-scale simulation, but not used here because OTA security exposure does not require road-network dynamics.",
                "- FleetPy: open-source fleet simulation framework for vehicle fleets, routing, user assignment, charging, and demand-responsive services. Useful as a fleet/agent reference, but too broad for this UDS security metric.",
                "- UXsim: lightweight Python macro/mesoscopic traffic flow simulator. Useful evidence that large-scale vehicle simulation can be abstracted efficiently, but its traffic-flow model is orthogonal to OTA exposure.",
                "- python-can and python-udsoncan: CAN/UDS protocol references already aligned with the lower-level part of this project.",
                "",
                "Metric definition:",
                "",
                "- A vehicle is vulnerable until either the full OTA update finishes or a hotpatch-first guard finishes.",
                "- Cumulative exposure is the sum of vulnerable minutes across all vehicles.",
                "- Expected successful attack opportunities multiply exposure vehicle-days by an assumed attack-attempt rate and by the measured UDS 0x2E hardware fuzzing pass rate.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fleet-size", type=int, default=1000)
    parser.add_argument("--horizon-days", type=int, default=60)
    parser.add_argument("--seed", type=int, default=20260620)
    parser.add_argument("--hotpatch-capable-ratio", type=float, default=0.85)
    parser.add_argument("--ota-slots", type=int, default=20)
    parser.add_argument("--hotpatch-slots", type=int, default=120)
    parser.add_argument("--ota-duration-min", type=int, default=45)
    parser.add_argument("--hotpatch-duration-min", type=int, default=3)
    parser.add_argument("--min-short-windows-per-day", type=int, default=2)
    parser.add_argument("--max-short-windows-per-day", type=int, default=4)
    parser.add_argument("--short-window-min", type=int, default=8)
    parser.add_argument("--short-window-max", type=int, default=22)
    parser.add_argument("--overnight-window-min", type=int, default=55)
    parser.add_argument("--overnight-window-max", type=int, default=140)
    parser.add_argument("--timeseries-step-min", type=int, default=30)
    parser.add_argument("--attack-attempt-rate-per-vehicle-day", type=float, default=0.05)
    parser.add_argument("--attack-success-probability", type=float, default=-1.0)
    parser.add_argument("--attack-summary-csv", default=DEFAULT_ATTACK_SUMMARY)
    parser.add_argument("--tag", default="paired_hardware_1000v_60d")
    parser.add_argument("--charts-dir", default="01_software_level/results/fleet_main")
    parser.add_argument("--pdf-dir", default="01_software_level/results/fleet_main")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    horizon_min = args.horizon_days * 1440
    tag = args.tag
    charts_dir = Path(args.charts_dir)
    pdf_dir = Path(args.pdf_dir)

    attack_probability = (
        args.attack_success_probability
        if args.attack_success_probability >= 0
        else read_attack_success_probability(Path(args.attack_summary_csv), 0.774)
    )

    vehicles = build_synthetic_fleet(
        fleet_size=args.fleet_size,
        horizon_min=horizon_min,
        seed=args.seed,
        hotpatch_capable_ratio=args.hotpatch_capable_ratio,
        min_short_windows_per_day=args.min_short_windows_per_day,
        max_short_windows_per_day=args.max_short_windows_per_day,
        short_window_min=args.short_window_min,
        short_window_max=args.short_window_max,
        overnight_window_min=args.overnight_window_min,
        overnight_window_max=args.overnight_window_max,
    )

    ota_only = simulate_ota_only(
        vehicles,
        ota_slots=args.ota_slots,
        ota_duration_min=args.ota_duration_min,
    )
    hotpatch_first = simulate_hotpatch_first(
        vehicles,
        ota_slots=args.ota_slots,
        hotpatch_slots=args.hotpatch_slots,
        ota_duration_min=args.ota_duration_min,
        hotpatch_duration_min=args.hotpatch_duration_min,
    )
    results = (ota_only, hotpatch_first)
    summaries = [
        summarize_result(
            result,
            fleet_size=args.fleet_size,
            attack_success_probability=attack_probability,
            attack_attempt_rate_per_vehicle_day=args.attack_attempt_rate_per_vehicle_day,
        )
        for result in results
    ]

    prefix = f"fleet_ota_exposure_{tag}"
    summary_csv = charts_dir / f"{prefix}_summary.csv"
    actions_csv = charts_dir / f"{prefix}_actions.csv"
    vehicles_csv = charts_dir / f"{prefix}_vehicles.csv"
    timeseries_csv = charts_dir / f"{prefix}_timeseries.csv"
    references_md = charts_dir / f"{prefix}_references.md"
    log_path = charts_dir / f"{prefix}.log"
    pdf_path = pdf_dir / f"{prefix}.pdf"

    write_summary_csv(summary_csv, summaries)
    write_actions_csv(actions_csv, results)
    write_vehicle_csv(vehicles_csv, vehicles, results)
    write_timeseries_csv(timeseries_csv, results, horizon_min, args.timeseries_step_min)
    write_references(references_md)
    generate_pdf(
        summary_csv=summary_csv,
        timeseries_csv=timeseries_csv,
        pdf_path=pdf_path,
        title="Fleet OTA Exposure Window Simulation",
    )

    by_strategy = {summary["strategy"]: summary for summary in summaries}
    ota_exp = float(by_strategy[STRATEGY_OTA_ONLY]["cumulative_exposure_vehicle_days"])
    hotpatch_exp = float(by_strategy[STRATEGY_HOTPATCH_FIRST]["cumulative_exposure_vehicle_days"])
    reduction = 1.0 - hotpatch_exp / ota_exp if ota_exp else 0.0
    log_path.write_text(
        "\n".join(
            [
                f"generated_at={datetime.now().astimezone().isoformat(timespec='seconds')}",
                f"fleet_size={args.fleet_size}",
                f"horizon_days={args.horizon_days}",
                f"seed={args.seed}",
                f"attack_success_probability={attack_probability:.6f}",
                f"ota_only_exposure_vehicle_days={ota_exp:.6f}",
                f"hotpatch_first_exposure_vehicle_days={hotpatch_exp:.6f}",
                f"exposure_reduction={reduction:.6f}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"fleet_size={args.fleet_size}")
    print(f"attack_success_probability={attack_probability:.6f}")
    print(f"ota_only_exposure_vehicle_days={ota_exp:.3f}")
    print(f"hotpatch_first_exposure_vehicle_days={hotpatch_exp:.3f}")
    print(f"exposure_reduction={reduction:.4f}")
    print(f"ota_only_full_protection_h={fmt_hours(float(by_strategy[STRATEGY_OTA_ONLY]['time_to_full_protection_min']))}")
    print(f"hotpatch_first_80pct_protection_h={fmt_hours(float(by_strategy[STRATEGY_HOTPATCH_FIRST]['time_to_80pct_protection_min']))}")
    print(f"wrote {summary_csv}")
    print(f"wrote {actions_csv}")
    print(f"wrote {vehicles_csv}")
    print(f"wrote {timeseries_csv}")
    print(f"wrote {references_md}")
    print(f"wrote {log_path}")
    print(f"wrote {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
