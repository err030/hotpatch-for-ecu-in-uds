#!/usr/bin/env python3
"""Sensitivity analysis using the same discrete-event fleet model as Fig. 5.8.

Unlike the earlier closed-form uniform-rollout grid, this analysis keeps the
main simulation's vehicle windows, slot limits, action durations, horizon and
random seed.  It varies only the hotpatch-capable fraction and an additional
delivery delay before hotpatch scheduling can begin.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from run_fleet_ota_exposure_simulation import (
    STRATEGY_HOTPATCH_FIRST,
    StrategyResult,
    build_synthetic_fleet,
    schedule_many,
    simulate_ota_only,
)


CAPABLE_RATIOS = (0.70, 0.85, 0.95, 1.00)
DELIVERY_DELAYS_H = (0, 6, 24, 72)


def simulate_hotpatch_with_delay(
    vehicles,
    *,
    capable_ratio: float,
    delivery_delay_min: int,
    ota_slots: int,
    hotpatch_slots: int,
    ota_duration_min: int,
    hotpatch_duration_min: int,
) -> StrategyResult:
    capable_count = round(len(vehicles) * capable_ratio)
    configured = tuple(
        replace(vehicle, hotpatch_capable=index < capable_count, priority=0 if index < capable_count else 1)
        for index, vehicle in enumerate(vehicles)
    )
    capable = tuple(vehicle for vehicle in configured if vehicle.hotpatch_capable)
    hotpatch_ready = {vehicle.vehicle_id: delivery_delay_min for vehicle in capable}
    hotpatch_actions, hotpatch_finished = schedule_many(
        strategy=STRATEGY_HOTPATCH_FIRST,
        vehicles=capable,
        action_kind="hotpatch",
        duration_min=hotpatch_duration_min,
        slot_count=hotpatch_slots,
        ready_by_vehicle=hotpatch_ready,
    )
    ota_ready = {vehicle.vehicle_id: hotpatch_finished.get(vehicle.vehicle_id, 0) for vehicle in configured}
    ota_actions, ota_finished = schedule_many(
        strategy=STRATEGY_HOTPATCH_FIRST,
        vehicles=configured,
        action_kind="ota",
        duration_min=ota_duration_min,
        slot_count=ota_slots,
        ready_by_vehicle=ota_ready,
    )
    protected_at = dict(ota_finished)
    protected_at.update(hotpatch_finished)
    return StrategyResult(
        strategy=STRATEGY_HOTPATCH_FIRST,
        actions=hotpatch_actions + ota_actions,
        protected_at=protected_at,
        ota_finished_at=dict(ota_finished),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="software level/results/20260710_fleet_event_sensitivity")
    parser.add_argument("--fleet-size", type=int, default=1000)
    parser.add_argument("--horizon-days", type=int, default=60)
    parser.add_argument("--seed", type=int, default=20260710)
    parser.add_argument("--ota-slots", type=int, default=20)
    parser.add_argument("--hotpatch-slots", type=int, default=120)
    parser.add_argument("--ota-duration-min", type=int, default=45)
    parser.add_argument("--hotpatch-duration-min", type=int, default=3)
    args = parser.parse_args()

    horizon_min = args.horizon_days * 1440
    # Build one fixed set of windows. Capability flags are reassigned below;
    # random windows therefore remain identical across the entire grid.
    vehicles = build_synthetic_fleet(
        fleet_size=args.fleet_size,
        horizon_min=horizon_min,
        seed=args.seed,
        hotpatch_capable_ratio=1.0,
        min_short_windows_per_day=2,
        max_short_windows_per_day=4,
        short_window_min=8,
        short_window_max=22,
        overnight_window_min=55,
        overnight_window_max=140,
    )
    ota_only = simulate_ota_only(vehicles, ota_slots=args.ota_slots, ota_duration_min=args.ota_duration_min)
    ota_exposure = sum(ota_only.protected_at.values()) / 1440.0

    rows = []
    for ratio in CAPABLE_RATIOS:
        for delay_h in DELIVERY_DELAYS_H:
            result = simulate_hotpatch_with_delay(
                vehicles,
                capable_ratio=ratio,
                delivery_delay_min=delay_h * 60,
                ota_slots=args.ota_slots,
                hotpatch_slots=args.hotpatch_slots,
                ota_duration_min=args.ota_duration_min,
                hotpatch_duration_min=args.hotpatch_duration_min,
            )
            hotpatch_exposure = sum(result.protected_at.values()) / 1440.0
            reduction = 1.0 - hotpatch_exposure / ota_exposure
            protected = sorted(result.protected_at.values())
            rows.append(
                {
                    "fleet_size": args.fleet_size,
                    "horizon_days": args.horizon_days,
                    "random_seed": args.seed,
                    "hotpatch_capable_ratio": f"{ratio:.2f}",
                    "additional_delivery_delay_h": delay_h,
                    "ota_slots": args.ota_slots,
                    "hotpatch_slots": args.hotpatch_slots,
                    "ota_duration_min": args.ota_duration_min,
                    "hotpatch_duration_min": args.hotpatch_duration_min,
                    "ota_only_exposure_vehicle_days": f"{ota_exposure:.6f}",
                    "hotpatch_first_exposure_vehicle_days": f"{hotpatch_exposure:.6f}",
                    "exposure_reduction_fraction": f"{reduction:.6f}",
                    "time_to_80pct_protection_h": f"{protected[799] / 60.0:.6f}",
                    "time_to_full_protection_h": f"{protected[-1] / 60.0:.6f}",
                    "model": "same_discrete_event_model_as_fleet_main",
                }
            )

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    detail_path = out / "fleet_event_sensitivity_detail.csv"
    with detail_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    base = next(row for row in rows if row["hotpatch_capable_ratio"] == "0.85" and row["additional_delivery_delay_h"] == 0)
    expected_main = 2970.517361
    base_matches = abs(float(base["hotpatch_first_exposure_vehicle_days"]) - expected_main) < 1e-6
    if not base_matches:
        raise RuntimeError("event-sensitivity base cell does not reproduce the detailed fleet-main result")
    log_path = out / "fleet_event_sensitivity.log"
    log_path.write_text(
        "\n".join(
            [
                f"generated_at={datetime.now().astimezone().isoformat(timespec='seconds')}",
                f"scenario_count={len(rows)}",
                f"fleet_size={args.fleet_size}",
                f"horizon_days={args.horizon_days}",
                f"seed={args.seed}",
                f"ota_slots={args.ota_slots}",
                f"hotpatch_slots={args.hotpatch_slots}",
                f"ota_duration_min={args.ota_duration_min}",
                f"hotpatch_duration_min={args.hotpatch_duration_min}",
                "capable_ratios=0.70,0.85,0.95,1.00",
                "additional_delivery_delay_h=0,6,24,72",
                f"base_85pct_0h_exposure_vehicle_days={base['hotpatch_first_exposure_vehicle_days']}",
                f"base_85pct_0h_reduction={base['exposure_reduction_fraction']}",
                f"base_matches_fleet_main={str(base_matches).lower()}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"scenarios={len(rows)}")
    print(f"base_matches_fleet_main={str(base_matches).lower()}")
    print(f"wrote {detail_path}")
    print(f"wrote {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
