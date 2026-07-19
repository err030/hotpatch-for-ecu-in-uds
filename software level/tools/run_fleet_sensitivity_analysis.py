#!/usr/bin/env python3
"""Generate the full fleet exposure sensitivity grid requested for the thesis.

This complements (rather than replaces) the detailed 1000-vehicle/60-day event
simulation.  It uses the closed-form expectation for a uniform OTA rollout so
all 1728 parameter combinations can be compared without Monte-Carlo noise.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path


FLEET_SIZES = (100, 1000, 10000)
DELIVERY_SUCCESS = (0.70, 0.85, 0.95, 1.00)
DELIVERY_DELAY_H = (1, 6, 24, 72)
OTA_DAYS = (7, 14, 30, 60)
ATTACK_RATES = {"low": 0.01, "medium": 0.05, "high": 0.20}
ROLLBACK_FAILURE = (0.00, 0.01, 0.05)


def expected_min_uniform(delay_days: float, rollout_days: float) -> float:
    """E[min(delay, U(0, rollout_days))]."""
    if delay_days >= rollout_days:
        return rollout_days / 2.0
    return delay_days - (delay_days * delay_days) / (2.0 * rollout_days)


def build_rows(attack_success_probability: float) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    scenario_id = 0
    for fleet_size in FLEET_SIZES:
        for delivery_success in DELIVERY_SUCCESS:
            for delivery_delay_h in DELIVERY_DELAY_H:
                for ota_days in OTA_DAYS:
                    for attack_level, attack_rate in ATTACK_RATES.items():
                        for rollback_rate in ROLLBACK_FAILURE:
                            scenario_id += 1
                            effective_success = delivery_success * (1.0 - rollback_rate)
                            ota_per_vehicle = ota_days / 2.0
                            hotpatch_per_vehicle = (
                                effective_success
                                * expected_min_uniform(delivery_delay_h / 24.0, float(ota_days))
                                + (1.0 - effective_success) * ota_per_vehicle
                            )
                            ota_exposure = fleet_size * ota_per_vehicle
                            hotpatch_exposure = fleet_size * hotpatch_per_vehicle
                            reduction = 1.0 - hotpatch_exposure / ota_exposure
                            ota_attempts = ota_exposure * attack_rate
                            hotpatch_attempts = hotpatch_exposure * attack_rate
                            rows.append(
                                {
                                    "scenario_id": f"FS{scenario_id:04d}",
                                    "fleet_size": fleet_size,
                                    "hotpatch_delivery_success": f"{delivery_success:.2f}",
                                    "hotpatch_delivery_delay_h": delivery_delay_h,
                                    "ota_rollout_duration_days": ota_days,
                                    "attack_attempt_level": attack_level,
                                    "attack_attempt_rate_per_vehicle_day": f"{attack_rate:.4f}",
                                    "rollback_failure_rate": f"{rollback_rate:.2f}",
                                    "effective_hotpatch_success": f"{effective_success:.6f}",
                                    "ota_only_exposure_vehicle_days": f"{ota_exposure:.6f}",
                                    "hotpatch_first_exposure_vehicle_days": f"{hotpatch_exposure:.6f}",
                                    "exposure_reduction_vehicle_days": f"{ota_exposure - hotpatch_exposure:.6f}",
                                    "exposure_reduction_fraction": f"{reduction:.6f}",
                                    "ota_only_expected_attack_attempts": f"{ota_attempts:.6f}",
                                    "hotpatch_first_expected_attack_attempts": f"{hotpatch_attempts:.6f}",
                                    "ota_only_expected_successful_attacks": f"{ota_attempts * attack_success_probability:.6f}",
                                    "hotpatch_first_expected_successful_attacks": f"{hotpatch_attempts * attack_success_probability:.6f}",
                                    "attack_success_probability": f"{attack_success_probability:.6f}",
                                    "model": "uniform_ota_closed_form_expectation",
                                }
                            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-success-probability", type=float, default=0.774)
    parser.add_argument("--output-dir", default="software level/results/20260710_fleet_sensitivity")
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows = build_rows(args.attack_success_probability)
    detail_path = out / "fleet_sensitivity_detail.csv"
    with detail_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    log_path = out / "fleet_sensitivity.log"
    reductions = [float(row["exposure_reduction_fraction"]) for row in rows]
    log_path.write_text(
        "\n".join(
            [
                f"generated_at={datetime.now().astimezone().isoformat(timespec='seconds')}",
                f"scenario_count={len(rows)}",
                f"attack_success_probability={args.attack_success_probability:.6f}",
                f"exposure_reduction_min={min(reductions):.6f}",
                f"exposure_reduction_max={max(reductions):.6f}",
                "fleet_sizes=100,1000,10000",
                "delivery_success=0.70,0.85,0.95,1.00",
                "delivery_delay_h=1,6,24,72",
                "ota_rollout_days=7,14,30,60",
                "attack_attempt_rates=low:0.01,medium:0.05,high:0.20 per vehicle-day",
                "rollback_failure_rates=0.00,0.01,0.05",
                "model_note=closed-form expectation; detailed 1000-vehicle event simulation remains the main trajectory evidence",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"scenarios={len(rows)}")
    print(f"wrote {detail_path}")
    print(f"wrote {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
