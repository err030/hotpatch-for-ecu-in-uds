#!/usr/bin/env python3
"""Validate and inventory the July 2026 evidence bundle."""

from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "software level" / "results"


def read(relative: str) -> list[dict[str, str]]:
    with (ROOT / relative).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    fuzz = read("software level/results/20260710_hardware_fuzz/hardware_fuzz_paired_detail.csv")
    fuzz_summary = read("software level/results/20260710_hardware_fuzz/hardware_fuzz_paired_summary.csv")
    latency = read("software level/results/20260710_paired_hardware/real_can_latency_detail.csv")
    state = read("software level/results/20260710_paired_hardware/real_can_state_integrity.csv")
    benign = read("software level/results/20260710_paired_hardware/hardware_benign_control_detail.csv")
    activation = read("software level/results/20260710_paired_hardware/patch_activation_detail.csv")
    vcan = read("software level/results/20260710_vcan/vcan_paired_detail.csv")
    fleet_sensitivity = read("software level/results/20260710_fleet_sensitivity/fleet_sensitivity_detail.csv")
    fleet_event_sensitivity = read("software level/results/20260710_fleet_event_sensitivity/fleet_event_sensitivity_detail.csv")
    fleet_main = read("software level/results/20260710_fleet_main/fleet_ota_exposure_20260710_paired_hardware_1000v_60d_summary.csv")
    agreement = read("evaluation/thesis_figures/tables/table52_software_hardware_agreement.csv")
    resources = read("evaluation/thesis_figures/tables/table53_resource_footprint.csv")
    resource_build = read("evaluation/thesis_figures/tables/table53_resource_build_measurements.csv")[0]
    measured_flash_delta = (
        int(resource_build["runtime_text"])
        + int(resource_build["runtime_data"])
        - int(resource_build["vulnerable_text"])
        - int(resource_build["vulnerable_data"])
    )
    measured_ram_delta = (
        int(resource_build["runtime_data"])
        + int(resource_build["runtime_bss"])
        - int(resource_build["vulnerable_data"])
        - int(resource_build["vulnerable_bss"])
    )

    checks = {
        "hardware_fuzz_rows_6000": len(fuzz) == 6000,
        "hardware_fuzz_no_timeouts": all(row["timeout"] == "false" for row in fuzz),
        "hardware_fuzz_observer_all_consistent": all(row["observer_consistent"] == "true" for row in fuzz),
        "hardware_fuzz_after_all_blocked": all(row["attack_success"] == "false" for row in fuzz if row["patch_state"] == "after"),
        "hardware_fuzz_three_paired_runs": len(fuzz_summary) == 6,
        "real_can_latency_rows_7280": len(latency) == 7280,
        "real_can_latency_no_timeouts": all(row["timeout"] == "false" for row in latency),
        "state_after_never_changed": all(row["state_changed"] == "false" for row in state if row["patch_state"] == "after"),
        "benign_all_operations_passed": all(row["passed"] == "true" for row in benign),
        "activation_100_of_100_protected": len(activation) == 100 and all(row["protected"] == "true" for row in activation),
        "vcan_rows_2000": len(vcan) == 2000,
        "vcan_after_all_blocked": all(row["attack_success"] == "false" for row in vcan if row["patch_state"] == "after"),
        "fleet_sensitivity_rows_1728": len(fleet_sensitivity) == 1728,
        "fleet_event_sensitivity_rows_16": len(fleet_event_sensitivity) == 16,
        "fleet_event_base_matches_main": any(
            row["hotpatch_capable_ratio"] == "0.85"
            and row["additional_delivery_delay_h"] == "0"
            and row["hotpatch_first_exposure_vehicle_days"] == "2970.517361"
            for row in fleet_event_sensitivity
        ),
        "fleet_main_two_strategies": len(fleet_main) == 2,
        "software_hardware_response_payload_agreement_2000_of_2000": any(
            row["metric"] == "Response payload" and row["total_agreement"] == "2000/2000" for row in agreement
        ),
        "software_hardware_response_class_agreement_2000_of_2000": any(
            row["metric"] == "Positive/negative response class" and row["total_agreement"] == "2000/2000" for row in agreement
        ),
        "software_hardware_nrc_agreement_2000_of_2000": any(
            row["metric"] == "Negative-response code (NRC)" and row["total_agreement"] == "2000/2000" for row in agreement
        ),
        "resource_flash_delta_matches_final_build": any(
            row["metric"] == "Firmware Flash (text + data)"
            and row["delta_or_status"] == f"+{measured_flash_delta} B"
            for row in resources
        ),
        "resource_static_ram_delta_matches_final_build": any(
            row["metric"] == "Static RAM (data + bss)"
            and row["delta_or_status"] == f"+{measured_ram_delta} B"
            for row in resources
        ),
    }

    manifest = [
        ("vcan", "software level/results/20260710_vcan/vcan_paired_detail.csv", len(vcan), "complete", "paired before/after over Linux vcan0"),
        ("hardware_fuzz", "software level/results/20260710_hardware_fuzz/hardware_fuzz_paired_detail.csv", len(fuzz), "complete", "3 seeds x 1000 cases x 2 states"),
        ("host_vs_nucleo", "software level/results/20260710_hardware_fuzz/hardware_fuzz_paired_summary.csv", len(fuzz_summary), "complete", "6000/6000 observer-consistent; no overhead claim"),
        ("real_can_latency", "software level/results/20260710_paired_hardware/real_can_latency_detail.csv", len(latency), "complete", "520 trials/state; first 20 marked warm-up"),
        ("state_integrity", "software level/results/20260710_paired_hardware/real_can_state_integrity.csv", len(state), "complete", "unique values and before/after readback"),
        ("hardware_benign", "software level/results/20260710_paired_hardware/hardware_benign_control_detail.csv", len(benign), "complete", "500 trials/state; all operations retained"),
        ("patch_activation", "software level/results/20260710_paired_hardware/patch_activation_detail.csv", len(activation), "partial", "real host monotonic activation/rollback; RTOS task jitter and CPU load not instrumented"),
        ("fleet_main", "software level/results/20260710_fleet_main/fleet_ota_exposure_20260710_paired_hardware_1000v_60d_summary.csv", len(fleet_main), "complete", "1000 vehicles, 60 days, paired-hardware attack rate"),
        ("fleet_sensitivity", "software level/results/20260710_fleet_sensitivity/fleet_sensitivity_detail.csv", len(fleet_sensitivity), "complete", "1728 parameter combinations"),
        ("fleet_event_sensitivity", "software level/results/20260710_fleet_event_sensitivity/fleet_event_sensitivity_detail.csv", len(fleet_event_sensitivity), "complete", "same discrete-event model as fleet_main; 85% capable and 0 h reproduces 68.7%"),
        ("software_hardware_agreement", "evaluation/thesis_figures/tables/table52_software_hardware_agreement.csv", 2000, "partial", "response payload/class/NRC/outcome 2000/2000; paired readback not recorded"),
        ("resource_footprint", "evaluation/thesis_figures/tables/table53_resource_footprint.csv", len(resources), "partial", "static build footprint measured; runtime high-water, CPU and jitter unavailable"),
    ]
    manifest_path = RESULTS / "20260710_results_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["category", "primary_artifact", "data_rows", "status", "note"])
        writer.writerows(manifest)

    log_lines = [f"{name}={str(passed).lower()}" for name, passed in checks.items()]
    log_lines.extend(
        [
            "observer_ab_physical_disconnect=not_collected_optional",
            "observer_overhead_claim=prohibited_by_current_evidence",
            "software_hardware_state_readback=not_recorded_in_paired_fuzz_files",
            "resource_runtime_highwater=not_instrumented",
            "rtos_task_jitter=not_instrumented",
            "cpu_load_pct=not_instrumented",
        ]
    )
    log_path = RESULTS / "20260710_results_validation.log"
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print("\n".join(log_lines))
    print(f"wrote {manifest_path}")
    print(f"wrote {log_path}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
