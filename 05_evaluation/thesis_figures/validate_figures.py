#!/usr/bin/env python3
"""Validate numerical integrity and export properties of the revised figures."""

from __future__ import annotations

import csv
from pathlib import Path
from statistics import median


BASE = Path(__file__).resolve().parent
RESULTS = BASE.parents[1] / "01_software_level" / "results"
FINAL_TIMING_RESULTS = RESULTS / "final_firmware_timing"
STEMS = [
    "fig51_measurement_paths",
    "fig52_attack_success",
    "fig53_state_integrity",
    "fig54_fuzz_reproducibility",
    "fig55_real_can_latency",
    "fig56_patch_activation",
    "fig57_observer_validation",
    "fig58_fleet_exposure",
    "fig59_fleet_sensitivity",
]


def csv_rows(name):
    with (BASE / "source_data" / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


checks = []


def check(name, condition, evidence):
    checks.append((name, bool(condition), str(evidence)))


for stem in STEMS:
    path = BASE / "pdf" / f"{stem}.pdf"
    check(f"{stem} PDF exists", path.exists() and path.stat().st_size > 0, f"{path.stat().st_size if path.exists() else 0} bytes")

attack = {r["workload"]: r for r in csv_rows("fig52_attack_success.csv")}
check("Target attacks blocked", float(attack["Target-DID attacks"]["before_pct"]) == 100 and float(attack["Target-DID attacks"]["after_pct"]) == 0, "100% to 0%")
check("Hardware corpus blocked", abs(float(attack["Mixed hardware corpus"]["before_pct"]) - 77.5) < 1e-9 and float(attack["Mixed hardware corpus"]["after_pct"]) == 0, "77.5% to 0%")
check("vcan corpus blocked", abs(float(attack["vcan corpus"]["before_pct"]) - 75.6) < 1e-9 and float(attack["vcan corpus"]["after_pct"]) == 0, "75.6% to 0%")

state = {r["patch_state"]: r for r in csv_rows("fig53_state_integrity.csv")}
check("State integrity baseline", int(state["before"]["state_changed"]) == 500, "500/500 changed")
check("State integrity patched", int(state["after"]["state_changed"]) == 0, "0/500 changed")

runs = csv_rows("fig54_fuzz_reproducibility.csv")
run_before = [float(r["before_pct"]) for r in runs]
run_after = [float(r["after_pct"]) for r in runs]
check("Three independent fuzz runs", len(runs) == 3, "n=3 seeds")
check("Run-level baseline rates", run_before == [75.6, 77.1, 79.8], run_before)
check("Run-level patched rates", run_after == [0.0, 0.0, 0.0], run_after)

target = csv_rows("fig55_target_latency.csv")
before = [float(r["latency_ms"]) for r in target if r["patch_state"] == "before"]
after = [float(r["latency_ms"]) for r in target if r["patch_state"] == "after"]
with (FINAL_TIMING_RESULTS / "real_can_latency_detail.csv").open(newline="", encoding="utf-8") as handle:
    raw_latency = [r for r in csv.DictReader(handle) if r["warmup"] == "false" and r["step"] == "write_target"]
raw_before = [float(r["latency_ms"]) for r in raw_latency if r["patch_state"] == "before"]
raw_after = [float(r["latency_ms"]) for r in raw_latency if r["patch_state"] == "after"]
check("Latency sample size", len(before) == 500 and len(after) == 500, f"{len(before)}/{len(after)}")
check("Latency source matches final firmware capture", sorted(before) == sorted(raw_before) and sorted(after) == sorted(raw_after), f"{median(before):.6f}/{median(after):.6f} ms")

activation = [float(r["activation_latency_ms"]) for r in csv_rows("fig56_activation_detail.csv")]
with (FINAL_TIMING_RESULTS / "patch_activation_detail.csv").open(newline="", encoding="utf-8") as handle:
    raw_activation = [float(r["activation_latency_ms"]) for r in csv.DictReader(handle)]
check("Activation sample size", len(activation) == 100, "n=100")
check("Activation source matches final firmware capture", activation == raw_activation, f"{median(activation):.6f} ms")

observer = csv_rows("fig57_observer_validation.csv")
check("Observer conditions", len(observer) == 6, "three runs x two states")
check("Observer request/response coverage", all(int(r["request_seen"]) == int(r["total"]) and int(r["response_seen"]) == int(r["total"]) for r in observer), "6,000/6,000 request and response records")
check("Observer classification consistency", sum(int(r["consistent"]) for r in observer) == 6000, "6,000/6,000")
observer_timing = csv_rows("fig57_observer_timing.csv")
valid_timing = [r for r in observer_timing if r["interval_valid_for_timing_plot"] == "true"]
excluded_timing = [r for r in observer_timing if r["interval_valid_for_timing_plot"] == "false"]
check("Observer timing source retained", len(observer_timing) == 6000, "all 6,000 records retained")
check("Observer timing plot validity", len(valid_timing) == 5999, "5,999 valid intervals")
check("Observer counter-boundary exclusion", len(excluded_timing) == 1 and excluded_timing[0]["timing_plot_exclusion_reason"] == "observer_counter_reset_or_wrap_boundary", "one explicitly labelled exclusion")

fleet = {r["strategy"]: r for r in csv_rows("fig58_fleet_summary.csv")}
ota = float(fleet["ota_only"]["cumulative_exposure_vehicle_days"])
hot = float(fleet["hotpatch_first"]["cumulative_exposure_vehicle_days"])
reduction = 100 * (1 - hot / ota)
check("Fleet exposure reduction", abs(reduction - 68.68) < .01, f"{reduction:.3f}%")
check("Fleet 80% protection", abs(float(fleet["hotpatch_first"]["time_to_80pct_protection_h"]) - 16.883333) < 1e-5, fleet["hotpatch_first"]["time_to_80pct_protection_h"] + " h")
sensitivity = csv_rows("fig59_fleet_sensitivity.csv")
check("Fleet sensitivity grid", len(sensitivity) == 16, "4 x 4")
base_cell = next(r for r in sensitivity if round(float(r["hotpatch_capable_pct"])) == 85 and round(float(r["additional_delivery_delay_h"])) == 0)
check("Fleet sensitivity exact base cell", abs(float(base_cell["exposure_reduction_pct"]) - reduction) < 1e-3, f"{float(base_cell['exposure_reduction_pct']):.6f}% matches Fig. 5.8 within CSV rounding")
check("Fleet sensitivity same event model", all(r["model"] == "same_discrete_event_model_as_fleet_main" for r in sensitivity), "same discrete-event model")

table_dir = BASE / "tables"
for name in ("table51_benign_state_integrity.tex", "table52_software_hardware_agreement.tex", "table53_resource_footprint.tex"):
    path = table_dir / name
    check(f"{name} exists", path.exists() and path.stat().st_size > 0, f"{path.stat().st_size if path.exists() else 0} bytes")
with (table_dir / "table52_software_hardware_agreement.csv").open(newline="", encoding="utf-8") as handle:
    agreement = {r["metric"]: r for r in csv.DictReader(handle)}
check("Software-hardware response agreement", agreement["Response payload"]["total_agreement"] == "2000/2000", agreement["Response payload"]["total_agreement"])
check("State/readback limitation explicit", agreement["State/readback agreement"]["total_agreement"] == "requires paired readback capture", agreement["State/readback agreement"]["total_agreement"])
with (table_dir / "table53_resource_footprint.csv").open(newline="", encoding="utf-8") as handle:
    resources = {r["metric"]: r for r in csv.DictReader(handle)}
with (table_dir / "table53_resource_build_measurements.csv").open(newline="", encoding="utf-8") as handle:
    resource_build = next(csv.DictReader(handle))
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
check(
    "Resource Flash delta matches final build",
    resources["Firmware Flash (text + data)"]["delta_or_status"] == f"+{measured_flash_delta} B",
    resources["Firmware Flash (text + data)"]["delta_or_status"],
)
check(
    "Resource RAM delta matches final build",
    resources["Static RAM (data + bss)"]["delta_or_status"] == f"+{measured_ram_delta} B",
    resources["Static RAM (data + bss)"]["delta_or_status"],
)


passed = sum(ok for _, ok, _ in checks)
for name, ok, evidence in checks:
    print(f"{'PASS' if ok else 'FAIL'}: {name} ({evidence})")
print(f"QA {passed}/{len(checks)} passed")
if passed != len(checks):
    raise SystemExit(1)
