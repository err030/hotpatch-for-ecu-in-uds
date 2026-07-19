#!/usr/bin/env python3
"""Create distribution-ready summaries from paired real-CAN result CSVs."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def percentile(values: list[float], q: float) -> float:
    values = sorted(values)
    position = (len(values) - 1) * q
    lo = int(position)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (position - lo)


def stats(values: list[float]) -> dict[str, str]:
    return {
        "count": str(len(values)),
        "median_ms": f"{statistics.median(values):.6f}",
        "q1_ms": f"{percentile(values, 0.25):.6f}",
        "q3_ms": f"{percentile(values, 0.75):.6f}",
        "p95_ms": f"{percentile(values, 0.95):.6f}",
        "p99_ms": f"{percentile(values, 0.99):.6f}",
    }


def write(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default="software level/results/20260710_paired_hardware")
    args = parser.parse_args()
    directory = Path(args.input_dir)
    latency = read(directory / "real_can_latency_detail.csv")
    state = read(directory / "real_can_state_integrity.csv")
    benign_path = directory / "hardware_benign_control_detail.csv"
    benign = read(benign_path) if benign_path.exists() else []
    activation = read(directory / "patch_activation_detail.csv")

    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    timeouts: dict[tuple[str, str], int] = defaultdict(int)
    for row in latency:
        if row["warmup"] == "true":
            continue
        key = (row["patch_state"], row["step"])
        if row["latency_ms"]:
            grouped[key].append(float(row["latency_ms"]))
        else:
            timeouts[key] += 1
    latency_summary: list[dict[str, object]] = []
    for (patch_state, step), values in sorted(grouped.items()):
        latency_summary.append(
            {
                "patch_state": patch_state,
                "step": step,
                **stats(values),
                "timeouts": timeouts[(patch_state, step)],
            }
        )
    write(directory / "real_can_latency_summary.csv", latency_summary)

    by_key = {(row["patch_state"], row["trial"], row["step"]): row for row in latency if row["warmup"] == "false"}
    delta_rows: list[dict[str, object]] = []
    for trial in sorted({row["trial"] for row in latency if row["warmup"] == "false"}, key=int):
        for step in sorted({row["step"] for row in latency}):
            before = by_key.get(("before", trial, step))
            after = by_key.get(("after", trial, step))
            if before and after and before["latency_ms"] and after["latency_ms"]:
                delta_rows.append(
                    {
                        "trial": trial,
                        "step": step,
                        "before_latency_ms": before["latency_ms"],
                        "after_latency_ms": after["latency_ms"],
                        "delta_after_minus_before_ms": f"{float(after['latency_ms']) - float(before['latency_ms']):.6f}",
                    }
                )
    write(directory / "real_can_latency_paired_delta.csv", delta_rows)

    state_summary: list[dict[str, object]] = []
    for patch_state in ("before", "after"):
        subset = [row for row in state if row["patch_state"] == patch_state and row["warmup"] == "false"]
        state_summary.append(
            {
                "patch_state": patch_state,
                "trials": len(subset),
                "attack_successes": sum(row["attack_success"] == "true" for row in subset),
                "state_changes": sum(row["state_changed"] == "true" for row in subset),
                "expected_write_response": "6E1234" if patch_state == "before" else "7F2E31",
                "matching_write_responses": sum(row["write_response"] == ("6E1234" if patch_state == "before" else "7F2E31") for row in subset),
            }
        )
    write(directory / "real_can_state_integrity_summary.csv", state_summary)

    activation_values = [float(row["activation_latency_ms"]) for row in activation if row["activation_latency_ms"]]
    activation_summary = [{**stats(activation_values), "protected_trials": sum(row["protected"] == "true" for row in activation), "total_trials": len(activation), "measurement_scope": "host_end_to_end_monotonic"}]
    write(directory / "patch_activation_summary.csv", activation_summary)

    state_by_profile = {
        patch_state: [row for row in state if row["patch_state"] == patch_state]
        for patch_state in ("before", "after")
    }
    continuity_checks = {
        patch_state: sum(
            rows[index]["value_before"] == rows[index - 1]["value_after"]
            for index in range(1, len(rows))
        )
        for patch_state, rows in state_by_profile.items()
    }
    checks = {
        "latency_expected_rows": len(latency) == 7280,
        "latency_no_timeouts": all(row["timeout"] == "false" for row in latency),
        "state_before_500_of_500_changed": sum(
            row["patch_state"] == "before" and row["warmup"] == "false" and row["state_changed"] == "true"
            for row in state
        ) == 500,
        "state_after_0_of_500_changed": sum(
            row["patch_state"] == "after" and row["warmup"] == "false" and row["state_changed"] == "true"
            for row in state
        ) == 0,
        "state_after_all_values_preserved": all(
            row["value_before"] == row["value_after"]
            for row in state
            if row["patch_state"] == "after" and row["warmup"] == "false"
        ),
        "state_profile_reset_confirmed": all(
            sum(row["state_reset_confirmed"] == "true" for row in rows) == 1
            and rows[0]["state_reset_confirmed"] == "true"
            for rows in state_by_profile.values()
        ),
        "state_profile_value_chain_complete": all(
            continuity_checks[patch_state] == len(rows) - 1
            for patch_state, rows in state_by_profile.items()
        ),
        "state_unique_attempted_values": all(
            len({row["attempted_value"] for row in rows}) == len(rows)
            for rows in state_by_profile.values()
        ),
        "activation_100_of_100_protected": len(activation) == 100 and all(row["protected"] == "true" for row in activation),
        "activation_all_protected_responses_7f2e31": all(row["protected_response"] == "7F2E31" for row in activation),
    }
    log_lines = [
        *(f"{name}={'pass' if passed else 'fail'}" for name, passed in checks.items()),
        f"latency_detail_rows={len(latency)}",
        f"latency_non_warmup_rows={sum(row['warmup'] == 'false' for row in latency)}",
        f"latency_timeouts={sum(row['timeout'] == 'true' for row in latency)}",
        f"state_integrity_rows={len(state)}",
        f"after_state_changes={sum(row['patch_state'] == 'after' and row['state_changed'] == 'true' for row in state)}",
        f"activation_rows={len(activation)}",
        f"activation_protected={sum(row['protected'] == 'true' for row in activation)}",
        "runtime_task_jitter_status=not_instrumented_in_current_firmware",
    ]
    if benign:
        log_lines.extend(
            [
                f"benign_detail_rows={len(benign)}",
                f"benign_failed_operations={sum(row['passed'] != 'true' for row in benign)}",
            ]
        )
    (directory / "validation.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print("\n".join(log_lines))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
