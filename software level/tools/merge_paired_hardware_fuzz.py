#!/usr/bin/env python3
"""Merge and validate the six paired hardware-fuzz campaigns."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    index = (len(ordered) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default="software level/results/20260710_hardware_fuzz")
    args = parser.parse_args()
    directory = Path(args.input_dir)
    paths = sorted(directory.glob("hardware_uds_2e_fuzz_observer_*_detail.csv"))
    if not paths:
        raise SystemExit("no campaign detail CSV files found")
    rows: list[dict[str, str]] = []
    for path in paths:
        with path.open(newline="", encoding="utf-8") as handle:
            rows.extend(csv.DictReader(handle))
    rows.sort(key=lambda row: (row["run_id"], row["patch_state"], int(row["case_id"])))
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row["run_id"], row["patch_state"])].append(row)

    pair_notes: list[str] = []
    pair_ok = True
    for run_id in sorted({key[0] for key in groups}):
        before = groups.get((run_id, "before"), [])
        after = groups.get((run_id, "after"), [])
        identical = len(before) == len(after) and all(
            left["case_id"] == right["case_id"]
            and left["request_payload"] == right["request_payload"]
            and left["mutation_kind"] == right["mutation_kind"]
            for left, right in zip(before, after)
        )
        pair_ok &= identical
        pair_notes.append(f"{run_id}_paired_corpus_identical={str(identical).lower()}")

    combined_path = directory / "hardware_fuzz_paired_detail.csv"
    with combined_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary_rows: list[dict[str, object]] = []
    for (run_id, patch_state), group in sorted(groups.items()):
        latencies = [float(row["latency_ms"]) for row in group if row["latency_ms"]]
        successes = sum(row["attack_success"] == "true" for row in group)
        consistent = sum(row["observer_consistent"] == "true" for row in group)
        summary_rows.append(
            {
                "run_id": run_id,
                "random_seed": group[0]["random_seed"],
                "patch_state": patch_state,
                "total_cases": len(group),
                "attack_successes": successes,
                "attack_success_rate": f"{successes / len(group):.6f}",
                "timeouts": sum(row["timeout"] == "true" for row in group),
                "observer_consistent": consistent,
                "observer_consistency_rate": f"{consistent / len(group):.6f}",
                "latency_median_ms": f"{statistics.median(latencies):.6f}",
                "latency_p95_ms": f"{percentile(latencies, 0.95):.6f}",
                "latency_p99_ms": f"{percentile(latencies, 0.99):.6f}",
            }
        )
    summary_path = directory / "hardware_fuzz_paired_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)

    mutation_groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        mutation_groups[(row["run_id"], row["patch_state"], row["mutation_kind"])].append(row)
    mutation_rows: list[dict[str, object]] = []
    for (run_id, patch_state, mutation_kind), group in sorted(mutation_groups.items()):
        successes = sum(row["attack_success"] == "true" for row in group)
        mutation_rows.append(
            {
                "run_id": run_id,
                "patch_state": patch_state,
                "mutation_kind": mutation_kind,
                "cases": len(group),
                "attack_successes": successes,
                "attack_success_rate": f"{successes / len(group):.6f}",
            }
        )
    with (directory / "hardware_fuzz_by_mutation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(mutation_rows[0]))
        writer.writeheader()
        writer.writerows(mutation_rows)

    log_lines = [
        f"source_detail_files={len(paths)}",
        f"combined_rows={len(rows)}",
        f"paired_validation_passed={str(pair_ok).lower()}",
        *pair_notes,
    ]
    (directory / "hardware_fuzz_paired_validation.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print("\n".join(log_lines))
    print(f"wrote {combined_path}")
    print(f"wrote {summary_path}")
    return 0 if pair_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
