#!/usr/bin/env python3
"""Derive event-level timeline CSV from hardware fuzz observer detail CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def derive(detail_csv: Path, timeline_csv: Path) -> int:
    rows = load_rows(detail_csv)
    if not rows:
        raise RuntimeError(f"no rows in {detail_csv}")

    first_can0_ns = int(rows[0]["send_monotonic_ns"])
    observer_starts = [row["observer_request_timestamp_us"] for row in rows if row["observer_request_timestamp_us"]]
    first_observer_us = int(observer_starts[0]) if observer_starts else 0

    timeline_csv.parent.mkdir(parents=True, exist_ok=True)
    with timeline_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "trial",
                "source",
                "event",
                "elapsed_ms",
                "payload_hex",
                "response_class",
                "attack_pass",
                "observer_consistent",
            ],
        )
        writer.writeheader()
        for row in rows:
            trial = row["trial"]
            common = {
                "trial": trial,
                "response_class": row["response_class"],
                "attack_pass": row["attack_pass"],
                "observer_consistent": row["observer_consistent"],
            }
            writer.writerow(
                {
                    **common,
                    "source": "can0",
                    "event": "request_send",
                    "elapsed_ms": f"{(int(row['send_monotonic_ns']) - first_can0_ns) / 1_000_000.0:.6f}",
                    "payload_hex": row["request_payload"],
                }
            )
            if row["recv_monotonic_ns"]:
                writer.writerow(
                    {
                        **common,
                        "source": "can0",
                        "event": "response_recv",
                        "elapsed_ms": f"{(int(row['recv_monotonic_ns']) - first_can0_ns) / 1_000_000.0:.6f}",
                        "payload_hex": row["response_payload"],
                    }
                )
            if row["observer_request_timestamp_us"]:
                writer.writerow(
                    {
                        **common,
                        "source": "nucleo",
                        "event": "request_seen",
                        "elapsed_ms": f"{(int(row['observer_request_timestamp_us']) - first_observer_us) / 1000.0:.6f}",
                        "payload_hex": row["request_payload"],
                    }
                )
            if row["observer_response_timestamp_us"]:
                writer.writerow(
                    {
                        **common,
                        "source": "nucleo",
                        "event": "response_seen",
                        "elapsed_ms": f"{(int(row['observer_response_timestamp_us']) - first_observer_us) / 1000.0:.6f}",
                        "payload_hex": row["response_payload"],
                    }
                )
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detail", required=True, help="Input hardware fuzz detail CSV.")
    parser.add_argument("--timeline", required=True, help="Output event-level timeline CSV.")
    args = parser.parse_args()

    count = derive(Path(args.detail), Path(args.timeline))
    print(f"derived timeline events for {count} trials")
    print(f"wrote {args.timeline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
