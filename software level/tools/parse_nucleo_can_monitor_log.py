#!/usr/bin/env python3
"""Convert Nucleo CAN observer UART logs into CSV."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MonitorFrame:
    source_line: int
    timestamp_us: int
    can_id: int
    dlc: int
    data_hex: str
    direction: str
    uds_payload_hex: str


def parse_single_frame_payload(data_hex: str) -> str:
    data = bytes.fromhex(data_hex)
    if not data:
        return ""
    pci = data[0]
    if (pci >> 4) != 0:
        return ""
    payload_len = pci & 0x0F
    if payload_len > 7 or len(data) < 1 + payload_len:
        return ""
    return data[1 : 1 + payload_len].hex().upper()


def parse_monitor_line(line: str, source_line: int) -> MonitorFrame | None:
    line = line.strip()
    if not line.startswith("MON,"):
        return None

    parts = line.split(",", 4)
    if len(parts) != 5:
        return None

    _, timestamp_text, can_id_text, dlc_text, data_hex = parts
    can_id = int(can_id_text, 16)
    direction = "request" if can_id == 0x7E0 else "response" if can_id == 0x7E8 else "other"

    return MonitorFrame(
        source_line=source_line,
        timestamp_us=int(timestamp_text),
        can_id=can_id,
        dlc=int(dlc_text),
        data_hex=data_hex.upper(),
        direction=direction,
        uds_payload_hex=parse_single_frame_payload(data_hex),
    )


def convert(log_path: Path, csv_path: Path) -> list[MonitorFrame]:
    frames: list[MonitorFrame] = []
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        frame = parse_monitor_line(line, line_number)
        if frame is not None:
            frames.append(frame)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "source_line",
                "timestamp_us",
                "elapsed_ms",
                "can_id_hex",
                "dlc",
                "data_hex",
                "direction",
                "uds_payload_hex",
            ],
        )
        writer.writeheader()
        start_us = frames[0].timestamp_us if frames else 0
        for frame in frames:
            writer.writerow(
                {
                    "source_line": frame.source_line,
                    "timestamp_us": frame.timestamp_us,
                    "elapsed_ms": f"{(frame.timestamp_us - start_us) / 1000.0:.3f}",
                    "can_id_hex": f"0x{frame.can_id:03X}",
                    "dlc": frame.dlc,
                    "data_hex": frame.data_hex,
                    "direction": frame.direction,
                    "uds_payload_hex": frame.uds_payload_hex,
                }
            )
    return frames


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="Input UART log captured from the Nucleo observer.")
    parser.add_argument("--csv", required=True, help="Output CSV path.")
    args = parser.parse_args()

    frames = convert(Path(args.log), Path(args.csv))
    request_count = sum(1 for frame in frames if frame.direction == "request")
    response_count = sum(1 for frame in frames if frame.direction == "response")
    print(f"parsed {len(frames)} frames: {request_count} requests, {response_count} responses")
    print(f"wrote {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

