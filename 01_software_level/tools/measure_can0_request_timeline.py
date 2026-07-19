#!/usr/bin/env python3
"""Measure a real SocketCAN UDS request timeline and render a thesis PDF."""

from __future__ import annotations

import argparse
import csv
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000
CAN_SFF_MASK = 0x000007FF
CAN_RAW_FILTER = 1

DEFAULT_REQUEST_ID = 0x7E0
DEFAULT_RESPONSE_ID = 0x7E8
UDS_SEED_MASK = 0xA55A
KINTSUGI_CONTROL_DID = 0xF190

DEFAULT_CSV = "software level/charts/can0_request_timeline_latest.csv"
DEFAULT_PDF = "software level/thesis_figures/pdf/fig12_can0_request_timeline.pdf"


@dataclass(frozen=True)
class RequestSpec:
    step: str
    payload: bytes


@dataclass(frozen=True)
class TimelineRow:
    trial: int
    step_index: int
    step: str
    request_payload: bytes
    response_payload: bytes | None
    request_can_id: int
    response_can_id: int
    send_wall_iso: str
    send_wall_ns: int
    send_monotonic_ns: int
    recv_monotonic_ns: int | None
    elapsed_start_ms: float
    elapsed_end_ms: float
    latency_ms: float | None
    response_class: str
    response_sid: str
    original_sid: str
    nrc: str
    note: str


def pack_can_frame(arbitration_id: int, data: bytes) -> bytes:
    if len(data) > 8:
        raise ValueError("classic CAN data must be <= 8 bytes")
    padded = data + bytes(8 - len(data))
    return struct.pack("=IB3x8s", arbitration_id, len(data), padded)


def unpack_can_frame(raw: bytes) -> tuple[int, bytes]:
    can_id, dlc, data = struct.unpack("=IB3x8s", raw)
    arbitration_id = can_id & CAN_SFF_MASK
    if can_id & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG):
        arbitration_id = can_id
    return arbitration_id, data[:dlc]


def pack_single_frame_payload(payload: bytes) -> bytes:
    if len(payload) > 7:
        raise ValueError("single-frame UDS payload must be <= 7 bytes")
    frame_data = bytes([len(payload)]) + payload
    return frame_data + bytes(8 - len(frame_data))


def unpack_single_frame_payload(data: bytes) -> bytes | None:
    if not data:
        return None
    payload_length = data[0] & 0x0F
    if (data[0] >> 4) != 0 or payload_length > 7 or len(data) < 1 + payload_length:
        return None
    return data[1 : 1 + payload_length]


def hex_bytes(data: bytes | None) -> str:
    if data is None:
        return "<none>"
    return data.hex().upper()


def wall_iso_from_ns(timestamp_ns: int) -> str:
    return datetime.fromtimestamp(timestamp_ns / 1_000_000_000).astimezone().isoformat(timespec="microseconds")


def classify_response(payload: bytes | None) -> tuple[str, str, str, str, str]:
    if payload is None:
        return "timeout", "", "", "", "no response before timeout"
    if len(payload) == 0:
        return "malformed", "", "", "", "empty UDS payload"
    sid = payload[0]
    if sid == 0x7F:
        original_sid = f"0x{payload[1]:02X}" if len(payload) > 1 else ""
        nrc = f"0x{payload[2]:02X}" if len(payload) > 2 else ""
        return "negative", "0x7F", original_sid, nrc, "negative response"
    if sid >= 0x40:
        return "positive", f"0x{sid:02X}", "", "", "positive response"
    return "other", f"0x{sid:02X}", "", "", "non-standard response SID"


def parse_seed(payload: bytes | None) -> int | None:
    if payload is None or len(payload) != 4:
        return None
    if payload[0] != 0x67 or payload[1] != 0x01:
        return None
    return (payload[2] << 8) | payload[3]


def drain_socket(can_socket: socket.socket, max_seconds: float = 0.05) -> int:
    drained = 0
    deadline = time.perf_counter() + max_seconds
    previous_timeout = can_socket.gettimeout()
    can_socket.settimeout(0.001)
    try:
        while time.perf_counter() < deadline:
            try:
                can_socket.recv(16)
                drained += 1
            except socket.timeout:
                break
    finally:
        can_socket.settimeout(previous_timeout)
    return drained


def bind_can_socket(interface: str, response_id: int) -> socket.socket:
    can_socket = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    can_socket.bind((interface,))
    can_filter = struct.pack("=II", response_id, CAN_SFF_MASK)
    can_socket.setsockopt(socket.SOL_CAN_RAW, CAN_RAW_FILTER, can_filter)
    return can_socket


def send_timed_request(
    can_socket: socket.socket,
    request_id: int,
    response_id: int,
    spec: RequestSpec,
    timeout_s: float,
    trial: int,
    step_index: int,
    first_send_ns: int | None,
) -> tuple[TimelineRow, int]:
    frame = pack_can_frame(request_id, pack_single_frame_payload(spec.payload))
    send_wall_ns = time.time_ns()
    send_monotonic_ns = time.perf_counter_ns()
    if first_send_ns is None:
        first_send_ns = send_monotonic_ns
    can_socket.send(frame)

    response_payload: bytes | None = None
    recv_monotonic_ns: int | None = None
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        can_socket.settimeout(max(0.001, deadline - time.perf_counter()))
        try:
            raw = can_socket.recv(16)
        except socket.timeout:
            break
        arbitration_id, data = unpack_can_frame(raw)
        if arbitration_id != response_id:
            continue
        recv_monotonic_ns = time.perf_counter_ns()
        response_payload = unpack_single_frame_payload(data)
        break

    end_ns = recv_monotonic_ns if recv_monotonic_ns is not None else time.perf_counter_ns()
    response_class, response_sid, original_sid, nrc, note = classify_response(response_payload)
    if response_payload is not None:
        note = f"{note}; response={hex_bytes(response_payload)}"

    row = TimelineRow(
        trial=trial,
        step_index=step_index,
        step=spec.step,
        request_payload=spec.payload,
        response_payload=response_payload,
        request_can_id=request_id,
        response_can_id=response_id,
        send_wall_iso=wall_iso_from_ns(send_wall_ns),
        send_wall_ns=send_wall_ns,
        send_monotonic_ns=send_monotonic_ns,
        recv_monotonic_ns=recv_monotonic_ns,
        elapsed_start_ms=(send_monotonic_ns - first_send_ns) / 1_000_000,
        elapsed_end_ms=(end_ns - first_send_ns) / 1_000_000,
        latency_ms=((recv_monotonic_ns - send_monotonic_ns) / 1_000_000) if recv_monotonic_ns is not None else None,
        response_class=response_class,
        response_sid=response_sid,
        original_sid=original_sid,
        nrc=nrc,
        note=note,
    )
    return row, first_send_ns


def base_sequence(trigger_kintsugi_hotpatch: bool) -> list[RequestSpec]:
    sequence: list[RequestSpec] = []
    if trigger_kintsugi_hotpatch:
        sequence.append(
            RequestSpec(
                "trigger_kintsugi_hotpatch",
                bytes([0x2E, (KINTSUGI_CONTROL_DID >> 8) & 0xFF, KINTSUGI_CONTROL_DID & 0xFF, 0x01]),
            )
        )
    sequence.extend(
        [
            RequestSpec("reset_default_session", bytes([0x10, 0x01])),
            RequestSpec("enter_extended_session", bytes([0x10, 0x03])),
            RequestSpec("request_security_seed", bytes([0x27, 0x01])),
        ]
    )
    return sequence


def run_trial(
    can_socket: socket.socket,
    args: argparse.Namespace,
    trial: int,
    first_send_ns: int | None,
) -> tuple[list[TimelineRow], int]:
    rows: list[TimelineRow] = []
    sequence = base_sequence(args.trigger_kintsugi_hotpatch)

    for spec in sequence:
        row, first_send_ns = send_timed_request(
            can_socket,
            args.request_id,
            args.response_id,
            spec,
            args.timeout,
            trial,
            len(rows) + 1,
            first_send_ns,
        )
        rows.append(row)
        if args.inter_step_delay_ms > 0:
            time.sleep(args.inter_step_delay_ms / 1000)

    seed = parse_seed(rows[-1].response_payload)
    key = (seed ^ UDS_SEED_MASK) if seed is not None else 0
    dynamic_specs = [
        RequestSpec("send_key_from_weak_transform", bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF])),
        RequestSpec("write_did_after_security_access", bytes([0x2E, 0x12, 0x34, 0xCA, 0xFE])),
        RequestSpec("read_back_did_0x1234", bytes([0x22, 0x12, 0x34])),
    ]
    for spec in dynamic_specs:
        row, first_send_ns = send_timed_request(
            can_socket,
            args.request_id,
            args.response_id,
            spec,
            args.timeout,
            trial,
            len(rows) + 1,
            first_send_ns,
        )
        rows.append(row)
        if args.inter_step_delay_ms > 0:
            time.sleep(args.inter_step_delay_ms / 1000)

    return rows, first_send_ns


def write_csv(path: Path, rows: list[TimelineRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "trial",
                "step_index",
                "step",
                "request_payload",
                "response_payload",
                "request_can_id",
                "response_can_id",
                "send_wall_iso",
                "send_wall_ns",
                "send_monotonic_ns",
                "recv_monotonic_ns",
                "elapsed_start_ms",
                "elapsed_end_ms",
                "latency_ms",
                "response_class",
                "response_sid",
                "original_sid",
                "nrc",
                "note",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.trial,
                    row.step_index,
                    row.step,
                    hex_bytes(row.request_payload),
                    hex_bytes(row.response_payload),
                    f"0x{row.request_can_id:03X}",
                    f"0x{row.response_can_id:03X}",
                    row.send_wall_iso,
                    row.send_wall_ns,
                    row.send_monotonic_ns,
                    "" if row.recv_monotonic_ns is None else row.recv_monotonic_ns,
                    f"{row.elapsed_start_ms:.6f}",
                    f"{row.elapsed_end_ms:.6f}",
                    "" if row.latency_ms is None else f"{row.latency_ms:.6f}",
                    row.response_class,
                    row.response_sid,
                    row.original_sid,
                    row.nrc,
                    row.note,
                ]
            )


def read_timeline_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def generate_pdf(csv_path: Path, pdf_path: Path, title: str) -> Path:
    rows = read_timeline_csv(csv_path)
    if not rows:
        raise RuntimeError(f"no rows in {csv_path}")

    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    colors = {
        "positive": "#2E7D32",
        "negative": "#D95319",
        "timeout": "#A2142F",
        "malformed": "#7E2F8E",
        "other": "#6E6E6E",
    }

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
            "grid.color": "#D9D9D9",
            "grid.linewidth": 0.7,
        }
    )

    fig, (ax_timeline, ax_latency) = plt.subplots(
        2,
        1,
        figsize=(9.0, 5.8),
        gridspec_kw={"height_ratios": [1.5, 1.0]},
    )
    fig.suptitle(title, fontweight="bold", y=0.98)

    labels: list[str] = []
    starts: list[float] = []
    ends: list[float] = []
    latencies: list[float] = []
    latency_is_timeout: list[bool] = []
    bar_colors: list[str] = []
    response_labels: list[str] = []

    for index, row in enumerate(rows):
        label = row["step"]
        if len({r["trial"] for r in rows}) > 1:
            label = f"T{row['trial']} {label}"
        labels.append(label)
        starts.append(float(row["elapsed_start_ms"]))
        ends.append(float(row["elapsed_end_ms"]))
        timeout_row = not row["latency_ms"]
        latency = (
            float(row["latency_ms"])
            if row["latency_ms"]
            else float(row["elapsed_end_ms"]) - float(row["elapsed_start_ms"])
        )
        latencies.append(latency)
        latency_is_timeout.append(timeout_row)
        bar_colors.append(colors.get(row["response_class"], colors["other"]))
        response_labels.append(row["response_payload"])

        y = len(rows) - index - 1
        color = colors.get(row["response_class"], colors["other"])
        ax_timeline.hlines(y, starts[-1], ends[-1], color=color, linewidth=4)
        ax_timeline.plot(starts[-1], y, marker="|", color="#202020", markersize=10)
        ax_timeline.plot(ends[-1], y, marker="o", color=color, markersize=4)
        ax_timeline.text(
            ends[-1] + max(0.08, max(ends) * 0.01 if ends else 0.08),
            y,
            row["response_payload"],
            va="center",
            fontsize=7.5,
            color="#202020",
        )

    y_positions = list(range(len(rows) - 1, -1, -1))
    ax_timeline.set_yticks(y_positions, labels)
    ax_timeline.set_xlabel("Elapsed time since first request send (ms)")
    ax_timeline.set_title("Observed request-response timeline on can0", loc="left")
    ax_timeline.grid(axis="x")
    ax_timeline.grid(axis="y", visible=False)

    x_positions = list(range(len(rows)))
    bars = ax_latency.bar(x_positions, latencies, color=bar_colors, edgecolor="#303030", linewidth=0.6)
    ax_latency.set_xticks(x_positions, [row["step"].replace("_", "\n") for row in rows])
    ax_latency.set_ylabel("Latency (ms)")
    ax_latency.set_title("Per-request latency", loc="left")
    ax_latency.grid(axis="y")
    ax_latency.grid(axis="x", visible=False)
    for bar, latency, response, timed_out in zip(bars, latencies, response_labels, latency_is_timeout):
        label = "timeout" if timed_out and response == "<none>" else f"{latency:.2f}"
        ax_latency.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(latencies + [1.0]) * 0.03,
            label,
            ha="center",
            va="bottom",
            fontsize=7.5,
        )

    first = rows[0]
    last = rows[-1]
    total_ms = float(last["elapsed_end_ms"])
    subtitle = (
        f"interface={first['request_can_id']}->{first['response_can_id']}  "
        f"first_send={first['send_wall_iso']}  total={total_ms:.3f} ms"
    )
    fig.text(0.01, 0.015, subtitle, fontsize=8, color="#6E6E6E")
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)
    return pdf_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure a real UDS request timeline over SocketCAN and render CSV/PDF artifacts."
    )
    parser.add_argument("--interface", default="can0", help="SocketCAN interface name")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--timeout", default=1.0, type=float, help="response timeout in seconds")
    parser.add_argument("--iterations", default=1, type=int, help="number of complete request-chain trials")
    parser.add_argument("--inter-step-delay-ms", default=0.0, type=float)
    parser.add_argument(
        "--trigger-kintsugi-hotpatch",
        action="store_true",
        help="Send 0x2E F190 01 before each chain to trigger the board Kintsugi bridge.",
    )
    parser.add_argument("--csv", default=DEFAULT_CSV, help="CSV output path")
    parser.add_argument("--pdf", default=DEFAULT_PDF, help="PDF output path")
    parser.add_argument("--title", default="Real CAN0 UDS Request Timeline")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.iterations < 1:
        print("--iterations must be >= 1", file=sys.stderr)
        return 2

    csv_path = Path(args.csv)
    pdf_path = Path(args.pdf)
    all_rows: list[TimelineRow] = []
    first_send_ns: int | None = None

    try:
        with bind_can_socket(args.interface, args.response_id) as can_socket:
            drained = drain_socket(can_socket)
            if drained:
                print(f"drained {drained} stale response frame(s) from {args.interface}")
            for trial in range(1, args.iterations + 1):
                rows, first_send_ns = run_trial(can_socket, args, trial, first_send_ns)
                all_rows.extend(rows)
    except OSError as exc:
        print(f"cannot use {args.interface}: {exc}", file=sys.stderr)
        return 2

    write_csv(csv_path, all_rows)
    generated_pdf = generate_pdf(csv_path, pdf_path, args.title)

    for row in all_rows:
        latency = "timeout" if row.latency_ms is None else f"{row.latency_ms:.3f} ms"
        print(
            f"T{row.trial}.{row.step_index} {row.step:34} "
            f"req={hex_bytes(row.request_payload):12} "
            f"resp={hex_bytes(row.response_payload):14} "
            f"{latency}"
        )
    print(f"\nwrote {csv_path}")
    print(f"wrote {generated_pdf}")

    received_count = sum(1 for row in all_rows if row.response_payload is not None)
    if received_count == 0:
        print(
            "\nwarning: no responses were received on the configured response CAN ID; "
            "the CSV/PDF contain a real all-timeout timeline.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
