#!/usr/bin/env python3
"""Measure staged Kintsugi runtime hotpatch lifecycle over SocketCAN.

This script complements the before/after UDS hotpatch experiment with a
"during" lifecycle view.  It intentionally separates Kintsugi receive,
schedule, and apply operations so the vehicle-specific experiment can show
that pending hotpatch states are observable and controlled before the ECU-local
UDS security policy becomes active.
"""

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
VALID_WRITE_DID = 0x1234
READ_ONLY_STATUS_DID = 0x1001

KINTSUGI_APPLY_ALL = 0x01
KINTSUGI_RECEIVE_ONLY = 0x02
KINTSUGI_SCHEDULE_ONLY = 0x03
KINTSUGI_APPLY_SCHEDULED = 0x04


@dataclass(frozen=True)
class StepResult:
    phase: str
    event: str
    request_payload: bytes
    response_payload: bytes | None
    expected: str
    passed: bool
    latency_ms: float | None
    wall_iso: str
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
    data = bytes([len(payload)]) + payload
    return data + bytes(8 - len(data))


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


def bind_can_socket(interface: str, response_id: int) -> socket.socket:
    can_socket = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    can_socket.bind((interface,))
    can_filter = struct.pack("=II", response_id, CAN_SFF_MASK)
    can_socket.setsockopt(socket.SOL_CAN_RAW, CAN_RAW_FILTER, can_filter)
    return can_socket


def drain_socket(can_socket: socket.socket, max_seconds: float = 0.03) -> None:
    deadline = time.perf_counter() + max_seconds
    previous_timeout = can_socket.gettimeout()
    can_socket.settimeout(0.001)
    try:
        while time.perf_counter() < deadline:
            try:
                can_socket.recv(16)
            except socket.timeout:
                break
    finally:
        can_socket.settimeout(previous_timeout)


def send_uds(
    can_socket: socket.socket,
    request_id: int,
    response_id: int,
    payload: bytes,
    timeout_s: float,
) -> tuple[bytes | None, float | None]:
    drain_socket(can_socket)
    frame = pack_can_frame(request_id, pack_single_frame_payload(payload))
    start_ns = time.perf_counter_ns()
    can_socket.send(frame)

    response_payload: bytes | None = None
    latency_ms: float | None = None
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
        end_ns = time.perf_counter_ns()
        response_payload = unpack_single_frame_payload(data)
        latency_ms = (end_ns - start_ns) / 1_000_000
        break
    return response_payload, latency_ms


def expected_seed(payload: bytes | None) -> tuple[bool, str]:
    if payload is None:
        return False, "no response"
    if len(payload) == 4 and payload[0] == 0x67 and payload[1] == 0x01:
        seed = (payload[2] << 8) | payload[3]
        return True, f"seed=0x{seed:04X}"
    return False, f"expected 6701xxxx, got {hex_bytes(payload)}"


def parse_seed(payload: bytes | None) -> int | None:
    if payload is None or len(payload) != 4:
        return None
    if payload[0] != 0x67 or payload[1] != 0x01:
        return None
    return (payload[2] << 8) | payload[3]


def add_step(
    rows: list[StepResult],
    can_socket: socket.socket,
    args: argparse.Namespace,
    phase: str,
    event: str,
    payload: bytes,
    expected_payload: bytes | None = None,
    expected_label: str | None = None,
) -> StepResult:
    response_payload, latency_ms = send_uds(
        can_socket,
        args.request_id,
        args.response_id,
        payload,
        args.timeout,
    )
    if expected_payload is None:
        passed, note = expected_seed(response_payload)
        expected = expected_label or "6701xxxx"
    else:
        passed = response_payload == expected_payload
        expected = expected_label or hex_bytes(expected_payload)
        note = (
            f"matched {hex_bytes(expected_payload)}"
            if passed
            else f"expected {hex_bytes(expected_payload)}, got {hex_bytes(response_payload)}"
        )
    row = StepResult(
        phase=phase,
        event=event,
        request_payload=payload,
        response_payload=response_payload,
        expected=expected,
        passed=passed,
        latency_ms=latency_ms,
        wall_iso=datetime.now().astimezone().isoformat(timespec="microseconds"),
        note=note,
    )
    rows.append(row)
    print_step(row)
    if args.inter_step_delay_ms > 0:
        time.sleep(args.inter_step_delay_ms / 1000)
    return row


def kintsugi_control_payload(command: int) -> bytes:
    return bytes([
        0x2E,
        (KINTSUGI_CONTROL_DID >> 8) & 0xFF,
        KINTSUGI_CONTROL_DID & 0xFF,
        command & 0xFF,
    ])


def run_attack_chain(
    rows: list[StepResult],
    can_socket: socket.socket,
    args: argparse.Namespace,
    phase: str,
    expect_blocked: bool,
) -> bool:
    add_step(
        rows,
        can_socket,
        args,
        phase,
        "enter_extended_session",
        bytes([0x10, 0x03]),
        bytes([0x50, 0x03, 0x00, 0x32, 0x13, 0x88]),
    )
    seed_step = add_step(
        rows,
        can_socket,
        args,
        phase,
        "request_security_seed",
        bytes([0x27, 0x01]),
        expected_payload=None,
        expected_label="6701xxxx",
    )
    seed = parse_seed(seed_step.response_payload)
    key = (seed ^ UDS_SEED_MASK) if seed is not None else 0
    add_step(
        rows,
        can_socket,
        args,
        phase,
        "send_key_from_weak_transform",
        bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF]),
        bytes([0x67, 0x02]),
    )
    write_step = add_step(
        rows,
        can_socket,
        args,
        phase,
        "write_did_after_security_access",
        bytes([0x2E, (VALID_WRITE_DID >> 8) & 0xFF, VALID_WRITE_DID & 0xFF, 0xCA, 0xFE]),
        bytes([0x7F, 0x2E, 0x31]) if expect_blocked else bytes([0x6E, 0x12, 0x34]),
        "7F2E31" if expect_blocked else "6E1234",
    )
    return write_step.passed


def run_benign_read(
    rows: list[StepResult],
    can_socket: socket.socket,
    args: argparse.Namespace,
    phase: str,
) -> bool:
    read_step = add_step(
        rows,
        can_socket,
        args,
        phase,
        "benign_read_status_did",
        bytes([0x22, (READ_ONLY_STATUS_DID >> 8) & 0xFF, READ_ONLY_STATUS_DID & 0xFF]),
        bytes([0x62, 0x10, 0x01, 0x42, 0x10]),
    )
    return read_step.passed


def print_step(row: StepResult) -> None:
    status = "PASS" if row.passed else "FAIL"
    latency = f"{row.latency_ms:.3f} ms" if row.latency_ms is not None else "timeout"
    print(
        f"{status:4} {row.phase:26} {row.event:34} "
        f"req={hex_bytes(row.request_payload):12} "
        f"resp={hex_bytes(row.response_payload):12} "
        f"lat={latency:>10} {row.note}"
    )


def write_csv(path: Path, rows: list[StepResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "phase",
            "event",
            "request_payload",
            "response_payload",
            "expected",
            "passed",
            "latency_ms",
            "wall_iso",
            "note",
        ])
        for row in rows:
            writer.writerow([
                row.phase,
                row.event,
                hex_bytes(row.request_payload),
                hex_bytes(row.response_payload),
                row.expected,
                "true" if row.passed else "false",
                "" if row.latency_ms is None else f"{row.latency_ms:.6f}",
                row.wall_iso,
                row.note,
            ])


def phase_summary(rows: list[StepResult]) -> list[dict[str, str]]:
    phases = []
    for phase in [
        "before_hotpatch",
        "during_received_pending",
        "during_scheduled_pending",
        "after_apply",
    ]:
        phase_rows = [row for row in rows if row.phase == phase]
        attack_row = next((row for row in phase_rows if row.event == "write_did_after_security_access"), None)
        benign_row = next((row for row in phase_rows if row.event == "benign_read_status_did"), None)
        phases.append({
            "phase": phase,
            "attack_expected": "blocked" if phase == "after_apply" else "success",
            "attack_observed": "blocked"
            if attack_row is not None and attack_row.response_payload == bytes([0x7F, 0x2E, 0x31])
            else "success"
            if attack_row is not None and attack_row.response_payload == bytes([0x6E, 0x12, 0x34])
            else "other",
            "attack_check_passed": "true" if attack_row is not None and attack_row.passed else "false",
            "benign_read_passed": "true" if benign_row is not None and benign_row.passed else "false",
        })
    return phases


def write_summary_csv(path: Path, summary_rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "phase",
                "attack_expected",
                "attack_observed",
                "attack_check_passed",
                "benign_read_passed",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)


def render_pdf(detail_rows: list[StepResult], summary_rows: list[dict[str, str]], pdf_path: Path) -> None:
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({
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
    })

    labels = ["before", "received\npending", "scheduled\npending", "after\napply"]
    phases = [row["phase"] for row in summary_rows]
    attack_success = [1 if row["attack_observed"] == "success" else 0 for row in summary_rows]
    attack_blocked = [1 if row["attack_observed"] == "blocked" else 0 for row in summary_rows]
    benign_pass = [1 if row["benign_read_passed"] == "true" else 0 for row in summary_rows]

    control_rows = [
        row for row in detail_rows
        if row.event in {
            "kintsugi_receive_hotpatch",
            "kintsugi_schedule_hotpatch",
            "kintsugi_apply_scheduled_hotpatch",
        }
    ]
    control_names = [row.event.replace("kintsugi_", "").replace("_hotpatch", "").replace("_", "\n") for row in control_rows]
    control_latency = [row.latency_ms or 0.0 for row in control_rows]

    all_latencies = [row.latency_ms for row in detail_rows if row.latency_ms is not None]

    fig, axes = plt.subplots(1, 3, figsize=(10.2, 3.6), gridspec_kw={"width_ratios": [1.25, 1.0, 1.0]})
    fig.suptitle("UDS-Level Kintsugi Runtime Hotpatch Lifecycle", fontweight="bold", y=1.05)

    x = np.arange(len(phases))
    width = 0.26
    ax = axes[0]
    ax.bar(x - width, attack_success, width, label="attack succeeds", color="#A2142F", edgecolor="#303030", zorder=3)
    ax.bar(x, attack_blocked, width, label="attack blocked", color="#0072BD", edgecolor="#303030", zorder=3)
    ax.bar(x + width, benign_pass, width, label="benign read passes", color="#2E7D32", edgecolor="#303030", zorder=3)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Observed outcome")
    ax.set_title("Lifecycle state behavior", loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=1)

    ax = axes[1]
    ax.bar(control_names, control_latency, color=["#4DBEEE", "#EDB120", "#7E2F8E"], edgecolor="#303030", zorder=3)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Kintsugi control transaction latency", loc="left")

    ax = axes[2]
    ax.hist(all_latencies, bins=min(18, max(5, len(all_latencies))), color="#77AC30", edgecolor="#303030", zorder=3)
    ax.set_xlabel("UDS response latency (ms)")
    ax.set_ylabel("Steps")
    ax.set_title("All lifecycle request latencies", loc="left")

    fig.text(
        0.01,
        -0.04,
        "During states are receive/schedule pending: the patch is stored or scheduled but the ECU-local UDS guard is not active until apply.",
        fontsize=8,
        color="#606060",
    )
    fig.tight_layout()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--timeout", default=1.0, type=float)
    parser.add_argument("--inter-step-delay-ms", default=20.0, type=float)
    parser.add_argument(
        "--csv",
        default="software level/charts/uds_kintsugi_during_lifecycle_latest.csv",
        help="Detailed lifecycle CSV output.",
    )
    parser.add_argument(
        "--summary-csv",
        default="software level/charts/uds_kintsugi_during_lifecycle_summary_latest.csv",
        help="Summary lifecycle CSV output.",
    )
    parser.add_argument(
        "--pdf",
        default="software level/thesis_figures/pdf/fig_kintsugi_during_lifecycle_latest.pdf",
        help="Lifecycle PDF figure output.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    rows: list[StepResult] = []

    try:
        can_socket = bind_can_socket(args.interface, args.response_id)
    except OSError as exc:
        print(f"cannot bind {args.interface}: {exc}", file=sys.stderr)
        return 2

    with can_socket:
        print("[phase] before_hotpatch: attack should succeed")
        run_attack_chain(rows, can_socket, args, "before_hotpatch", expect_blocked=False)
        run_benign_read(rows, can_socket, args, "before_hotpatch")

        add_step(
            rows,
            can_socket,
            args,
            "during_received_pending",
            "kintsugi_receive_hotpatch",
            kintsugi_control_payload(KINTSUGI_RECEIVE_ONLY),
            bytes([0x6E, 0xF1, 0x90]),
        )
        print("[phase] during_received_pending: patch is stored but not active")
        run_attack_chain(rows, can_socket, args, "during_received_pending", expect_blocked=False)
        run_benign_read(rows, can_socket, args, "during_received_pending")

        add_step(
            rows,
            can_socket,
            args,
            "during_scheduled_pending",
            "kintsugi_schedule_hotpatch",
            kintsugi_control_payload(KINTSUGI_SCHEDULE_ONLY),
            bytes([0x6E, 0xF1, 0x90]),
        )
        print("[phase] during_scheduled_pending: applicator is prepared but policy is not active")
        run_attack_chain(rows, can_socket, args, "during_scheduled_pending", expect_blocked=False)
        run_benign_read(rows, can_socket, args, "during_scheduled_pending")

        add_step(
            rows,
            can_socket,
            args,
            "after_apply",
            "kintsugi_apply_scheduled_hotpatch",
            kintsugi_control_payload(KINTSUGI_APPLY_SCHEDULED),
            bytes([0x6E, 0xF1, 0x90]),
        )
        print("[phase] after_apply: ECU-local DID quarantine should block the attack")
        run_attack_chain(rows, can_socket, args, "after_apply", expect_blocked=True)
        run_benign_read(rows, can_socket, args, "after_apply")

    summary_rows = phase_summary(rows)
    detail_path = Path(args.csv)
    summary_path = Path(args.summary_csv)
    pdf_path = Path(args.pdf)
    write_csv(detail_path, rows)
    write_summary_csv(summary_path, summary_rows)
    render_pdf(rows, summary_rows, pdf_path)
    print(f"\nwrote {detail_path}")
    print(f"wrote {summary_path}")
    print(f"wrote {pdf_path}")

    return 0 if all(row.passed for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
