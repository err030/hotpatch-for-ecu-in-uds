#!/usr/bin/env python3
"""Run hardware UDS 0x2E fuzzing and cross-check with a Nucleo CAN observer."""

from __future__ import annotations

import argparse
import csv
import os
import random
import socket
import struct
import termios
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
DEFAULT_SERIAL = "/dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_0034002C3235511437333439-if02"
UDS_SEED_MASK = 0xA55A


@dataclass(frozen=True)
class Mutation:
    trial: int
    kind: str
    did: int
    data: bytes

    @property
    def payload(self) -> bytes:
        return bytes([0x2E, (self.did >> 8) & 0xFF, self.did & 0xFF]) + self.data


@dataclass
class FuzzRow:
    trial: int
    mutation_kind: str
    did: int
    data: bytes
    request_payload: bytes
    request_can_data: bytes
    response_payload: bytes | None
    response_class: str
    response_sid: str
    nrc: str
    attack_pass: bool
    send_wall_iso: str
    send_monotonic_ns: int
    recv_monotonic_ns: int | None
    latency_ms: float | None
    observer_request_seen: bool = False
    observer_response_seen: bool = False
    observer_request_timestamp_us: int | None = None
    observer_response_timestamp_us: int | None = None
    observer_latency_ms: float | None = None
    observer_consistent: bool = False
    consistency_note: str = ""


@dataclass(frozen=True)
class ObserverFrame:
    source_line: int
    timestamp_us: int
    can_id: int
    dlc: int
    data_hex: str
    uds_payload_hex: str


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
    payload_len = data[0] & 0x0F
    if (data[0] >> 4) != 0 or payload_len > 7 or len(data) < 1 + payload_len:
        return None
    return data[1 : 1 + payload_len]


def hex_bytes(data: bytes | None) -> str:
    if data is None:
        return "<none>"
    return data.hex().upper()


def wall_iso_from_ns(timestamp_ns: int) -> str:
    return datetime.fromtimestamp(timestamp_ns / 1_000_000_000).astimezone().isoformat(timespec="microseconds")


def classify_response(payload: bytes | None) -> tuple[str, str, str]:
    if payload is None:
        return "timeout", "", ""
    if not payload:
        return "malformed", "", ""
    sid = payload[0]
    if sid == 0x7F:
        nrc = f"0x{payload[2]:02X}" if len(payload) > 2 else ""
        return "negative", "0x7F", nrc
    if sid == 0x6E:
        return "positive", "0x6E", ""
    if sid >= 0x40:
        return "positive_other", f"0x{sid:02X}", ""
    return "other", f"0x{sid:02X}", ""


def parse_seed(payload: bytes | None) -> int | None:
    if payload is None or len(payload) != 4:
        return None
    if payload[0] != 0x67 or payload[1] != 0x01:
        return None
    return (payload[2] << 8) | payload[3]


def bind_can_socket(interface: str, response_id: int) -> socket.socket:
    can_socket = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    can_socket.bind((interface,))
    can_filter = struct.pack("=II", response_id, CAN_SFF_MASK)
    can_socket.setsockopt(socket.SOL_CAN_RAW, CAN_RAW_FILTER, can_filter)
    return can_socket


def drain_can(can_socket: socket.socket, max_seconds: float = 0.05) -> int:
    drained = 0
    previous_timeout = can_socket.gettimeout()
    deadline = time.perf_counter() + max_seconds
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


def send_uds(
    can_socket: socket.socket,
    request_id: int,
    response_id: int,
    payload: bytes,
    timeout_s: float,
) -> tuple[bytes | None, int, int | None, int]:
    frame_data = pack_single_frame_payload(payload)
    send_wall_ns = time.time_ns()
    send_monotonic_ns = time.perf_counter_ns()
    can_socket.send(pack_can_frame(request_id, frame_data))

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
    return response_payload, send_monotonic_ns, recv_monotonic_ns, send_wall_ns


def configure_serial(fd: int, baud: int) -> None:
    baud_map = {115200: termios.B115200, 57600: termios.B57600, 38400: termios.B38400}
    if baud not in baud_map:
        raise ValueError(f"unsupported baud rate: {baud}")

    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = baud_map[baud]
    attrs[5] = baud_map[baud]
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIOFLUSH)


def read_serial_available(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def parse_single_frame_payload(data_hex: str) -> str:
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        return ""
    payload = unpack_single_frame_payload(data)
    return "" if payload is None else payload.hex().upper()


def parse_observer_log(text: str) -> list[ObserverFrame]:
    frames: list[ObserverFrame] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line.startswith("MON,"):
            continue
        parts = line.split(",", 4)
        if len(parts) != 5:
            continue
        _, timestamp_text, can_id_text, dlc_text, data_hex = parts
        try:
            frames.append(
                ObserverFrame(
                    source_line=line_number,
                    timestamp_us=int(timestamp_text),
                    can_id=int(can_id_text, 16),
                    dlc=int(dlc_text),
                    data_hex=data_hex.upper(),
                    uds_payload_hex=parse_single_frame_payload(data_hex),
                )
            )
        except ValueError:
            continue
    return frames


def build_mutations(iterations: int, seed: int) -> list[Mutation]:
    rng = random.Random(seed)
    mutations: list[Mutation] = []
    for trial in range(1, iterations + 1):
        roll = rng.random()
        if roll < 0.78:
            kind = "target_did_random_data"
            did = 0x1234
            data_len = rng.choice([1, 2, 3, 4])
        elif roll < 0.88:
            kind = "unknown_did"
            did = rng.choice([0x2222, 0x3333, 0xF187])
            data_len = rng.choice([1, 2, 3, 4])
        elif roll < 0.94:
            kind = "read_only_did"
            did = 0x1001
            data_len = rng.choice([1, 2, 3])
        else:
            kind = "missing_data"
            did = 0x1234
            data_len = 0
        data = bytes(rng.randrange(0, 256) for _ in range(data_len))
        mutations.append(Mutation(trial=trial, kind=kind, did=did, data=data))
    return mutations


def unlock_security_access(can_socket: socket.socket, args: argparse.Namespace) -> list[tuple[str, bytes, bytes | None]]:
    setup: list[tuple[str, bytes, bytes | None]] = []
    for name, payload in [
        ("reset_default_session", bytes([0x10, 0x01])),
        ("enter_extended_session", bytes([0x10, 0x03])),
        ("request_security_seed", bytes([0x27, 0x01])),
    ]:
        response, _, _, _ = send_uds(can_socket, args.request_id, args.response_id, payload, args.timeout)
        setup.append((name, payload, response))
        time.sleep(args.setup_delay_ms / 1000.0)

    seed = parse_seed(setup[-1][2])
    key = 0 if seed is None else seed ^ UDS_SEED_MASK
    key_payload = bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF])
    response, _, _, _ = send_uds(can_socket, args.request_id, args.response_id, key_payload, args.timeout)
    setup.append(("send_key_from_weak_transform", key_payload, response))
    return setup


def run_campaign(can_socket: socket.socket, serial_fd: int, args: argparse.Namespace) -> tuple[list[FuzzRow], str]:
    mutations = build_mutations(args.iterations, args.seed)
    chunks: list[bytes] = []
    rows: list[FuzzRow] = []

    for mutation in mutations:
        request_payload = mutation.payload
        request_can_data = pack_single_frame_payload(request_payload)
        response_payload, send_ns, recv_ns, send_wall_ns = send_uds(
            can_socket,
            args.request_id,
            args.response_id,
            request_payload,
            args.timeout,
        )
        response_class, response_sid, nrc = classify_response(response_payload)
        chunks.append(read_serial_available(serial_fd))
        latency_ms = None if recv_ns is None else (recv_ns - send_ns) / 1_000_000.0
        rows.append(
            FuzzRow(
                trial=mutation.trial,
                mutation_kind=mutation.kind,
                did=mutation.did,
                data=mutation.data,
                request_payload=request_payload,
                request_can_data=request_can_data,
                response_payload=response_payload,
                response_class=response_class,
                response_sid=response_sid,
                nrc=nrc,
                attack_pass=(response_payload is not None and response_payload[:3] == bytes([0x6E, (mutation.did >> 8) & 0xFF, mutation.did & 0xFF])),
                send_wall_iso=wall_iso_from_ns(send_wall_ns),
                send_monotonic_ns=send_ns,
                recv_monotonic_ns=recv_ns,
                latency_ms=latency_ms,
            )
        )
        if args.inter_request_delay_ms > 0:
            time.sleep(args.inter_request_delay_ms / 1000.0)

        if mutation.trial % args.progress_every == 0:
            print(f"completed {mutation.trial}/{args.iterations}")

    end_deadline = time.perf_counter() + args.observer_drain_seconds
    while time.perf_counter() < end_deadline:
        chunks.append(read_serial_available(serial_fd))
        time.sleep(0.02)

    observer_text = b"".join(chunks).decode("ascii", errors="replace")
    return rows, observer_text


def pair_observer(rows: list[FuzzRow], frames: list[ObserverFrame], request_id: int, response_id: int) -> None:
    cursor = 0
    for row in rows:
        request_payload_hex = hex_bytes(row.request_payload)
        response_payload_hex = hex_bytes(row.response_payload)
        request_frame: ObserverFrame | None = None
        response_frame: ObserverFrame | None = None

        for index in range(cursor, len(frames)):
            frame = frames[index]
            if frame.can_id == request_id and frame.uds_payload_hex == request_payload_hex:
                request_frame = frame
                cursor = index + 1
                break

        if request_frame is not None and row.response_payload is not None:
            for index in range(cursor, len(frames)):
                frame = frames[index]
                if frame.can_id == response_id:
                    response_frame = frame
                    cursor = index + 1
                    break

        row.observer_request_seen = request_frame is not None
        row.observer_response_seen = response_frame is not None
        row.observer_request_timestamp_us = None if request_frame is None else request_frame.timestamp_us
        row.observer_response_timestamp_us = None if response_frame is None else response_frame.timestamp_us
        if request_frame is not None and response_frame is not None:
            row.observer_latency_ms = (response_frame.timestamp_us - request_frame.timestamp_us) / 1000.0

        if request_frame is None:
            row.observer_consistent = False
            row.consistency_note = "observer_missing_request"
        elif row.response_payload is None:
            row.observer_consistent = response_frame is None
            row.consistency_note = "both_timeout_or_no_response" if row.observer_consistent else "observer_extra_response"
        elif response_frame is None:
            row.observer_consistent = False
            row.consistency_note = "observer_missing_response"
        elif response_frame.uds_payload_hex != response_payload_hex:
            row.observer_consistent = False
            row.consistency_note = f"response_mismatch_observer={response_frame.uds_payload_hex}"
        else:
            row.observer_consistent = True
            row.consistency_note = "matched_request_response"


def write_detail_csv(path: Path, rows: list[FuzzRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "trial",
                "mutation_kind",
                "did_hex",
                "data_hex",
                "request_payload",
                "request_can_data_hex",
                "response_payload",
                "response_class",
                "response_sid",
                "nrc",
                "attack_pass",
                "send_wall_iso",
                "send_monotonic_ns",
                "recv_monotonic_ns",
                "latency_ms",
                "observer_request_seen",
                "observer_response_seen",
                "observer_request_timestamp_us",
                "observer_response_timestamp_us",
                "observer_latency_ms",
                "observer_consistent",
                "consistency_note",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "trial": row.trial,
                    "mutation_kind": row.mutation_kind,
                    "did_hex": f"0x{row.did:04X}",
                    "data_hex": hex_bytes(row.data),
                    "request_payload": hex_bytes(row.request_payload),
                    "request_can_data_hex": hex_bytes(row.request_can_data),
                    "response_payload": hex_bytes(row.response_payload),
                    "response_class": row.response_class,
                    "response_sid": row.response_sid,
                    "nrc": row.nrc,
                    "attack_pass": "true" if row.attack_pass else "false",
                    "send_wall_iso": row.send_wall_iso,
                    "send_monotonic_ns": row.send_monotonic_ns,
                    "recv_monotonic_ns": "" if row.recv_monotonic_ns is None else row.recv_monotonic_ns,
                    "latency_ms": "" if row.latency_ms is None else f"{row.latency_ms:.6f}",
                    "observer_request_seen": "true" if row.observer_request_seen else "false",
                    "observer_response_seen": "true" if row.observer_response_seen else "false",
                    "observer_request_timestamp_us": "" if row.observer_request_timestamp_us is None else row.observer_request_timestamp_us,
                    "observer_response_timestamp_us": "" if row.observer_response_timestamp_us is None else row.observer_response_timestamp_us,
                    "observer_latency_ms": "" if row.observer_latency_ms is None else f"{row.observer_latency_ms:.6f}",
                    "observer_consistent": "true" if row.observer_consistent else "false",
                    "consistency_note": row.consistency_note,
                }
            )


def write_setup_csv(path: Path, setup_rows: list[tuple[str, bytes, bytes | None]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["step", "request_payload", "response_payload", "response_class", "response_sid", "nrc"])
        for step, request, response in setup_rows:
            response_class, response_sid, nrc = classify_response(response)
            writer.writerow([step, hex_bytes(request), hex_bytes(response), response_class, response_sid, nrc])


def write_summary_csv(path: Path, rows: list[FuzzRow], setup_rows: list[tuple[str, bytes, bytes | None]]) -> None:
    total = len(rows)
    pass_count = sum(1 for row in rows if row.attack_pass)
    response_count = sum(1 for row in rows if row.response_payload is not None)
    consistent_count = sum(1 for row in rows if row.observer_consistent)
    request_seen_count = sum(1 for row in rows if row.observer_request_seen)
    response_seen_count = sum(1 for row in rows if row.observer_response_seen)
    latencies = [row.latency_ms for row in rows if row.latency_ms is not None]
    observer_latencies = [row.observer_latency_ms for row in rows if row.observer_latency_ms is not None]
    setup_ok = all(classify_response(response)[0].startswith("positive") for _, _, response in setup_rows)

    def avg(values: list[float]) -> str:
        return "" if not values else f"{sum(values) / len(values):.6f}"

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_trials", total])
        writer.writerow(["setup_positive", "true" if setup_ok else "false"])
        writer.writerow(["attack_pass_count", pass_count])
        writer.writerow(["attack_pass_rate", f"{pass_count / total:.6f}" if total else ""])
        writer.writerow(["attack_fail_count", total - pass_count])
        writer.writerow(["response_count", response_count])
        writer.writerow(["timeout_count", total - response_count])
        writer.writerow(["observer_request_seen_count", request_seen_count])
        writer.writerow(["observer_response_seen_count", response_seen_count])
        writer.writerow(["observer_consistent_count", consistent_count])
        writer.writerow(["observer_consistency_rate", f"{consistent_count / total:.6f}" if total else ""])
        writer.writerow(["can0_latency_avg_ms", avg(latencies)])
        writer.writerow(["observer_latency_avg_ms", avg(observer_latencies)])


def generate_pdf(detail_csv: Path, summary_csv: Path, pdf_path: Path, title: str) -> None:
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/hotpatch_uds_mplconfig")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = list(csv.DictReader(detail_csv.open(newline="", encoding="utf-8")))
    summary = {row["metric"]: row["value"] for row in csv.DictReader(summary_csv.open(newline="", encoding="utf-8"))}
    trials = [int(row["trial"]) for row in rows]
    latencies = [float(row["latency_ms"]) if row["latency_ms"] else None for row in rows]
    observer_latencies = [float(row["observer_latency_ms"]) if row["observer_latency_ms"] else None for row in rows]
    attack_pass = [row["attack_pass"] == "true" for row in rows]
    consistent = [row["observer_consistent"] == "true" for row in rows]

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
            "axes.axisbelow": True,
            "grid.color": "#D9D9D9",
            "grid.linewidth": 0.7,
        }
    )

    fig, axes = plt.subplots(2, 2, figsize=(9.0, 6.4))
    fig.suptitle(title, fontweight="bold", y=0.98)

    total = int(summary.get("total_trials", "0"))
    pass_count = int(summary.get("attack_pass_count", "0"))
    fail_count = int(summary.get("attack_fail_count", "0"))
    consistent_count = int(summary.get("observer_consistent_count", "0"))
    inconsistent_count = total - consistent_count

    ax = axes[0][0]
    ax.set_axisbelow(True)
    ax.bar(
        ["pass", "fail"],
        [pass_count, fail_count],
        color=["#2E7D32", "#A2142F"],
        edgecolor="#303030",
        zorder=3,
    )
    ax.set_ylabel("Trials")
    ax.set_title("0x2E fuzzing outcome", loc="left")
    for index, value in enumerate([pass_count, fail_count]):
        ax.text(index, value + max(total * 0.015, 1), f"{value}", ha="center", va="bottom", zorder=4)

    ax = axes[0][1]
    ax.set_axisbelow(True)
    ax.bar(
        ["matched", "mismatch"],
        [consistent_count, inconsistent_count],
        color=["#0072BD", "#D95319"],
        edgecolor="#303030",
        zorder=3,
    )
    ax.set_ylabel("Trials")
    ax.set_title("can0 vs Nucleo observer consistency", loc="left")
    for index, value in enumerate([consistent_count, inconsistent_count]):
        ax.text(index, value + max(total * 0.015, 1), f"{value}", ha="center", va="bottom", zorder=4)

    ax = axes[1][0]
    ax.set_axisbelow(True)
    pass_x = [trial for trial, ok, latency in zip(trials, attack_pass, latencies) if ok and latency is not None]
    pass_y = [latency for ok, latency in zip(attack_pass, latencies) if ok and latency is not None]
    fail_x = [trial for trial, ok, latency in zip(trials, attack_pass, latencies) if not ok and latency is not None]
    fail_y = [latency for ok, latency in zip(attack_pass, latencies) if not ok and latency is not None]
    ax.scatter(fail_x, fail_y, s=9, color="#A2142F", alpha=0.55, label="fail", zorder=3)
    ax.scatter(pass_x, pass_y, s=9, color="#2E7D32", alpha=0.55, label="pass", zorder=3)
    ax.set_xlabel("Trial")
    ax.set_ylabel("can0 latency (ms)")
    ax.set_title("Per-trial response delay", loc="left")
    ax.legend(frameon=False, loc="upper right")

    ax = axes[1][1]
    ax.set_axisbelow(True)
    diffs = [
        observer - latency
        for observer, latency in zip(observer_latencies, latencies)
        if observer is not None and latency is not None
    ]
    if diffs:
        ax.hist(diffs, bins=30, color="#7E2F8E", edgecolor="#303030", linewidth=0.4, zorder=3)
        ax.set_xlabel("Nucleo latency - can0 latency (ms)")
    else:
        ax.text(0.5, 0.5, "No paired latency samples", ha="center", va="center")
    ax.set_ylabel("Trials")
    ax.set_title("Observer timing delta", loc="left")

    subtitle = (
        f"trials={total}, pass_rate={float(summary.get('attack_pass_rate', '0')) * 100:.2f}%, "
        f"observer_match={float(summary.get('observer_consistency_rate', '0')) * 100:.2f}%, "
        f"can0_avg={summary.get('can0_latency_avg_ms', '')} ms"
    )
    fig.text(0.01, 0.015, subtitle, fontsize=8, color="#606060")
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def timestamp_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--serial", default=DEFAULT_SERIAL)
    parser.add_argument("--baud", default=115200, type=int)
    parser.add_argument("--iterations", default=1000, type=int)
    parser.add_argument("--seed", default=20260620, type=int)
    parser.add_argument("--timeout", default=0.25, type=float)
    parser.add_argument("--setup-delay-ms", default=20.0, type=float)
    parser.add_argument("--inter-request-delay-ms", default=12.0, type=float)
    parser.add_argument("--observer-drain-seconds", default=2.0, type=float)
    parser.add_argument("--progress-every", default=100, type=int)
    parser.add_argument("--tag", default="", help="Output tag. Defaults to current timestamp.")
    parser.add_argument("--charts-dir", default="software level/charts")
    parser.add_argument("--pdf-dir", default="software level/thesis_figures/pdf")
    parser.add_argument("--title", default="Hardware UDS 0x2E Fuzzing with Independent Observer")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    if args.progress_every < 1:
        args.progress_every = args.iterations + 1

    tag = args.tag or timestamp_tag()
    charts_dir = Path(args.charts_dir)
    pdf_dir = Path(args.pdf_dir)
    detail_csv = charts_dir / f"hardware_uds_2e_fuzz_observer_{tag}_detail.csv"
    summary_csv = charts_dir / f"hardware_uds_2e_fuzz_observer_{tag}_summary.csv"
    setup_csv = charts_dir / f"hardware_uds_2e_fuzz_observer_{tag}_setup.csv"
    observer_log = charts_dir / f"hardware_uds_2e_fuzz_observer_{tag}_nucleo.log"
    observer_csv = charts_dir / f"hardware_uds_2e_fuzz_observer_{tag}_nucleo.csv"
    pdf_path = pdf_dir / f"hardware_uds_2e_fuzz_observer_{tag}.pdf"

    serial_fd = os.open(args.serial, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure_serial(serial_fd, args.baud)
        with bind_can_socket(args.interface, args.response_id) as can_socket:
            drained = drain_can(can_socket)
            if drained:
                print(f"drained {drained} stale CAN response frame(s)")
            setup_rows = unlock_security_access(can_socket, args)
            time.sleep(0.2)
            termios.tcflush(serial_fd, termios.TCIOFLUSH)
            rows, observer_text = run_campaign(can_socket, serial_fd, args)
    finally:
        os.close(serial_fd)

    observer_log.parent.mkdir(parents=True, exist_ok=True)
    observer_log.write_text(observer_text, encoding="utf-8")
    frames = parse_observer_log(observer_text)
    pair_observer(rows, frames, args.request_id, args.response_id)

    write_setup_csv(setup_csv, setup_rows)
    write_detail_csv(detail_csv, rows)
    write_summary_csv(summary_csv, rows, setup_rows)
    write_observer_csv(observer_csv, frames)
    generate_pdf(detail_csv, summary_csv, pdf_path, args.title)

    pass_count = sum(1 for row in rows if row.attack_pass)
    consistent_count = sum(1 for row in rows if row.observer_consistent)
    print(f"trials={len(rows)} attack_pass={pass_count} attack_fail={len(rows) - pass_count}")
    print(f"observer_consistent={consistent_count}/{len(rows)}")
    print(f"wrote {setup_csv}")
    print(f"wrote {detail_csv}")
    print(f"wrote {summary_csv}")
    print(f"wrote {observer_log}")
    print(f"wrote {observer_csv}")
    print(f"wrote {pdf_path}")
    return 0 if consistent_count == len(rows) else 1


def write_observer_csv(path: Path, frames: list[ObserverFrame]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["source_line", "timestamp_us", "can_id_hex", "dlc", "data_hex", "uds_payload_hex"],
        )
        writer.writeheader()
        for frame in frames:
            writer.writerow(
                {
                    "source_line": frame.source_line,
                    "timestamp_us": frame.timestamp_us,
                    "can_id_hex": f"0x{frame.can_id:03X}",
                    "dlc": frame.dlc,
                    "data_hex": frame.data_hex,
                    "uds_payload_hex": frame.uds_payload_hex,
                }
            )


if __name__ == "__main__":
    raise SystemExit(main())
