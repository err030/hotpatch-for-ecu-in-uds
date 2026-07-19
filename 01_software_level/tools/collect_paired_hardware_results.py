#!/usr/bin/env python3
"""Collect paired real-CAN latency, benign-control, and activation evidence.

The Kintsugi runtime patch is volatile.  Each before/after state therefore starts
from an nRF52840 system reset; the after state then applies the patch over CAN.
All timestamps are host CLOCK_MONOTONIC measurements around real can0 traffic.
"""

from __future__ import annotations

import argparse
import csv
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


CAN_SFF_MASK = 0x7FF
CAN_RAW_FILTER = 1
SEED_MASK = 0xA55A
REQUEST_ID = 0x7E0
RESPONSE_ID = 0x7E8
TARGET_DID = 0x1234
CONTROL_DID = 0x1235


@dataclass(frozen=True)
class Tx:
    request: bytes
    response: bytes | None
    send_ns: int
    recv_ns: int | None

    @property
    def latency_ms(self) -> float | None:
        return None if self.recv_ns is None else (self.recv_ns - self.send_ns) / 1_000_000


class Logger:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("a", encoding="utf-8", buffering=1)

    def log(self, message: str) -> None:
        line = f"{datetime.now().astimezone().isoformat(timespec='milliseconds')} {message}"
        print(line, flush=True)
        self.handle.write(line + "\n")

    def close(self) -> None:
        self.handle.close()


def pack_can_frame(arbitration_id: int, data: bytes) -> bytes:
    return struct.pack("=IB3x8s", arbitration_id, len(data), data.ljust(8, b"\x00"))


def unpack_can_frame(raw: bytes) -> tuple[int, bytes]:
    can_id, dlc, data = struct.unpack("=IB3x8s", raw)
    return can_id & CAN_SFF_MASK, data[:dlc]


def pack_uds(payload: bytes) -> bytes:
    if len(payload) > 7:
        raise ValueError("classic-CAN UDS single-frame payload must be <= 7 bytes")
    return bytes([len(payload)]) + payload + bytes(7 - len(payload))


def unpack_uds(data: bytes) -> bytes | None:
    if not data or data[0] >> 4:
        return None
    length = data[0] & 0x0F
    return data[1 : 1 + length] if length <= 7 and len(data) >= length + 1 else None


def hex_bytes(value: bytes | None) -> str:
    return "" if value is None else value.hex().upper()


def classify(value: bytes | None) -> tuple[str, str, bool]:
    if value is None:
        return "timeout", "", True
    if len(value) >= 3 and value[0] == 0x7F:
        return "negative", f"0x{value[2]:02X}", False
    if value and value[0] >= 0x40:
        return "positive", "", False
    return "malformed", "", False


def response_matches(request: bytes, response: bytes | None) -> bool:
    if not request or response is None or not response:
        return False
    if response[0] == 0x7F:
        return len(response) >= 2 and response[1] == request[0]
    if response[0] != ((request[0] + 0x40) & 0xFF):
        return False
    if request[0] in (0x10, 0x27, 0x3E):
        return len(request) >= 2 and len(response) >= 2 and (response[1] & 0x7F) == (request[1] & 0x7F)
    if request[0] in (0x22, 0x2E):
        return len(request) >= 3 and len(response) >= 3 and response[1:3] == request[1:3]
    return True


class CanClient:
    def __init__(self, interface: str, timeout: float, inter_request_delay_s: float = 0.025) -> None:
        self.timeout = timeout
        self.inter_request_delay_s = inter_request_delay_s
        self.sock = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.sock.bind((interface,))
        self.sock.setsockopt(
            socket.SOL_CAN_RAW,
            CAN_RAW_FILTER,
            struct.pack("=II", RESPONSE_ID, CAN_SFF_MASK),
        )
        self.drain()

    def close(self) -> None:
        self.sock.close()

    def drain(self) -> None:
        self.sock.settimeout(0.001)
        while True:
            try:
                self.sock.recv(16)
            except socket.timeout:
                break

    def send(self, payload: bytes) -> Tx:
        self.drain()
        send_ns = time.perf_counter_ns()
        self.sock.send(pack_can_frame(REQUEST_ID, pack_uds(payload)))
        deadline = time.perf_counter() + self.timeout
        while time.perf_counter() < deadline:
            self.sock.settimeout(max(0.001, deadline - time.perf_counter()))
            try:
                raw = self.sock.recv(16)
            except socket.timeout:
                break
            can_id, data = unpack_can_frame(raw)
            if can_id == RESPONSE_ID:
                response = unpack_uds(data)
                if response_matches(payload, response):
                    result = Tx(payload, response, send_ns, time.perf_counter_ns())
                    if self.inter_request_delay_s > 0:
                        time.sleep(self.inter_request_delay_s)
                    return result
        return Tx(payload, None, send_ns, None)


def reset_board(logger: Logger) -> tuple[int, int]:
    start_ns = time.perf_counter_ns()
    result = subprocess.run(
        ["nrfjprog", "--reset"],
        check=False,
        capture_output=True,
        text=True,
    )
    end_ns = time.perf_counter_ns()
    if result.returncode != 0:
        raise RuntimeError(f"nrfjprog --reset failed: {result.stderr.strip()}")
    logger.log(f"board_reset duration_ms={(end_ns - start_ns) / 1_000_000:.3f}")
    # The FreeRTOS/MCP2515 path needs time to reinitialize after the debugger
    # releases reset; requests sent during this window are silently lost.
    time.sleep(1.0)
    return start_ns, end_ns


def parse_seed(response: bytes | None) -> int:
    if response is None or len(response) != 4 or response[:2] != b"\x67\x01":
        raise RuntimeError(f"invalid seed response: {hex_bytes(response)}")
    return int.from_bytes(response[2:4], "big")


def unlock(client: CanClient) -> list[tuple[str, Tx]]:
    rows = [
        ("enter_extended_session", client.send(b"\x10\x03")),
        ("request_security_seed", client.send(b"\x27\x01")),
    ]
    try:
        seed = parse_seed(rows[-1][1].response)
    except RuntimeError as exc:
        observed = ", ".join(f"{name}={hex_bytes(tx.response) or '<timeout>'}" for name, tx in rows)
        raise RuntimeError(f"{exc}; unlock observations: {observed}") from exc
    key = (seed ^ SEED_MASK).to_bytes(2, "big")
    rows.append(("send_security_key", client.send(b"\x27\x02" + key)))
    return rows


def apply_patch(client: CanClient) -> list[tuple[str, Tx]]:
    return [
        ("patch_receive_validate", client.send(b"\x2E\xF1\x90\x02")),
        ("patch_schedule", client.send(b"\x2E\xF1\x90\x03")),
        ("patch_apply", client.send(b"\x2E\xF1\x90\x04")),
    ]


def read_value(response: bytes | None, did: int) -> str:
    prefix = bytes([0x62, did >> 8, did & 0xFF])
    return hex_bytes(response[len(prefix) :]) if response is not None and response.startswith(prefix) else ""


def write_rows(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def tx_fields(tx: Tx) -> dict[str, object]:
    response_class, nrc, timeout = classify(tx.response)
    return {
        "request_payload": hex_bytes(tx.request),
        "response_payload": hex_bytes(tx.response),
        "send_monotonic_ns": tx.send_ns,
        "recv_monotonic_ns": "" if tx.recv_ns is None else tx.recv_ns,
        "latency_ms": "" if tx.latency_ms is None else f"{tx.latency_ms:.6f}",
        "response_class": response_class,
        "nrc": nrc,
        "timeout": str(timeout).lower(),
    }


def collect_latency(args: argparse.Namespace, out: Path, logger: Logger) -> None:
    detail: list[dict[str, object]] = []
    state_rows: list[dict[str, object]] = []
    run_id = f"real_can_latency_{args.run_id}"
    for patch_state in ("before", "after"):
        reset_board(logger)
        client = CanClient(args.interface, args.timeout)
        try:
            if patch_state == "after":
                controls = apply_patch(client)
                if any(tx.response != bytes.fromhex("6EF190") for _, tx in controls):
                    raise RuntimeError("after-state patch activation failed")
            for trial in range(1, args.latency_trials + 1):
                warmup = trial <= args.warmup
                sequence: list[tuple[str, Tx]] = [("session_reset", client.send(b"\x10\x01"))]
                sequence.extend(unlock(client))
                before = client.send(b"\x22\x12\x34")
                sequence.append(("read_target_before", before))
                attempted = trial.to_bytes(2, "big")
                write = client.send(b"\x2E\x12\x34" + attempted)
                sequence.append(("write_target", write))
                after = client.send(b"\x22\x12\x34")
                sequence.append(("read_target_after", after))
                for step, tx in sequence:
                    detail.append(
                        {
                            "run_id": run_id,
                            "trial": trial,
                            "patch_state": patch_state,
                            "warmup": str(warmup).lower(),
                            "step": step,
                            **tx_fields(tx),
                        }
                    )
                value_before = read_value(before.response, TARGET_DID)
                value_after = read_value(after.response, TARGET_DID)
                attack_success = write.response == b"\x6E\x12\x34"
                state_rows.append(
                    {
                        "run_id": run_id,
                        "trial": trial,
                        "patch_state": patch_state,
                        "warmup": str(warmup).lower(),
                        "value_before": value_before,
                        "attempted_value": hex_bytes(attempted),
                        "value_after": value_after,
                        "state_reset_confirmed": str(trial == 1 and value_before == "").lower(),
                        "attack_success": str(attack_success).lower(),
                        "state_changed": str(value_before != value_after).lower(),
                        "write_response": hex_bytes(write.response),
                    }
                )
                if trial % 100 == 0:
                    logger.log(f"latency patch_state={patch_state} trial={trial}/{args.latency_trials}")
        finally:
            client.close()
    write_rows(
        out / "real_can_latency_detail.csv",
        ["run_id", "trial", "patch_state", "warmup", "step", "request_payload", "response_payload", "send_monotonic_ns", "recv_monotonic_ns", "latency_ms", "response_class", "nrc", "timeout"],
        detail,
    )
    write_rows(
        out / "real_can_state_integrity.csv",
        ["run_id", "trial", "patch_state", "warmup", "value_before", "attempted_value", "value_after", "state_reset_confirmed", "attack_success", "state_changed", "write_response"],
        state_rows,
    )


def expected_positive(tx: Tx, prefix: bytes) -> bool:
    return tx.response is not None and tx.response.startswith(prefix)


def collect_benign(args: argparse.Namespace, out: Path, logger: Logger) -> None:
    detail: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    run_id = f"hardware_benign_{args.run_id}"
    for patch_state in ("before", "after"):
        reset_board(logger)
        client = CanClient(args.interface, args.timeout)
        passed_trials = 0
        try:
            if patch_state == "after":
                apply_patch(client)
            for trial in range(1, args.benign_trials + 1):
                value = trial.to_bytes(2, "big")
                operations: list[tuple[str, Tx, bytes]] = []
                operations.append(("session_reset_start", client.send(b"\x10\x01"), b"\x50\x01"))
                operations.append(("diagnostic_session_control", client.send(b"\x10\x03"), b"\x50\x03"))
                operations.append(("read_status_did", client.send(b"\x22\x10\x01"), b"\x62\x10\x01"))
                unlock_rows = unlock(client)
                operations.extend((step, tx, b"\x50\x03" if step == "enter_extended_session" else (b"\x67\x01" if step == "request_security_seed" else b"\x67\x02")) for step, tx in unlock_rows)
                operations.append(("write_nonisolated_did", client.send(b"\x2E\x12\x35" + value), b"\x6E\x12\x35"))
                operations.append(("read_nonisolated_did", client.send(b"\x22\x12\x35"), b"\x62\x12\x35" + value))
                operations.append(("tester_present", client.send(b"\x3E\x00"), b"\x7E\x00"))
                operations.append(("session_reset_end", client.send(b"\x10\x01"), b"\x50\x01"))
                trial_pass = True
                for operation, tx, expected in operations:
                    passed = expected_positive(tx, expected)
                    trial_pass &= passed
                    detail.append(
                        {
                            "run_id": run_id,
                            "trial": trial,
                            "patch_state": patch_state,
                            "operation": operation,
                            "passed": str(passed).lower(),
                            "expected_response_prefix": hex_bytes(expected),
                            **tx_fields(tx),
                        }
                    )
                passed_trials += int(trial_pass)
                if trial % 100 == 0:
                    logger.log(f"benign patch_state={patch_state} trial={trial}/{args.benign_trials}")
        finally:
            client.close()
        summaries.append(
            {
                "run_id": run_id,
                "patch_state": patch_state,
                "total_trials": args.benign_trials,
                "passed_trials": passed_trials,
                "pass_rate": f"{passed_trials / args.benign_trials:.6f}",
            }
        )
    write_rows(
        out / "hardware_benign_control_detail.csv",
        ["run_id", "trial", "patch_state", "operation", "passed", "expected_response_prefix", "request_payload", "response_payload", "send_monotonic_ns", "recv_monotonic_ns", "latency_ms", "response_class", "nrc", "timeout"],
        detail,
    )
    write_rows(out / "hardware_benign_control_summary.csv", ["run_id", "patch_state", "total_trials", "passed_trials", "pass_rate"], summaries)


def collect_activation(args: argparse.Namespace, out: Path, logger: Logger) -> None:
    rows: list[dict[str, object]] = []
    run_id = f"patch_activation_{args.run_id}"
    reset_board(logger)
    for trial in range(1, args.activation_trials + 1):
        client = CanClient(args.interface, args.timeout, inter_request_delay_s=0.0)
        try:
            warmup = client.send(b"\x10\x01")
            if not expected_positive(warmup, b"\x50\x01"):
                raise RuntimeError("activation warm-up request failed")
            receive = client.send(b"\x2E\xF1\x90\x02")
            schedule = client.send(b"\x2E\xF1\x90\x03")
            apply = client.send(b"\x2E\xF1\x90\x04")
            unlock(client)
            protected = client.send(b"\x2E\x12\x34" + trial.to_bytes(2, "big"))
        finally:
            client.close()
        rollback_start_ns, rollback_complete_ns = reset_board(logger)
        rows.append(
            {
                "run_id": run_id,
                "trial": trial,
                "patch_trigger_ns": receive.send_ns,
                "validation_complete_ns": receive.recv_ns or "",
                "scheduled_ns": schedule.recv_ns or "",
                "patch_active_ns": apply.recv_ns or "",
                "first_protected_request_ns": protected.send_ns,
                "first_protected_response_ns": protected.recv_ns or "",
                "rollback_start_ns": rollback_start_ns,
                "rollback_complete_ns": rollback_complete_ns,
                "activation_latency_ms": "" if apply.recv_ns is None else f"{(apply.recv_ns - receive.send_ns) / 1_000_000:.6f}",
                "validation_rtt_ms": "" if receive.latency_ms is None else f"{receive.latency_ms:.6f}",
                "scheduling_rtt_ms": "" if schedule.latency_ms is None else f"{schedule.latency_ms:.6f}",
                "application_rtt_ms": "" if apply.latency_ms is None else f"{apply.latency_ms:.6f}",
                "rollback_latency_ms": f"{(rollback_complete_ns - rollback_start_ns) / 1_000_000:.6f}",
                "protected_response": hex_bytes(protected.response),
                "protected": str(protected.response == b"\x7F\x2E\x31").lower(),
                "measurement_scope": "host_end_to_end_monotonic",
                "pre_activation_warmup_response": hex_bytes(warmup.response),
                "task_period_us": "",
                "task_jitter_us": "",
                "cpu_load_pct": "",
                "bus_load_pct": "",
                "runtime_telemetry_status": "not_instrumented_in_current_firmware",
            }
        )
        if trial % 10 == 0:
            logger.log(f"activation trial={trial}/{args.activation_trials}")
    write_rows(
        out / "patch_activation_detail.csv",
        ["run_id", "trial", "patch_trigger_ns", "validation_complete_ns", "scheduled_ns", "patch_active_ns", "first_protected_request_ns", "first_protected_response_ns", "rollback_start_ns", "rollback_complete_ns", "activation_latency_ms", "validation_rtt_ms", "scheduling_rtt_ms", "application_rtt_ms", "rollback_latency_ms", "protected_response", "protected", "measurement_scope", "pre_activation_warmup_response", "task_period_us", "task_jitter_us", "cpu_load_pct", "bus_load_pct", "runtime_telemetry_status"],
        rows,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--timeout", type=float, default=0.3)
    parser.add_argument("--output-dir", default="01_software_level/results/paired_hardware")
    parser.add_argument("--run-id", default="20260710", help="Suffix stored in each CSV run_id field.")
    parser.add_argument("--campaign", choices=("all", "latency", "benign", "activation"), default="all")
    parser.add_argument("--latency-trials", type=int, default=520, help="Includes warm-up trials.")
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--benign-trials", type=int, default=500)
    parser.add_argument("--activation-trials", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    logger = Logger(out / "collection.log")
    try:
        logger.log(f"start campaign={args.campaign} interface={args.interface}")
        if args.campaign in ("all", "latency"):
            collect_latency(args, out, logger)
        if args.campaign in ("all", "benign"):
            collect_benign(args, out, logger)
        if args.campaign in ("all", "activation"):
            collect_activation(args, out, logger)
        logger.log("collection complete")
    finally:
        logger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
