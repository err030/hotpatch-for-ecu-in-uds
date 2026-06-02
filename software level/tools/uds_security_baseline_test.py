#!/usr/bin/env python3
"""Run baseline UDS security checks against the nRF ECU over SocketCAN.

The script assumes can0 is already created by slcand and set UP. It sends
single-frame ISO-TP UDS requests on 0x7E0 and waits for responses on 0x7E8.
"""

from __future__ import annotations

import argparse
import csv
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000
CAN_SFF_MASK = 0x000007FF

DEFAULT_REQUEST_ID = 0x7E0
DEFAULT_RESPONSE_ID = 0x7E8
UDS_SEED_MASK = 0xA55A


@dataclass(frozen=True)
class CanFrame:
    arbitration_id: int
    data: bytes


@dataclass(frozen=True)
class UdsResult:
    name: str
    request_payload: bytes
    response_payload: bytes | None
    expected: str
    passed: bool
    note: str


Expectation = Callable[[bytes | None], tuple[bool, str]]


def pack_can_frame(arbitration_id: int, data: bytes) -> bytes:
    if len(data) > 8:
        raise ValueError("classic CAN data must be <= 8 bytes")
    padded = data + bytes(8 - len(data))
    return struct.pack("=IB3x8s", arbitration_id, len(data), padded)


def unpack_can_frame(raw: bytes) -> CanFrame:
    can_id, dlc, data = struct.unpack("=IB3x8s", raw)
    arbitration_id = can_id & CAN_SFF_MASK
    if can_id & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG):
        arbitration_id = can_id
    return CanFrame(arbitration_id=arbitration_id, data=data[:dlc])


def pack_single_frame_payload(payload: bytes) -> bytes:
    if len(payload) > 7:
        raise ValueError("single-frame UDS payload must be <= 7 bytes")
    frame_data = bytes([len(payload)]) + payload
    return frame_data + bytes(8 - len(frame_data))


def unpack_single_frame_payload(data: bytes) -> bytes | None:
    if not data:
        return None
    pci_type = data[0] >> 4
    payload_length = data[0] & 0x0F
    if pci_type != 0 or payload_length > 7 or len(data) < 1 + payload_length:
        return None
    return data[1 : 1 + payload_length]


def hex_bytes(data: bytes | None) -> str:
    if data is None:
        return "<none>"
    return data.hex().upper()


def expect_payload(expected: bytes) -> Expectation:
    def check(payload: bytes | None) -> tuple[bool, str]:
        if payload == expected:
            return True, f"matched {hex_bytes(expected)}"
        return False, f"expected {hex_bytes(expected)}, got {hex_bytes(payload)}"

    return check


def expect_seed(payload: bytes | None) -> tuple[bool, str]:
    if payload is None:
        return False, "no response"
    if len(payload) != 4 or payload[0] != 0x67 or payload[1] != 0x01:
        return False, f"expected 6701xxxx, got {hex_bytes(payload)}"
    seed = (payload[2] << 8) | payload[3]
    return True, f"seed=0x{seed:04X}"


def parse_seed(payload: bytes | None) -> int:
    if payload is None or len(payload) != 4 or payload[0] != 0x67 or payload[1] != 0x01:
        raise RuntimeError(f"cannot parse seed from {hex_bytes(payload)}")
    return (payload[2] << 8) | payload[3]


def send_and_receive(
    can_socket: socket.socket,
    interface: str,
    request_id: int,
    response_id: int,
    payload: bytes,
    timeout_s: float,
) -> bytes | None:
    can_socket.send(pack_can_frame(request_id, pack_single_frame_payload(payload)))
    deadline = time.monotonic() + timeout_s

    while time.monotonic() < deadline:
        can_socket.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            raw = can_socket.recv(16)
        except TimeoutError:
            return None
        except socket.timeout:
            return None

        frame = unpack_can_frame(raw)
        if frame.arbitration_id != response_id:
            continue
        return unpack_single_frame_payload(frame.data)

    return None


def run_case(
    can_socket: socket.socket,
    args: argparse.Namespace,
    name: str,
    request_payload: bytes,
    expected_label: str,
    expectation: Expectation,
) -> UdsResult:
    response_payload = send_and_receive(
        can_socket=can_socket,
        interface=args.interface,
        request_id=args.request_id,
        response_id=args.response_id,
        payload=request_payload,
        timeout_s=args.timeout,
    )
    passed, note = expectation(response_payload)
    return UdsResult(
        name=name,
        request_payload=request_payload,
        response_payload=response_payload,
        expected=expected_label,
        passed=passed,
        note=note,
    )


def print_result(result: UdsResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(
        f"{status:4} {result.name:34} "
        f"req={hex_bytes(result.request_payload):14} "
        f"resp={hex_bytes(result.response_payload):14} "
        f"{result.note}"
    )


def write_csv(path: Path, results: list[UdsResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case", "request_payload", "response_payload", "expected", "passed", "note"])
        for result in results:
            writer.writerow(
                [
                    result.name,
                    hex_bytes(result.request_payload),
                    hex_bytes(result.response_payload),
                    result.expected,
                    "true" if result.passed else "false",
                    result.note,
                ]
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run baseline UDS security tests over SocketCAN."
    )
    parser.add_argument("--interface", default="can0", help="SocketCAN interface name")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--timeout", default=1.0, type=float, help="response timeout in seconds")
    parser.add_argument(
        "--csv",
        default="software level/charts/hardware_baseline_security_latest.csv",
        help="CSV output path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    results: list[UdsResult] = []

    with socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as can_socket:
        try:
            can_socket.bind((args.interface,))
        except OSError as exc:
            print(f"cannot bind {args.interface}: {exc}", file=sys.stderr)
            return 2

        # Reset to default session so the first malicious write is deterministic.
        results.append(
            run_case(
                can_socket,
                args,
                "reset_default_session",
                bytes([0x10, 0x01]),
                "5001",
                expect_payload(bytes([0x50, 0x01])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "default_session_write_blocked",
                bytes([0x2E, 0x12, 0x34, 0xAA, 0xBB]),
                "7F2E22",
                expect_payload(bytes([0x7F, 0x2E, 0x22])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "enter_extended_session",
                bytes([0x10, 0x03]),
                "5003",
                expect_payload(bytes([0x50, 0x03])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "extended_write_without_unlock_blocked",
                bytes([0x2E, 0x12, 0x34, 0xAA, 0xBB]),
                "7F2E33",
                expect_payload(bytes([0x7F, 0x2E, 0x33])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "request_seed_for_wrong_key",
                bytes([0x27, 0x01]),
                "6701xxxx",
                expect_seed,
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "wrong_key_blocked",
                bytes([0x27, 0x02, 0x00, 0x00]),
                "7F2733",
                expect_payload(bytes([0x7F, 0x27, 0x33])),
            )
        )
        seed_result = run_case(
            can_socket,
            args,
            "request_seed_for_valid_key",
            bytes([0x27, 0x01]),
            "6701xxxx",
            expect_seed,
        )
        results.append(seed_result)

        try:
            seed = parse_seed(seed_result.response_payload)
            key = seed ^ UDS_SEED_MASK
            key_payload = bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF])
        except RuntimeError:
            key_payload = bytes([0x27, 0x02, 0x00, 0x00])

        results.append(
            run_case(
                can_socket,
                args,
                "valid_key_unlocks_security",
                key_payload,
                "6702",
                expect_payload(bytes([0x67, 0x02])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "authorized_did_write_allowed",
                bytes([0x2E, 0x12, 0x34, 0xAA, 0xBB]),
                "6E1234",
                expect_payload(bytes([0x6E, 0x12, 0x34])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "session_reset_clears_unlock",
                bytes([0x10, 0x01]),
                "5001",
                expect_payload(bytes([0x50, 0x01])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "replay_write_after_reset_blocked",
                bytes([0x2E, 0x12, 0x34, 0xAA, 0xBB]),
                "7F2E22",
                expect_payload(bytes([0x7F, 0x2E, 0x22])),
            )
        )

    for result in results:
        print_result(result)

    csv_path = Path(args.csv)
    write_csv(csv_path, results)
    print(f"\nwrote {csv_path}")

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
