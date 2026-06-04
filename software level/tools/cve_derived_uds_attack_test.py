#!/usr/bin/env python3
"""Run CVE-derived UDS attack checks over SocketCAN.

These tests map Kintsugi real-world CVE bug classes to this project's actual
UDS-over-CAN input surface. They are not claims that this ECU contains the
original vulnerable components.
"""

from __future__ import annotations

import argparse
import csv
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


CAN_SFF_MASK = 0x000007FF
DEFAULT_REQUEST_ID = 0x7E0
DEFAULT_RESPONSE_ID = 0x7E8
UDS_SEED_MASK = 0xA55A
SESSION_EXTENDED_RESPONSE = bytes([0x50, 0x03, 0x00, 0x32, 0x13, 0x88])


@dataclass(frozen=True)
class TestResult:
    cve_basis: str
    case: str
    request: str
    response: str
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
    return can_id & CAN_SFF_MASK, data[:dlc]


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


def expect_no_response(payload: bytes | None) -> tuple[bool, str]:
    if payload is None:
        return True, "no response, malformed frame was dropped before dispatcher"
    return False, f"expected no response, got {hex_bytes(payload)}"


def expect_seed(payload: bytes | None) -> tuple[bool, str]:
    if payload is None:
        return False, "no response"
    if len(payload) != 4 or payload[0] != 0x67 or payload[1] != 0x01:
        return False, f"expected 6701xxxx, got {hex_bytes(payload)}"
    return True, f"seed=0x{((payload[2] << 8) | payload[3]):04X}"


def parse_seed(payload: bytes | None) -> int:
    if payload is None or len(payload) != 4 or payload[0] != 0x67 or payload[1] != 0x01:
        raise RuntimeError(f"cannot parse seed from {hex_bytes(payload)}")
    return (payload[2] << 8) | payload[3]


def recv_response(can_socket: socket.socket, response_id: int, timeout_s: float) -> bytes | None:
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


def send_raw(
    can_socket: socket.socket,
    request_id: int,
    response_id: int,
    data: bytes,
    timeout_s: float,
) -> bytes | None:
    can_socket.send(pack_can_frame(request_id, data))
    return recv_response(can_socket, response_id, timeout_s)


def send_uds(
    can_socket: socket.socket,
    request_id: int,
    response_id: int,
    payload: bytes,
    timeout_s: float,
) -> bytes | None:
    return send_raw(
        can_socket,
        request_id,
        response_id,
        pack_single_frame_payload(payload),
        timeout_s,
    )


def run_case(
    can_socket: socket.socket,
    args: argparse.Namespace,
    cve_basis: str,
    case: str,
    request_label: str,
    sender: Callable[[], bytes | None],
    expected_label: str,
    expectation: Expectation,
) -> TestResult:
    response = sender()
    passed, note = expectation(response)
    return TestResult(
        cve_basis=cve_basis,
        case=case,
        request=request_label,
        response=hex_bytes(response),
        expected=expected_label,
        passed=passed,
        note=note,
    )


def print_result(result: TestResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(
        f"{status:4} {result.cve_basis:15} {result.case:38} "
        f"resp={result.response:14} {result.note}"
    )


def write_csv(path: Path, results: list[TestResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve_basis", "case", "request", "response", "expected", "passed", "note"])
        for result in results:
            writer.writerow(
                [
                    result.cve_basis,
                    result.case,
                    result.request,
                    result.response,
                    result.expected,
                    "true" if result.passed else "false",
                    result.note,
                ]
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run CVE-derived UDS attack tests.")
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID, type=lambda value: int(value, 0))
    parser.add_argument("--response-id", default=DEFAULT_RESPONSE_ID, type=lambda value: int(value, 0))
    parser.add_argument("--timeout", default=1.0, type=float)
    parser.add_argument(
        "--csv",
        default="software level/charts/cve_derived_uds_attack_latest.csv",
        help="CSV output path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    results: list[TestResult] = []

    with socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as can_socket:
        can_socket.bind((args.interface,))

        results.append(
            run_case(
                can_socket,
                args,
                "CVE-2020-17443",
                "short DiagnosticSessionControl request",
                "UDS 10",
                lambda: send_uds(can_socket, args.request_id, args.response_id, bytes([0x10]), args.timeout),
                "7F1013",
                expect_payload(bytes([0x7F, 0x10, 0x13])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "CVE-2018-16603",
                "single-frame PCI length exceeds actual DLC",
                "raw 072E12",
                lambda: send_raw(can_socket, args.request_id, args.response_id, bytes([0x07, 0x2E, 0x12]), args.timeout),
                "<none>",
                expect_no_response,
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "setup",
                "enter extended session",
                "UDS 1003",
                lambda: send_uds(can_socket, args.request_id, args.response_id, bytes([0x10, 0x03]), args.timeout),
                "500300321388",
                expect_payload(SESSION_EXTENDED_RESPONSE),
            )
        )
        seed_response = send_uds(can_socket, args.request_id, args.response_id, bytes([0x27, 0x01]), args.timeout)
        seed_ok, seed_note = expect_seed(seed_response)
        results.append(
            TestResult(
                cve_basis="setup",
                case="request seed",
                request="UDS 2701",
                response=hex_bytes(seed_response),
                expected="6701xxxx",
                passed=seed_ok,
                note=seed_note,
            )
        )

        try:
            seed = parse_seed(seed_response)
            key = seed ^ UDS_SEED_MASK
            key_payload = bytes([0x27, 0x02, (key >> 8) & 0xFF, key & 0xFF])
        except RuntimeError:
            key_payload = bytes([0x27, 0x02, 0x00, 0x00])

        results.append(
            run_case(
                can_socket,
                args,
                "setup",
                "unlock security level 1",
                f"UDS {key_payload.hex().upper()}",
                lambda: send_uds(can_socket, args.request_id, args.response_id, key_payload, args.timeout),
                "6702",
                expect_payload(bytes([0x67, 0x02])),
            )
        )
        results.append(
            run_case(
                can_socket,
                args,
                "CVE-2018-16524",
                "DID write with zero-length data",
                "UDS 2E1234",
                lambda: send_uds(can_socket, args.request_id, args.response_id, bytes([0x2E, 0x12, 0x34]), args.timeout),
                "7F2E13",
                expect_payload(bytes([0x7F, 0x2E, 0x13])),
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
