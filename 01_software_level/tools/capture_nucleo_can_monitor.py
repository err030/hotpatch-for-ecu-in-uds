#!/usr/bin/env python3
"""Capture Nucleo CAN observer UART logs, optionally triggering can0 requests."""

from __future__ import annotations

import argparse
import os
import subprocess
import termios
import time
from pathlib import Path


DEFAULT_SERIAL = "/dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_0034002C3235511437333439-if02"
DEFAULT_LOG = "software level/charts/nucleo_can_monitor_latest.log"
DEFAULT_REQUEST_FRAME = "7E0#0210010000000000"


def configure_serial(fd: int, baud: int) -> None:
    baud_map = {
        9600: termios.B9600,
        19200: termios.B19200,
        38400: termios.B38400,
        57600: termios.B57600,
        115200: termios.B115200,
    }
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


def read_available(fd: int) -> bytes:
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


def capture(args: argparse.Namespace) -> str:
    fd = os.open(args.serial, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure_serial(fd, args.baud)
        chunks: list[bytes] = []
        start = time.monotonic()
        next_send = start + args.initial_delay
        sent = 0

        while time.monotonic() - start < args.duration:
            now = time.monotonic()
            if sent < args.send_requests and now >= next_send:
                subprocess.run(["cansend", args.interface, args.request_frame], check=False)
                sent += 1
                next_send = now + args.send_interval

            data = read_available(fd)
            if data:
                chunks.append(data)
            time.sleep(0.02)

        data = read_available(fd)
        if data:
            chunks.append(data)
    finally:
        os.close(fd)

    text = b"".join(chunks).decode("ascii", errors="replace")
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    Path(args.log).write_text(text, encoding="utf-8")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default=DEFAULT_SERIAL, help="UART device path.")
    parser.add_argument("--baud", type=int, default=115200, help="UART baud rate.")
    parser.add_argument("--duration", type=float, default=5.0, help="Capture duration in seconds.")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Output log path.")
    parser.add_argument("--interface", default="can0", help="SocketCAN interface for optional trigger traffic.")
    parser.add_argument("--send-requests", type=int, default=0, help="Number of can0 requests to send during capture.")
    parser.add_argument("--request-frame", default=DEFAULT_REQUEST_FRAME, help="CAN frame passed to cansend.")
    parser.add_argument("--initial-delay", type=float, default=0.2, help="Delay before first optional request.")
    parser.add_argument("--send-interval", type=float, default=0.5, help="Delay between optional requests.")
    args = parser.parse_args()

    text = capture(args)
    lines = [line for line in text.splitlines() if line.strip()]
    mon_lines = [line for line in lines if line.startswith("MON,")]
    print(f"captured_lines={len(lines)} mon_lines={len(mon_lines)}")
    print(f"wrote {args.log}")
    if mon_lines:
        print(mon_lines[0])
        if len(mon_lines) > 1:
            print(mon_lines[-1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
