#!/usr/bin/env python3
"""Orchestrate three reset-isolated, seed-paired before/after fuzz runs."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


DEFAULT_SERIAL = "/dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_0034002C3235511437333439-if02"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--serial", default=DEFAULT_SERIAL)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--seeds", default="20260710,20260711,20260712")
    parser.add_argument("--output-dir", default="software level/results/20260710_hardware_fuzz")
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).with_name("run_hardware_uds_2e_fuzz_with_observer.py")
    seeds = [int(value.strip()) for value in args.seeds.split(",")]
    log_path = output / "orchestration.log"
    with log_path.open("w", encoding="utf-8", buffering=1) as log:
        for run_index, seed in enumerate(seeds, start=1):
            for patch_state in ("before", "after"):
                stamp = datetime.now().astimezone().isoformat(timespec="seconds")
                header = f"{stamp} start run_{run_index} seed={seed} patch_state={patch_state}"
                print(header, flush=True)
                log.write(header + "\n")
                reset = subprocess.run(["nrfjprog", "--reset"], capture_output=True, text=True)
                log.write(reset.stdout)
                log.write(reset.stderr)
                if reset.returncode != 0:
                    return reset.returncode
                time.sleep(1.0)
                tag = f"run{run_index}_seed{seed}_{patch_state}"
                command = [
                    sys.executable,
                    str(script),
                    "--interface",
                    args.interface,
                    "--serial",
                    args.serial,
                    "--iterations",
                    str(args.iterations),
                    "--seed",
                    str(seed),
                    "--run-id",
                    f"run_{run_index}",
                    "--patch-state",
                    patch_state,
                    "--timeout",
                    "0.3",
                    "--inter-request-delay-ms",
                    "20",
                    "--observer-drain-seconds",
                    "2",
                    "--tag",
                    tag,
                    "--charts-dir",
                    str(output),
                    "--pdf-dir",
                    str(output),
                    "--title",
                    f"Hardware fuzz run {run_index} {patch_state}",
                ]
                if patch_state == "after":
                    command.append("--trigger-hotpatch")
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                assert process.stdout is not None
                for line in process.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                return_code = process.wait()
                if return_code != 0:
                    log.write(f"campaign_failed return_code={return_code}\n")
                    return return_code
                log.write(f"completed run_{run_index} patch_state={patch_state}\n")
        log.write("all_campaigns_complete=true\n")
    print(f"wrote {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
