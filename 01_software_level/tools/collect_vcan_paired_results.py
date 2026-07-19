#!/usr/bin/env python3
"""Collect a deterministic before/after corpus over the real Linux vcan0 path."""

from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


SOFTWARE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOFTWARE_ROOT))

from src.hotpatch_uds.ecu import PatchableECU  # noqa: E402
from src.hotpatch_uds.scenarios import (  # noqa: E402
    build_socketcan_gateway_routed_client_and_server,
    derive_key_from_seed,
)
from src.hotpatch_uds.server import MockEcuServer  # noqa: E402


@dataclass(frozen=True)
class Mutation:
    case_id: int
    kind: str
    did: int
    data: bytes

    @property
    def payload(self) -> bytes:
        return bytes([0x2E, self.did >> 8, self.did & 0xFF]) + self.data


def build_corpus(count: int, seed: int) -> list[Mutation]:
    rng = random.Random(seed)
    rows: list[Mutation] = []
    for case_id in range(1, count + 1):
        roll = rng.random()
        if roll < 0.78:
            kind, did, length = "target_did_random_data", 0x1234, rng.choice((1, 2, 3, 4))
        elif roll < 0.88:
            kind, did, length = "unknown_did", rng.choice((0x2222, 0x3333, 0xF187)), rng.choice((1, 2, 3, 4))
        elif roll < 0.94:
            kind, did, length = "read_only_did", 0x1001, rng.choice((1, 2, 3))
        else:
            kind, did, length = "missing_data", 0x1234, 0
        rows.append(Mutation(case_id, kind, did, bytes(rng.randrange(256) for _ in range(length))))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="vcan0")
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260710)
    parser.add_argument("--output-dir", default="01_software_level/results/vcan")
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    corpus = build_corpus(args.cases, args.seed)
    rows: list[dict[str, object]] = []
    log_lines = [
        f"started_at={datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"interface={args.interface}",
        f"random_seed={args.seed}",
        f"cases_per_state={args.cases}",
    ]
    for patch_state in ("before", "after"):
        server = MockEcuServer(PatchableECU())
        if patch_state == "after":
            server.apply_patch()
        live = build_socketcan_gateway_routed_client_and_server(server, interface=args.interface)
        try:
            live.client.change_to_extended_session()
            seed_result = live.client.request_seed()
            live.client.send_key(derive_key_from_seed(seed_result.response))
            successes = 0
            for mutation in corpus:
                start_ns = time.perf_counter_ns()
                result = live.client.write_data_by_identifier(mutation.did, mutation.data)
                recv_ns = time.perf_counter_ns()
                response = result.exchange.response_payload
                positive = result.response.positive and result.response.sid == 0x6E
                successes += int(positive)
                rows.append(
                    {
                        "run_id": "vcan_paired_20260710",
                        "random_seed": args.seed,
                        "case_id": mutation.case_id,
                        "patch_state": patch_state,
                        "mutation_kind": mutation.kind,
                        "did": f"0x{mutation.did:04X}",
                        "payload_length": len(mutation.payload),
                        "request_payload": mutation.payload.hex().upper(),
                        "response_payload": response.hex().upper(),
                        "response_class": "positive" if result.response.positive else "negative",
                        "nrc": "" if result.response.positive else f"0x{result.response.nrc:02X}",
                        "attack_success": str(positive).lower(),
                        "send_monotonic_ns": start_ns,
                        "recv_monotonic_ns": recv_ns,
                        "latency_ms": f"{(recv_ns - start_ns) / 1_000_000:.6f}",
                        "timeout": "false",
                    }
                )
            log_lines.append(f"{patch_state}_attack_success={successes}/{args.cases}")
        finally:
            live.close()
    fieldnames = list(rows[0])
    with (out / "vcan_paired_detail.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    paired = all(
        rows[index]["request_payload"] == rows[index + args.cases]["request_payload"]
        for index in range(args.cases)
    )
    log_lines.append(f"paired_corpus_identical={str(paired).lower()}")
    log_lines.append(f"completed_at={datetime.now().astimezone().isoformat(timespec='seconds')}")
    (out / "vcan_paired.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print("\n".join(log_lines))
    print(f"wrote {out / 'vcan_paired_detail.csv'}")
    print(f"wrote {out / 'vcan_paired.log'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
