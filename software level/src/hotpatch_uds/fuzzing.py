"""Systematic fuzzing corpus and runners.

- 这个文件用于生成系统化 fuzzing / negative testing 用例。
- 重点是：
  - 针对 parser 的边界输入
  - 针对 state machine 的非法序列
  - 针对 ISO-TP 的异常帧序列
- 每一类异常都能解释清楚。
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .differential import DifferentialCase, DifferentialOperation


@dataclass(frozen=True)
class PayloadFuzzCase:
    """UDS payload parser 用例。"""

    name: str
    payload: bytes


@dataclass(frozen=True)
class IsoTpFrameFuzzCase:
    """ISO-TP 异常帧用例。"""

    name: str
    first_frame_payload: bytes
    malformed_sequence_numbers: tuple[int, ...]


def build_protocol_payload_corpus(seed: int = 20260503) -> tuple[PayloadFuzzCase, ...]:
    """生成一组确定性的 parser fuzz corpus。"""
    rng = random.Random(seed)
    base_cases = [
        PayloadFuzzCase("empty", b""),
        PayloadFuzzCase("short_session", b"\x10"),
        PayloadFuzzCase("short_read", b"\x22\x12"),
        PayloadFuzzCase("short_security", b"\x27"),
        PayloadFuzzCase("short_write", b"\x2E\x12"),
        PayloadFuzzCase("unknown_sid", b"\x99\x00"),
        PayloadFuzzCase("valid_session", b"\x10\x03"),
        PayloadFuzzCase("valid_read", b"\x22\x12\x34"),
        PayloadFuzzCase("valid_seed_request", b"\x27\x01"),
        PayloadFuzzCase("valid_write", b"\x2E\x12\x34\xAA"),
    ]
    for index in range(12):
        length = 1 + (index % 5)
        payload = bytes(rng.randrange(0, 256) for _ in range(length))
        base_cases.append(PayloadFuzzCase(f"mutated_{index:02d}", payload))
    return tuple(base_cases)


def build_state_sequence_corpus() -> tuple[DifferentialCase, ...]:
    """生成一组 UDS 状态机序列 fuzz 用例。"""
    return (
        DifferentialCase(
            name="write_without_session",
            operations=(DifferentialOperation("write", did=0x1234, data=b"\x01"),),
        ),
        DifferentialCase(
            name="send_key_without_seed",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("send_invalid_key", data=b"\x00\x00"),
            ),
        ),
        DifferentialCase(
            name="double_seed_then_valid_key",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
            ),
        ),
        DifferentialCase(
            name="session_flip_then_write",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
                DifferentialOperation("change_to_default_session"),
                DifferentialOperation("write", did=0x1234, data=b"\x02"),
            ),
        ),
    )


def build_isotp_frame_corpus() -> tuple[IsoTpFrameFuzzCase, ...]:
    """生成一组 ISO-TP 异常帧序号用例。"""
    return (
        IsoTpFrameFuzzCase(
            name="unexpected_sequence_number_5",
            first_frame_payload=b"\x2E\x12\x34\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A",
            malformed_sequence_numbers=(5,),
        ),
        IsoTpFrameFuzzCase(
            name="unexpected_sequence_number_0_after_ff",
            first_frame_payload=b"\x2E\x12\x34\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22\x33\x44",
            malformed_sequence_numbers=(0,),
        ),
    )
