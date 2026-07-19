"""Timing model for UDS handlers and hotpatch overhead.

- 这个文件用于完成 thesis 软件模拟中的 timing model。
- 它是一个可解释的、可重复的、参数明确的抽象时间模型。
- 目标是先比较 patch 前后 UDS handler 开销、周期任务抖动和 patch activation delay。

参考来源：
- Kintsugi: https://www.usenix.org/conference/usenixsecurity25/presentation/mackensen
- HERA: https://www.ndss-symposium.org/ndss-paper/hera-hotpatching-of-embedded-real-time-applications/
"""

from __future__ import annotations

from dataclasses import dataclass

from .protocol import (
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_SECURITY_ACCESS,
    SID_WRITE_DATA_BY_IDENTIFIER,
)


@dataclass(frozen=True)
class TimingModelConfig:
    """默认 timing model 参数，单位为毫秒。"""

    periodic_task_period_ms: float = 10.0
    periodic_task_execution_ms: float = 2.5
    session_control_handler_ms: float = 0.45
    security_request_seed_handler_ms: float = 0.80
    security_send_key_handler_ms: float = 1.20
    write_handler_vulnerable_ms: float = 0.90
    write_handler_patched_ms: float = 1.05
    patch_check_overhead_ms: float = 0.15
    patch_loading_delay_ms: float = 3.5
    patch_activation_delay_ms: float = 2.0
    patch_rollback_delay_ms: float = 1.2


@dataclass(frozen=True)
class TimingObservation:
    """单个服务或动作的 timing 结果。"""

    label: str
    duration_ms: float


@dataclass(frozen=True)
class TimingSummary:
    """一组 timing 指标的摘要。"""

    total_attack_chain_latency_ms: float
    write_handler_latency_ms: float
    periodic_task_jitter_ms: float
    patch_activation_total_delay_ms: float
    patch_rollback_delay_ms: float


def service_handler_latency_ms(
    sid: int,
    *,
    patched: bool,
    subfunction: int | None = None,
    config: TimingModelConfig | None = None,
) -> float:
    """返回指定 UDS 服务的 handler 执行时间。"""
    cfg = config or TimingModelConfig()
    if sid == SID_DIAGNOSTIC_SESSION_CONTROL:
        return cfg.session_control_handler_ms
    if sid == SID_SECURITY_ACCESS:
        if subfunction == 0x01:
            return cfg.security_request_seed_handler_ms
        return cfg.security_send_key_handler_ms
    if sid == SID_WRITE_DATA_BY_IDENTIFIER:
        return cfg.write_handler_patched_ms if patched else cfg.write_handler_vulnerable_ms
    raise ValueError(f"Unsupported SID for timing model: 0x{sid:02X}")


def estimate_attack_chain_timing(
    *,
    patched: bool,
    config: TimingModelConfig | None = None,
) -> TimingSummary:
    """估计 0x10 -> 0x27 -> 0x2E 这条链的时间开销。"""
    cfg = config or TimingModelConfig()
    session_latency = service_handler_latency_ms(
        SID_DIAGNOSTIC_SESSION_CONTROL,
        patched=patched,
        config=cfg,
    )
    request_seed_latency = service_handler_latency_ms(
        SID_SECURITY_ACCESS,
        patched=patched,
        subfunction=0x01,
        config=cfg,
    )
    send_key_latency = service_handler_latency_ms(
        SID_SECURITY_ACCESS,
        patched=patched,
        subfunction=0x02,
        config=cfg,
    )
    write_latency = service_handler_latency_ms(
        SID_WRITE_DATA_BY_IDENTIFIER,
        patched=patched,
        config=cfg,
    )
    total_chain = session_latency + request_seed_latency + send_key_latency + write_latency
    jitter = estimate_periodic_task_jitter_ms(
        write_handler_latency_ms=write_latency,
        periodic_task_execution_ms=cfg.periodic_task_execution_ms,
        periodic_task_period_ms=cfg.periodic_task_period_ms,
    )
    patch_activation_total = cfg.patch_loading_delay_ms + cfg.patch_activation_delay_ms

    return TimingSummary(
        total_attack_chain_latency_ms=round(total_chain, 3),
        write_handler_latency_ms=round(write_latency, 3),
        periodic_task_jitter_ms=round(jitter, 3),
        patch_activation_total_delay_ms=round(patch_activation_total, 3),
        patch_rollback_delay_ms=round(cfg.patch_rollback_delay_ms, 3),
    )


def estimate_periodic_task_jitter_ms(
    *,
    write_handler_latency_ms: float,
    periodic_task_execution_ms: float,
    periodic_task_period_ms: float,
) -> float:
    """估计单次写服务对周期任务的最坏情况抖动。"""
    available_slack = max(periodic_task_period_ms - periodic_task_execution_ms, 0.0)
    blocking_overhead = max(write_handler_latency_ms - available_slack, 0.0)
    if blocking_overhead > 0:
        return blocking_overhead
    return min(write_handler_latency_ms * 0.25, available_slack * 0.25)


def format_timing_summary(label: str, summary: TimingSummary) -> list[str]:
    """把 timing 摘要格式化成便于 thesis 记录的文本。"""
    return [
        f"timing_case: {label}",
        f"total_attack_chain_latency_ms: {summary.total_attack_chain_latency_ms}",
        f"write_handler_latency_ms: {summary.write_handler_latency_ms}",
        f"periodic_task_jitter_ms: {summary.periodic_task_jitter_ms}",
        f"patch_activation_total_delay_ms: {summary.patch_activation_total_delay_ms}",
        f"patch_rollback_delay_ms: {summary.patch_rollback_delay_ms}",
    ]


def run_default_timing_comparison(
    config: TimingModelConfig | None = None,
) -> tuple[TimingSummary, TimingSummary]:
    """返回 vulnerable 与 patched 的默认 timing 对比。"""
    cfg = config or TimingModelConfig()
    return (
        estimate_attack_chain_timing(patched=False, config=cfg),
        estimate_attack_chain_timing(patched=True, config=cfg),
    )
