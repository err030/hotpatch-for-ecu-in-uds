"""Software-level evaluation for hotpatch effectiveness in UDS-on-CAN.

- 这个模块把 fleet、timing、hotpatch manager 和攻击链结果汇总到一套指标中。
- 输出面向 thesis：exposure window、resource utilization、real-time overhead、
  attack blocking rate。
"""

from __future__ import annotations

from dataclasses import dataclass
import csv
from io import StringIO

from .ecu import PatchableECU
from .fleet import run_default_fleet_comparison
from .server import MockEcuServer
from .timing import run_default_timing_comparison


@dataclass(frozen=True)
class AttackResistanceSummary:
    """单 ECU 攻击窗口里的结果。"""

    total_attack_attempts: int
    successful_attempts_before_hotpatch: int
    blocked_attempts_after_hotpatch: int
    successful_attempts_before_ota_only: int
    blocked_attempts_after_ota_only: int
    hotpatch_block_rate: float
    ota_only_block_rate: float


@dataclass(frozen=True)
class HotpatchEvaluationSummary:
    """用于图表和报告的汇总结果。"""

    reserved_memory_bytes: int
    peak_quarantine_bytes: int
    peak_active_code_bytes: int
    guard_overhead_total_ms: float
    validation_total_ms: float
    scheduling_total_ms: float
    application_total_ms: float
    vulnerable_attack_chain_latency_ms: float
    patched_attack_chain_latency_ms: float
    vulnerable_periodic_jitter_ms: float
    patched_periodic_jitter_ms: float
    ota_only_cumulative_exposure_window_min: int
    hotpatch_first_cumulative_exposure_window_min: int
    exposure_window_reduction_ratio: float
    attack_resistance: AttackResistanceSummary


def simulate_attack_window(
    *,
    hotpatch_activation_min: int,
    ota_activation_min: int,
    observation_window_min: int,
    attack_interval_min: int,
) -> AttackResistanceSummary:
    """把攻击机会抽象成固定周期请求，统计 hotpatch 前后阻挡率。"""
    attack_times = tuple(range(0, observation_window_min + 1, attack_interval_min))
    hotpatch_success = sum(1 for time in attack_times if time < hotpatch_activation_min)
    hotpatch_blocked = len(attack_times) - hotpatch_success
    ota_success = sum(1 for time in attack_times if time < ota_activation_min)
    ota_blocked = len(attack_times) - ota_success

    return AttackResistanceSummary(
        total_attack_attempts=len(attack_times),
        successful_attempts_before_hotpatch=hotpatch_success,
        blocked_attempts_after_hotpatch=hotpatch_blocked,
        successful_attempts_before_ota_only=ota_success,
        blocked_attempts_after_ota_only=ota_blocked,
        hotpatch_block_rate=round(hotpatch_blocked / len(attack_times), 4),
        ota_only_block_rate=round(ota_blocked / len(attack_times), 4),
    )


def evaluate_default_hotpatch_value() -> HotpatchEvaluationSummary:
    """运行默认软件级评估。"""
    patchable_server = MockEcuServer(PatchableECU())
    patchable_server.apply_patch()
    hotpatch_runtime = patchable_server.describe_hotpatch_runtime()

    vulnerable_timing, patched_timing = run_default_timing_comparison()
    ota_only, hotpatch_first = run_default_fleet_comparison(fleet_size=20)

    attack_summary = simulate_attack_window(
        hotpatch_activation_min=2,
        ota_activation_min=30,
        observation_window_min=30,
        attack_interval_min=1,
    )

    ota_exposure = ota_only.metrics.cumulative_exposure_window_min
    hotpatch_exposure = hotpatch_first.metrics.cumulative_exposure_window_min
    exposure_reduction_ratio = 0.0
    if ota_exposure > 0:
        exposure_reduction_ratio = round(1.0 - (hotpatch_exposure / ota_exposure), 4)

    return HotpatchEvaluationSummary(
        reserved_memory_bytes=int(hotpatch_runtime["reserved_memory_bytes"]),
        peak_quarantine_bytes=int(hotpatch_runtime["peak_quarantine_bytes"]),
        peak_active_code_bytes=int(hotpatch_runtime["peak_active_code_bytes"]),
        guard_overhead_total_ms=float(hotpatch_runtime["total_guard_time_ms"]),
        validation_total_ms=float(hotpatch_runtime["total_validation_time_ms"]),
        scheduling_total_ms=float(hotpatch_runtime["total_scheduling_time_ms"]),
        application_total_ms=float(hotpatch_runtime["total_application_time_ms"]),
        vulnerable_attack_chain_latency_ms=vulnerable_timing.total_attack_chain_latency_ms,
        patched_attack_chain_latency_ms=patched_timing.total_attack_chain_latency_ms,
        vulnerable_periodic_jitter_ms=vulnerable_timing.periodic_task_jitter_ms,
        patched_periodic_jitter_ms=patched_timing.periodic_task_jitter_ms,
        ota_only_cumulative_exposure_window_min=ota_exposure,
        hotpatch_first_cumulative_exposure_window_min=hotpatch_exposure,
        exposure_window_reduction_ratio=exposure_reduction_ratio,
        attack_resistance=attack_summary,
    )


def format_hotpatch_evaluation_lines(summary: HotpatchEvaluationSummary | None = None) -> list[str]:
    """命令行摘要。"""
    resolved = summary or evaluate_default_hotpatch_value()
    attack = resolved.attack_resistance
    return [
        f"reserved_memory_bytes: {resolved.reserved_memory_bytes}",
        f"peak_quarantine_bytes: {resolved.peak_quarantine_bytes}",
        f"peak_active_code_bytes: {resolved.peak_active_code_bytes}",
        f"manager_validation_total_ms: {resolved.validation_total_ms}",
        f"manager_scheduling_total_ms: {resolved.scheduling_total_ms}",
        f"guard_overhead_total_ms: {resolved.guard_overhead_total_ms}",
        f"applicator_total_ms: {resolved.application_total_ms}",
        f"vulnerable_attack_chain_latency_ms: {resolved.vulnerable_attack_chain_latency_ms}",
        f"patched_attack_chain_latency_ms: {resolved.patched_attack_chain_latency_ms}",
        f"ota_only_cumulative_exposure_window_min: {resolved.ota_only_cumulative_exposure_window_min}",
        f"hotpatch_first_cumulative_exposure_window_min: {resolved.hotpatch_first_cumulative_exposure_window_min}",
        f"exposure_window_reduction_ratio: {resolved.exposure_window_reduction_ratio}",
        f"hotpatch_block_rate: {attack.hotpatch_block_rate}",
        f"ota_only_block_rate: {attack.ota_only_block_rate}",
        f"total_attack_attempts: {attack.total_attack_attempts}",
    ]


def hotpatch_evaluation_csv(summary: HotpatchEvaluationSummary | None = None) -> str:
    """导出默认 CSV。"""
    resolved = summary or evaluate_default_hotpatch_value()
    attack = resolved.attack_resistance
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["metric", "value"])
    writer.writerow(["reserved_memory_bytes", resolved.reserved_memory_bytes])
    writer.writerow(["peak_quarantine_bytes", resolved.peak_quarantine_bytes])
    writer.writerow(["peak_active_code_bytes", resolved.peak_active_code_bytes])
    writer.writerow(["guard_overhead_total_ms", resolved.guard_overhead_total_ms])
    writer.writerow(["validation_total_ms", resolved.validation_total_ms])
    writer.writerow(["scheduling_total_ms", resolved.scheduling_total_ms])
    writer.writerow(["application_total_ms", resolved.application_total_ms])
    writer.writerow(["vulnerable_attack_chain_latency_ms", resolved.vulnerable_attack_chain_latency_ms])
    writer.writerow(["patched_attack_chain_latency_ms", resolved.patched_attack_chain_latency_ms])
    writer.writerow(["vulnerable_periodic_jitter_ms", resolved.vulnerable_periodic_jitter_ms])
    writer.writerow(["patched_periodic_jitter_ms", resolved.patched_periodic_jitter_ms])
    writer.writerow(
        ["ota_only_cumulative_exposure_window_min", resolved.ota_only_cumulative_exposure_window_min]
    )
    writer.writerow(
        [
            "hotpatch_first_cumulative_exposure_window_min",
            resolved.hotpatch_first_cumulative_exposure_window_min,
        ]
    )
    writer.writerow(["exposure_window_reduction_ratio", resolved.exposure_window_reduction_ratio])
    writer.writerow(["total_attack_attempts", attack.total_attack_attempts])
    writer.writerow(["hotpatch_block_rate", attack.hotpatch_block_rate])
    writer.writerow(["ota_only_block_rate", attack.ota_only_block_rate])
    return buffer.getvalue()


def hotpatch_evaluation_markdown(summary: HotpatchEvaluationSummary | None = None) -> str:
    """导出 thesis 可引用的 Markdown 摘要。"""
    resolved = summary or evaluate_default_hotpatch_value()
    attack = resolved.attack_resistance
    lines = [
        "# Hotpatch Evaluation",
        "",
        "## Exposure Window",
        "",
        f"- OTA-only cumulative exposure window: `{resolved.ota_only_cumulative_exposure_window_min}` min",
        f"- Hotpatch-first cumulative exposure window: `{resolved.hotpatch_first_cumulative_exposure_window_min}` min",
        f"- Relative reduction: `{resolved.exposure_window_reduction_ratio}`",
        "",
        "## Resource Utilization",
        "",
        f"- Reserved memory footprint: `{resolved.reserved_memory_bytes}` bytes",
        f"- Peak quarantine usage: `{resolved.peak_quarantine_bytes}` bytes",
        f"- Peak active code usage: `{resolved.peak_active_code_bytes}` bytes",
        "",
        "## Real-Time Overhead",
        "",
        f"- Validation overhead: `{resolved.validation_total_ms}` ms",
        f"- Scheduling overhead: `{resolved.scheduling_total_ms}` ms",
        f"- Guard overhead: `{resolved.guard_overhead_total_ms}` ms",
        f"- Application overhead: `{resolved.application_total_ms}` ms",
        f"- Vulnerable attack chain latency: `{resolved.vulnerable_attack_chain_latency_ms}` ms",
        f"- Patched attack chain latency: `{resolved.patched_attack_chain_latency_ms}` ms",
        "",
        "## Attack Resistance",
        "",
        f"- Total attack attempts in observation window: `{attack.total_attack_attempts}`",
        f"- Hotpatch block rate: `{attack.hotpatch_block_rate}`",
        f"- OTA-only block rate in same window: `{attack.ota_only_block_rate}`",
    ]
    return "\n".join(lines)
