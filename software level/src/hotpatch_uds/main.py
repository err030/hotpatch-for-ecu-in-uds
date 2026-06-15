"""命令行入口。

- 运行这个文件后，可以看到 thesis 当前最核心的几组结果：
  1. gateway-routed UDS 下的基础攻击链
  2. 未授权写、错误 key、session 切换、重放等漏洞场景
  3. runtime patch 前后的行为变化
"""

from __future__ import annotations

from .backends import format_backend_matrix_lines
from .evaluation import format_hotpatch_evaluation_lines
from .scenarios import (
    build_reference_servers,
    run_failed_key_state_retention_attack,
    run_attack_with_unlock,
    run_attack_without_unlock,
    run_patch_failure_scenario,
    run_patch_rollback_scenario,
    run_replay_attack,
    run_runtime_hotpatch_scenario,
    run_session_change_state_retention_attack,
)
from .fleet import format_fleet_result, run_default_fleet_comparison
from .frameworks import (
    format_framework_status_lines,
    format_socketcan_status_lines,
    framework_readiness_summary,
)
from .differential import format_differential_comparison, run_default_differential_suite
from .timing import format_timing_summary, run_default_timing_comparison


def print_block(title: str, lines: list[str]) -> None:
    print(f"\n=== {title} ===")
    for line in lines:
        print(line)


def main() -> None:
    print_block(
        "Framework probe",
        format_framework_status_lines()
        + format_socketcan_status_lines()
        + format_backend_matrix_lines()
        + [framework_readiness_summary()],
    )

    vulnerable_server, patched_server = build_reference_servers()

    print_block(
        "Vulnerable ECU: attack without unlock",
        run_attack_without_unlock(vulnerable_server),
    )
    print_block(
        "Patched ECU: attack without unlock",
        run_attack_without_unlock(patched_server),
    )
    print_block(
        "Patched ECU: attack with unlock",
        run_attack_with_unlock(build_reference_servers()[1]),
    )
    print_block(
        "Patchable ECU: runtime hotpatch scenario",
        run_runtime_hotpatch_scenario(),
    )
    print_block(
        "Patchable ECU: failed patch scenario",
        run_patch_failure_scenario(),
    )
    print_block(
        "Patchable ECU: rollback scenario",
        run_patch_rollback_scenario(),
    )
    print_block(
        "Sticky unlock after failed key",
        run_failed_key_state_retention_attack(),
    )
    print_block(
        "Sticky unlock after session change",
        run_session_change_state_retention_attack(),
    )
    print_block(
        "Replay old write after session re-entry",
        run_replay_attack(),
    )

    ota_only_result, hotpatch_first_result = run_default_fleet_comparison(fleet_size=20)
    print_block(
        "Fleet strategy: OTA only",
        format_fleet_result(ota_only_result),
    )
    print_block(
        "Fleet strategy: hotpatch first then OTA",
        format_fleet_result(hotpatch_first_result),
    )

    vulnerable_timing, patched_timing = run_default_timing_comparison()
    print_block(
        "Timing model: vulnerable",
        format_timing_summary("vulnerable", vulnerable_timing),
    )
    print_block(
        "Timing model: patched",
        format_timing_summary("patched", patched_timing),
    )

    for comparison in run_default_differential_suite():
        print_block(
            f"Differential test: {comparison.case_name}",
            format_differential_comparison(comparison),
        )

    print_block(
        "Hotpatch evaluation",
        format_hotpatch_evaluation_lines(),
    )


if __name__ == "__main__":
    main()
