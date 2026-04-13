"""命令行入口。

- 运行这个文件后，可以看到 software-only simulation 的四个核心结果：
  1. vulnerable ECU 未解锁也能写
  2. patched ECU 未解锁会被拒绝
  3. patched ECU 解锁后可以写
  4. runtime patch 会改变同一条写路径的行为
"""

from __future__ import annotations

from .scenarios import (
    build_reference_servers,
    run_attack_with_unlock,
    run_attack_without_unlock,
    run_runtime_patch_demo,
)


def print_block(title: str, lines: list[str]) -> None:
    print(f"\n=== {title} ===")
    for line in lines:
        print(line)


def main() -> None:
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
        "Patchable ECU: runtime patch demo",
        run_runtime_patch_demo(),
    )


if __name__ == "__main__":
    main()
