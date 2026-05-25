"""Backend definitions for the UDS simulation stack.

- 这个模块把当前仓库支持的 backend 明确成可枚举配置。
- 目标是把 software-only、python-can virtual、python-can socketcan/vcan0
  统一到一套命名和说明里，便于场景构建、文档和评估。
"""

from __future__ import annotations

from dataclasses import dataclass

from .frameworks import missing_framework_names, probe_socketcan_status


BACKEND_IN_MEMORY = "in_memory"
BACKEND_PYTHON_CAN_VIRTUAL = "python_can_virtual"
BACKEND_PYTHON_CAN_SOCKETCAN = "python_can_socketcan"


@dataclass(frozen=True)
class BackendConfig:
    """单个 backend 的声明式配置。"""

    name: str
    bus_layer: str
    transport_layer: str
    uds_layer: str
    channel: str
    uses_python_can: bool
    uses_can_isotp: bool
    uses_udsoncan: bool
    uses_os_can: bool


def default_backend_configs(
    *,
    virtual_channel: str = "hotpatch-uds",
    socketcan_channel: str = "vcan0",
) -> tuple[BackendConfig, ...]:
    """返回仓库默认支持的三层 backend。"""
    return (
        BackendConfig(
            name=BACKEND_IN_MEMORY,
            bus_layer="InMemoryCanBus",
            transport_layer="local IsoTpSender/Reassembler",
            uds_layer="local UdsClient",
            channel="memory",
            uses_python_can=False,
            uses_can_isotp=False,
            uses_udsoncan=False,
            uses_os_can=False,
        ),
        BackendConfig(
            name=BACKEND_PYTHON_CAN_VIRTUAL,
            bus_layer="python-can virtual",
            transport_layer="can-isotp",
            uds_layer="udsoncan connection",
            channel=virtual_channel,
            uses_python_can=True,
            uses_can_isotp=True,
            uses_udsoncan=True,
            uses_os_can=False,
        ),
        BackendConfig(
            name=BACKEND_PYTHON_CAN_SOCKETCAN,
            bus_layer="python-can socketcan",
            transport_layer="can-isotp",
            uds_layer="udsoncan connection",
            channel=socketcan_channel,
            uses_python_can=True,
            uses_can_isotp=True,
            uses_udsoncan=True,
            uses_os_can=True,
        ),
    )


def backend_config_by_name(
    backend_name: str,
    *,
    virtual_channel: str = "hotpatch-uds",
    socketcan_channel: str = "vcan0",
) -> BackendConfig:
    """按名字解析 backend 配置。"""
    for config in default_backend_configs(
        virtual_channel=virtual_channel,
        socketcan_channel=socketcan_channel,
    ):
        if config.name == backend_name:
            return config
    raise ValueError(f"Unsupported backend name: {backend_name}")


def format_backend_matrix_lines(
    *,
    virtual_channel: str = "hotpatch-uds",
    socketcan_channel: str = "vcan0",
) -> list[str]:
    """把 backend 矩阵格式化成命令行摘要。"""
    missing_frameworks = set(missing_framework_names())
    socketcan_status = probe_socketcan_status(socketcan_channel)
    lines: list[str] = []

    for config in default_backend_configs(
        virtual_channel=virtual_channel,
        socketcan_channel=socketcan_channel,
    ):
        ready = True
        blockers: list[str] = []
        if config.uses_python_can and "python-can" in missing_frameworks:
            ready = False
            blockers.append("python-can missing")
        if config.uses_can_isotp and "can-isotp" in missing_frameworks:
            ready = False
            blockers.append("can-isotp missing")
        if config.uses_udsoncan and "udsoncan" in missing_frameworks:
            ready = False
            blockers.append("udsoncan missing")
        if config.uses_os_can and not socketcan_status.interface_exists:
            ready = False
            blockers.append(f"{socketcan_channel} missing")

        readiness = "ready" if ready else "pending"
        blocker_text = ", ".join(blockers) if blockers else "-"
        lines.append(
            f"{config.name}: {readiness} bus={config.bus_layer} "
            f"transport={config.transport_layer} uds={config.uds_layer} "
            f"channel={config.channel} blockers={blocker_text}"
        )

    return lines
