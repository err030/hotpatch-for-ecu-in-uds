"""Framework probing and integration notes.

中文说明：
- 这个文件用于检查当前环境里已有的 CAN / ISO-TP / UDS Python 框架。
- 它不负责真正接入这些框架，只负责探测、整理角色和输出后续接入建议。
- 这样可以先为 `vcan / SocketCAN / python-can / can-isotp / udsoncan`
  做准备，而不强制当前仓库立刻依赖它们。
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from importlib.util import find_spec
from pathlib import Path
import socket


@dataclass(frozen=True)
class FrameworkStatus:
    """单个框架的环境状态。"""

    package_name: str
    display_name: str
    role: str
    reference_url: str
    installed: bool
    version: str | None
    integration_priority: int


@dataclass(frozen=True)
class SocketCanStatus:
    """SocketCAN / vcan 环境状态。"""

    interface_name: str
    python_socketcan_supported: bool
    interface_exists: bool
    interface_type_hint: str


def probe_python_frameworks() -> tuple[FrameworkStatus, ...]:
    """检查当前 Python 环境是否安装了目标框架。"""
    candidates = (
        (
            "can",
            "python-can",
            "CAN bus abstraction, virtual bus, SocketCAN backend",
            "https://github.com/hardbyte/python-can",
            1,
        ),
        (
            "isotp",
            "can-isotp",
            "ISO-TP transport over user-space CAN or Linux ISO-TP sockets",
            "https://github.com/pylessard/python-can-isotp",
            2,
        ),
        (
            "udsoncan",
            "udsoncan",
            "Synchronous UDS client and response parsing",
            "https://github.com/pylessard/python-udsoncan",
            3,
        ),
    )
    statuses: list[FrameworkStatus] = []
    for package_name, display_name, role, url, priority in candidates:
        installed = find_spec(package_name) is not None
        version = None
        if installed:
            try:
                distribution_name = display_name if display_name != "udsoncan" else "udsoncan"
                version = metadata.version(distribution_name)
            except metadata.PackageNotFoundError:
                version = "unknown"
        statuses.append(
            FrameworkStatus(
                package_name=package_name,
                display_name=display_name,
                role=role,
                reference_url=url,
                installed=installed,
                version=version,
                integration_priority=priority,
            )
        )
    return tuple(statuses)


def format_framework_status_lines(statuses: tuple[FrameworkStatus, ...] | None = None) -> list[str]:
    """把框架状态格式化成便于 thesis 记录的文本。"""
    resolved = statuses or probe_python_frameworks()
    lines: list[str] = []
    for status in sorted(resolved, key=lambda item: item.integration_priority):
        install_text = "installed" if status.installed else "missing"
        version_text = status.version or "-"
        lines.append(
            f"{status.display_name}: {install_text} version={version_text} role={status.role}"
        )
    return lines


def missing_framework_names(statuses: tuple[FrameworkStatus, ...] | None = None) -> tuple[str, ...]:
    """返回当前还没有安装的框架名。"""
    resolved = statuses or probe_python_frameworks()
    return tuple(status.display_name for status in resolved if not status.installed)


def framework_readiness_summary(statuses: tuple[FrameworkStatus, ...] | None = None) -> str:
    """给出一句总括性判断。"""
    resolved = statuses or probe_python_frameworks()
    missing = missing_framework_names(resolved)
    if not missing:
        return "python-can / can-isotp / udsoncan are available for vcan preparation"
    return f"frameworks still missing: {', '.join(missing)}"


def probe_socketcan_status(interface_name: str = "vcan0") -> SocketCanStatus:
    """检查标准库 SocketCAN 能力和目标接口是否存在。"""
    interface_path = Path("/sys/class/net", interface_name)
    interface_type_hint = "missing"
    if interface_path.exists():
        type_file = interface_path / "type"
        if type_file.exists():
            type_value = type_file.read_text(encoding="utf-8").strip()
            interface_type_hint = "can-like" if type_value == "280" else type_value
        else:
            interface_type_hint = "present"

    return SocketCanStatus(
        interface_name=interface_name,
        python_socketcan_supported=hasattr(socket, "AF_CAN") and hasattr(socket, "CAN_RAW"),
        interface_exists=interface_path.exists(),
        interface_type_hint=interface_type_hint,
    )


def format_socketcan_status_lines(interface_name: str = "vcan0") -> list[str]:
    """把 SocketCAN/vcan 状态格式化成命令行可读文本。"""
    status = probe_socketcan_status(interface_name)
    return [
        (
            f"socketcan-python: {'available' if status.python_socketcan_supported else 'missing'} "
            f"interface={status.interface_name}"
        ),
        (
            f"socketcan-interface: {'present' if status.interface_exists else 'missing'} "
            f"type={status.interface_type_hint}"
        ),
    ]
