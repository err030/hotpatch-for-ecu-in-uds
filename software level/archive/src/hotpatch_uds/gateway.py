"""Gateway 诊断路由模型。

- 这个文件模拟自动驾驶车队场景里常见的 gateway-routed diagnostics。
- 它把 tester 外侧的诊断 ID 转发到 gateway 后侧 ECU 的内部诊断 ID。
- 它也支持简单的 routing policy，用于研究 open / restricted / misconfigured
  三种 gateway 行为。

参考来源：
- Green, Chatterjee, Daily, Exploiting Diagnostic Protocol Vulnerabilities on
  Embedded Networks in Commercial Vehicles:
  https://www.ndss-symposium.org/ndss-paper/auto-draft-480/
- udsoncan 文档: https://udsoncan.readthedocs.io/en/latest/
"""

from __future__ import annotations

from dataclasses import dataclass

from .bus import InMemoryCanBus
from .isotp import CanFrame, FRAME_TYPE_FIRST, FRAME_TYPE_SINGLE
from .protocol import (
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_SECURITY_ACCESS,
    SID_WRITE_DATA_BY_IDENTIFIER,
)


GATEWAY_MODE_OPEN = "open"
GATEWAY_MODE_RESTRICTED = "restricted"
GATEWAY_MODE_MISCONFIGURED = "misconfigured"


@dataclass(frozen=True)
class GatewayRoute:
    """一条 tester -> gateway -> ECU 的诊断路由。"""

    external_request_id: int = 0x7E0
    internal_request_id: int = 0x6E0
    internal_response_id: int = 0x6E8
    external_response_id: int = 0x7E8


def gateway_allowed_services(mode: str) -> set[int] | None:
    """根据 gateway 策略返回允许转发的 UDS 服务集合。"""
    if mode == GATEWAY_MODE_OPEN:
        return None
    if mode == GATEWAY_MODE_RESTRICTED:
        return {
            SID_DIAGNOSTIC_SESSION_CONTROL,
            SID_SECURITY_ACCESS,
        }
    if mode == GATEWAY_MODE_MISCONFIGURED:
        return {
            SID_DIAGNOSTIC_SESSION_CONTROL,
            SID_SECURITY_ACCESS,
            SID_WRITE_DATA_BY_IDENTIFIER,
        }
    raise ValueError(f"Unsupported gateway mode: {mode}")


def service_id_from_can_frame(frame: CanFrame) -> int | None:
    """尽量从单帧或首帧里读出 UDS SID，用于 gateway 策略判断。"""
    if not frame.data:
        return None

    pci_type = frame.data[0] >> 4
    if pci_type == FRAME_TYPE_SINGLE:
        if len(frame.data) < 2:
            return None
        return frame.data[1]

    if pci_type == FRAME_TYPE_FIRST:
        if len(frame.data) < 3:
            return None
        return frame.data[2]

    return None


class RoutedDiagnosticGateway:
    """最小 gateway 模型，负责转发外侧和内侧诊断流量。"""

    def __init__(
        self,
        bus: InMemoryCanBus,
        name: str = "gateway",
        route: GatewayRoute | None = None,
        mode: str = GATEWAY_MODE_MISCONFIGURED,
    ) -> None:
        self.bus = bus
        self.name = name
        self.route = route or GatewayRoute()
        self.mode = mode
        self.allowed_services = gateway_allowed_services(mode)
        self.last_drop_reason: str | None = None
        self.bus.register(
            self.name,
            accepted_arbitration_ids={
                self.route.external_request_id,
                self.route.internal_response_id,
            },
        )

    def clear_drop_reason(self) -> None:
        self.last_drop_reason = None

    def forward_all_pending(self) -> None:
        """把 gateway 队列里的所有待处理帧按策略转发出去。"""
        for frame in self.bus.drain(self.name):
            if frame.arbitration_id == self.route.external_request_id:
                if not self._allow_request_frame(frame):
                    continue
                self.bus.send(
                    self.name,
                    CanFrame(arbitration_id=self.route.internal_request_id, data=frame.data),
                )
                continue

            if frame.arbitration_id == self.route.internal_response_id:
                self.bus.send(
                    self.name,
                    CanFrame(arbitration_id=self.route.external_response_id, data=frame.data),
                )

    def _allow_request_frame(self, frame: CanFrame) -> bool:
        sid = service_id_from_can_frame(frame)
        if self.allowed_services is None or sid is None:
            return True
        if sid in self.allowed_services:
            return True

        self.last_drop_reason = (
            f"gateway mode '{self.mode}' blocked UDS service 0x{sid:02X}"
        )
        return False
