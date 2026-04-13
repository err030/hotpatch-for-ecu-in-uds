"""Mock ECU server 与运行时 patch 切换。

- 这个文件负责把 ECU 状态机暴露成字节 payload -> 字节 payload的服务端。
- 同时提供 runtime patch 切换，模拟 hotpatch 前后行为变化。
"""

from __future__ import annotations

from dataclasses import dataclass

from .ecu import BaseECU


@dataclass
class MockEcuServer:
    """包一层 server 接口，便于 transport 直接调用"""

    ecu: BaseECU

    def handle_payload(self, request_payload: bytes) -> bytes:
        return self.ecu.handle_payload(request_payload)

    def apply_patch(self) -> None:
        self.ecu.apply_patch()

    def mode_name(self) -> str:
        return self.ecu.mode_name()
