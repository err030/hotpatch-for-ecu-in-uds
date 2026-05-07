"""Mock ECU server 与运行时 patch 切换。

- 这个文件负责把 ECU 状态机暴露成字节 payload -> 字节 payload的服务端。
- 同时提供 runtime patch 生命周期，模拟 loading / activating / patched /
  failed / rollback。
"""

from __future__ import annotations

from dataclasses import dataclass

from .ecu import BaseECU


@dataclass
class MockEcuServer:
    """包一层 server 接口，便于 transport 直接调用"""

    ecu: BaseECU
    patch_state: str = "vulnerable"
    patch_steps_to_protection: int = 0

    def handle_payload(self, request_payload: bytes) -> bytes:
        return self.ecu.handle_payload(request_payload)

    def start_patch_loading(self) -> None:
        self.patch_state = "patch_loading"
        self.patch_steps_to_protection = 0

    def activate_patch(self) -> None:
        self.patch_state = "patch_activating"
        self.patch_steps_to_protection += 1
        self.ecu.apply_patch()
        self.patch_state = "patched"
        self.patch_steps_to_protection += 1

    def fail_patch(self) -> None:
        self.patch_state = "patch_failed"

    def rollback_patch(self) -> None:
        self.ecu.rollback_patch()
        self.patch_state = "vulnerable"
        self.patch_steps_to_protection = 0

    def apply_patch(self) -> None:
        self.start_patch_loading()
        self.activate_patch()

    def mode_name(self) -> str:
        return self.patch_state if self.patch_state != "vulnerable" else self.ecu.mode_name()
