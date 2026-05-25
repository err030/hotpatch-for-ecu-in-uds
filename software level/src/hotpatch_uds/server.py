"""Mock ECU server 与运行时 patch 切换。

- 这个文件负责把 ECU 状态机暴露成字节 payload -> 字节 payload的服务端。
- 同时提供 runtime patch 生命周期，模拟 loading / activating / patched /
  failed / rollback。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ecu import BaseECU
from .hotpatch import HotpatchManager, build_uds_security_hotpatch


@dataclass
class MockEcuServer:
    """包一层 server 接口，便于 transport 直接调用"""

    ecu: BaseECU
    patch_state: str = "vulnerable"
    patch_steps_to_protection: int = 0
    hotpatch_manager: HotpatchManager = field(default_factory=HotpatchManager)
    next_patch_identifier: int = 1

    def handle_payload(self, request_payload: bytes) -> bytes:
        self.hotpatch_manager.guard_and_apply(self.ecu.apply_patch)
        self.patch_state = self.hotpatch_manager.patch_state
        return self.ecu.handle_payload(request_payload)

    def start_patch_loading(self) -> None:
        descriptor = build_uds_security_hotpatch(
            identifier=self.next_patch_identifier,
            vulnerability_count=max(self.ecu.vulnerability_count(), 1),
        )
        self.hotpatch_manager.stage(descriptor)
        self.patch_state = self.hotpatch_manager.patch_state
        self.patch_steps_to_protection = 0

    def activate_patch(self) -> None:
        if not self.hotpatch_manager.validate_and_store():
            self.patch_state = self.hotpatch_manager.patch_state
            return

        self.patch_steps_to_protection += 1
        staged_descriptor = self.hotpatch_manager.staged_descriptor
        if staged_descriptor is None:
            self.patch_state = self.hotpatch_manager.patch_state
            return
        if not self.hotpatch_manager.schedule(staged_descriptor.identifier):
            self.patch_state = self.hotpatch_manager.patch_state
            return

        self.hotpatch_manager.guard_and_apply(self.ecu.apply_patch)
        self.next_patch_identifier += 1
        self.patch_state = self.hotpatch_manager.patch_state
        self.patch_steps_to_protection += 1

    def fail_patch(self) -> None:
        self.patch_state = "patch_failed"
        self.hotpatch_manager.patch_state = "patch_failed"
        self.hotpatch_manager.metrics.rejected_patch_count += 1

    def rollback_patch(self) -> None:
        self.hotpatch_manager.rollback(self.ecu.rollback_patch)
        self.patch_state = self.hotpatch_manager.patch_state
        self.patch_steps_to_protection = 0

    def apply_patch(self) -> None:
        self.start_patch_loading()
        self.activate_patch()

    def mode_name(self) -> str:
        return self.patch_state if self.patch_state != "vulnerable" else self.ecu.mode_name()

    def describe_hotpatch_runtime(self) -> dict[str, int | float | str]:
        """导出 hotpatch manager 的软件级统计。"""
        return self.hotpatch_manager.describe()
