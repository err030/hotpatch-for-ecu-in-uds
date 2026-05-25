"""Kintsugi-inspired hotpatch lifecycle model for the UDS simulation.

- 这个模块不尝试复制 Kintsugi 的底层 RTOS/MPU 实现。
- 它提取其关键结构：quarantine、slot、manager、guard/applicator、
  validation/scheduling/application overhead、resource accounting。
- 目标是把当前 thesis 里的 patch 行为从布尔开关升级成可评估的软件模型。
"""

from __future__ import annotations

from dataclasses import dataclass, field


PATCH_STATE_VULNERABLE = "vulnerable"
PATCH_STATE_LOADING = "patch_loading"
PATCH_STATE_VALIDATED = "patch_validated"
PATCH_STATE_SCHEDULED = "patch_scheduled"
PATCH_STATE_ACTIVATING = "patch_activating"
PATCH_STATE_PATCHED = "patched"
PATCH_STATE_FAILED = "patch_failed"
PATCH_STATE_ROLLED_BACK = "patch_rolled_back"

PATCH_SLOT_INACTIVE = "inactive"
PATCH_SLOT_PENDING = "pending"
PATCH_SLOT_SCHEDULED = "scheduled"
PATCH_SLOT_ACTIVE = "active"
PATCH_SLOT_BLOCKED = "blocked"
PATCH_SLOT_FAILED = "failed"


@dataclass(frozen=True)
class HotpatchDescriptor:
    """一个抽象 hotpatch 的元数据。"""

    identifier: int
    target_component: str
    patch_type: str
    code_size_bytes: int
    validation_time_ms: float
    scheduling_time_ms: float
    applicator_time_ms: float
    guard_overhead_ms: float
    fixes: tuple[str, ...]


@dataclass
class HotpatchSlot:
    """一个 hotpatch slot。"""

    identifier: int | None = None
    status: str = PATCH_SLOT_INACTIVE
    descriptor: HotpatchDescriptor | None = None


@dataclass
class HotpatchManagerConfig:
    """Kintsugi 风格 manager 配置。"""

    slot_count: int = 4
    quarantine_size_bytes: int = 256
    max_patch_code_size_bytes: int = 160
    slot_metadata_bytes: int = 48
    guard_context_bytes: int = 96
    manager_context_bytes: int = 128


@dataclass
class HotpatchMetrics:
    """manager / guard / applicator 统计。"""

    validation_count: int = 0
    scheduling_count: int = 0
    application_count: int = 0
    rollback_count: int = 0
    rejected_patch_count: int = 0
    guard_checks: int = 0
    total_validation_time_ms: float = 0.0
    total_scheduling_time_ms: float = 0.0
    total_application_time_ms: float = 0.0
    total_guard_time_ms: float = 0.0
    peak_quarantine_bytes: int = 0
    peak_active_code_bytes: int = 0


@dataclass
class HotpatchManager:
    """软件级 hotpatch manager。"""

    config: HotpatchManagerConfig = field(default_factory=HotpatchManagerConfig)
    slots: list[HotpatchSlot] = field(default_factory=list)
    metrics: HotpatchMetrics = field(default_factory=HotpatchMetrics)
    patch_state: str = PATCH_STATE_VULNERABLE
    staged_descriptor: HotpatchDescriptor | None = None
    active_identifier: int | None = None

    def __post_init__(self) -> None:
        if not self.slots:
            self.slots = [HotpatchSlot() for _ in range(self.config.slot_count)]

    def stage(self, descriptor: HotpatchDescriptor) -> None:
        """把 patch 放进 quarantine。"""
        self.staged_descriptor = descriptor
        self.patch_state = PATCH_STATE_LOADING
        self.metrics.peak_quarantine_bytes = max(
            self.metrics.peak_quarantine_bytes,
            descriptor.code_size_bytes,
        )

    def validate_and_store(self) -> bool:
        """验证 staged patch 并写入一个 pending slot。"""
        descriptor = self.staged_descriptor
        if descriptor is None:
            self.patch_state = PATCH_STATE_FAILED
            self.metrics.rejected_patch_count += 1
            return False

        self.metrics.validation_count += 1
        self.metrics.total_validation_time_ms += descriptor.validation_time_ms

        if descriptor.code_size_bytes > self.config.max_patch_code_size_bytes:
            self.patch_state = PATCH_STATE_FAILED
            self.metrics.rejected_patch_count += 1
            return False

        slot = self._first_free_slot()
        if slot is None:
            self.patch_state = PATCH_STATE_FAILED
            self.metrics.rejected_patch_count += 1
            return False

        slot.identifier = descriptor.identifier
        slot.descriptor = descriptor
        slot.status = PATCH_SLOT_PENDING
        self.patch_state = PATCH_STATE_VALIDATED
        return True

    def schedule(self, identifier: int) -> bool:
        """把一个 pending slot 置为 scheduled。"""
        slot = self._find_slot(identifier)
        if slot is None or slot.descriptor is None or slot.status != PATCH_SLOT_PENDING:
            self.patch_state = PATCH_STATE_FAILED
            self.metrics.rejected_patch_count += 1
            return False

        self.metrics.scheduling_count += 1
        self.metrics.total_scheduling_time_ms += slot.descriptor.scheduling_time_ms
        slot.status = PATCH_SLOT_SCHEDULED
        self.patch_state = PATCH_STATE_SCHEDULED
        return True

    def guard_and_apply(self, apply_callback) -> bool:
        """模拟 guard/applicator 在 safe point 应用 patch。"""
        self.metrics.guard_checks += 1

        scheduled_slot = self._first_slot_with_status(PATCH_SLOT_SCHEDULED)
        if scheduled_slot is None or scheduled_slot.descriptor is None:
            return False

        descriptor = scheduled_slot.descriptor
        self.metrics.total_guard_time_ms += descriptor.guard_overhead_ms
        self.patch_state = PATCH_STATE_ACTIVATING

        apply_callback()

        self.metrics.application_count += 1
        self.metrics.total_application_time_ms += descriptor.applicator_time_ms
        scheduled_slot.status = PATCH_SLOT_ACTIVE
        self.active_identifier = scheduled_slot.identifier
        self.patch_state = PATCH_STATE_PATCHED
        self.metrics.peak_active_code_bytes = max(
            self.metrics.peak_active_code_bytes,
            self.active_code_bytes(),
        )
        return True

    def rollback(self, rollback_callback) -> None:
        """回滚 active patch。"""
        rollback_callback()
        active_slot = self._first_slot_with_status(PATCH_SLOT_ACTIVE)
        if active_slot is not None:
            active_slot.status = PATCH_SLOT_BLOCKED
        self.active_identifier = None
        self.patch_state = PATCH_STATE_VULNERABLE
        self.metrics.rollback_count += 1

    def total_reserved_memory_bytes(self) -> int:
        """静态预留资源。"""
        return (
            self.config.quarantine_size_bytes
            + self.config.guard_context_bytes
            + self.config.manager_context_bytes
            + self.config.slot_count * self.config.slot_metadata_bytes
        )

    def active_code_bytes(self) -> int:
        """当前 active patch 占用的代码区大小。"""
        total = 0
        for slot in self.slots:
            if slot.status == PATCH_SLOT_ACTIVE and slot.descriptor is not None:
                total += slot.descriptor.code_size_bytes
        return total

    def current_quarantine_bytes(self) -> int:
        """当前 quarantine 使用量。"""
        if self.patch_state == PATCH_STATE_LOADING and self.staged_descriptor is not None:
            return self.staged_descriptor.code_size_bytes
        return 0

    def active_slot_count(self) -> int:
        return sum(1 for slot in self.slots if slot.status == PATCH_SLOT_ACTIVE)

    def describe(self) -> dict[str, int | float | str]:
        """导出给场景、图表和测试的摘要。"""
        return {
            "patch_state": self.patch_state,
            "active_identifier": self.active_identifier or 0,
            "active_slots": self.active_slot_count(),
            "reserved_memory_bytes": self.total_reserved_memory_bytes(),
            "active_code_bytes": self.active_code_bytes(),
            "quarantine_bytes": self.current_quarantine_bytes(),
            "validation_count": self.metrics.validation_count,
            "scheduling_count": self.metrics.scheduling_count,
            "application_count": self.metrics.application_count,
            "rollback_count": self.metrics.rollback_count,
            "guard_checks": self.metrics.guard_checks,
            "rejected_patch_count": self.metrics.rejected_patch_count,
            "total_validation_time_ms": round(self.metrics.total_validation_time_ms, 3),
            "total_scheduling_time_ms": round(self.metrics.total_scheduling_time_ms, 3),
            "total_application_time_ms": round(self.metrics.total_application_time_ms, 3),
            "total_guard_time_ms": round(self.metrics.total_guard_time_ms, 3),
            "peak_quarantine_bytes": self.metrics.peak_quarantine_bytes,
            "peak_active_code_bytes": self.metrics.peak_active_code_bytes,
        }

    def _find_slot(self, identifier: int) -> HotpatchSlot | None:
        for slot in self.slots:
            if slot.identifier == identifier:
                return slot
        return None

    def _first_free_slot(self) -> HotpatchSlot | None:
        for slot in self.slots:
            if slot.status == PATCH_SLOT_INACTIVE:
                return slot
        return None

    def _first_slot_with_status(self, status: str) -> HotpatchSlot | None:
        for slot in self.slots:
            if slot.status == status:
                return slot
        return None


def build_uds_security_hotpatch(
    *,
    identifier: int = 1,
    vulnerability_count: int = 4,
) -> HotpatchDescriptor:
    """构造默认的 UDS 授权路径 hotpatch。"""
    code_size = 48 + vulnerability_count * 16
    fixes = (
        "require_unlock_for_write",
        "clear_unlock_on_failed_key",
        "clear_unlock_on_session_change",
        "disable_authorized_write_replay",
    )
    return HotpatchDescriptor(
        identifier=identifier,
        target_component="uds_write_authorization_path",
        patch_type="policy_replacement",
        code_size_bytes=code_size,
        validation_time_ms=0.35 + vulnerability_count * 0.05,
        scheduling_time_ms=0.20 + vulnerability_count * 0.03,
        applicator_time_ms=0.75 + vulnerability_count * 0.08,
        guard_overhead_ms=0.04 + vulnerability_count * 0.01,
        fixes=fixes,
    )
