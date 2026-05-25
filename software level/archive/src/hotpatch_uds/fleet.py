"""Fleet-level OTA and hotpatch strategy simulation.

- 这个文件用于把当前单 ECU 的 UDS/hotpatch 原型提升到 fleet-level 抽象模拟。
- 它比较两种策略：`ota_only` 和 `hotpatch_first_then_ota`。
- 目标是评估保护时间、累计暴露时间和车辆不可用时间。

参考来源：
- FleetPy: https://github.com/TUM-VT/FleetPy
- SimPy 文档: https://simpy.readthedocs.io/en/stable/
- Uptane: https://github.com/uptane
- aktualizr: https://github.com/uptane/aktualizr
- Eclipse hawkBit: https://projects.eclipse.org/projects/iot.hawkbit
- Mender: https://github.com/mendersoftware/mender
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil


STRATEGY_OTA_ONLY = "ota_only"
STRATEGY_HOTPATCH_FIRST = "hotpatch_first_then_ota"


@dataclass(frozen=True)
class AvailabilityWindow:
    """车辆可用于更新的时间窗口，单位默认按分钟建模。"""

    start_minute: int
    end_minute: int

    def can_fit(self, start_time: int, duration: int) -> bool:
        return self.start_minute <= start_time and start_time + duration <= self.end_minute


@dataclass(frozen=True)
class FleetVehicle:
    """车队中的一辆车。"""

    vehicle_id: str
    availability_windows: tuple[AvailabilityWindow, ...]
    hotpatch_capable: bool = True
    priority: int = 0
    ota_duration_min: int = 30
    hotpatch_duration_min: int = 2


@dataclass(frozen=True)
class FleetConfig:
    """车队策略比较的全局配置。"""

    campaign_start_minute: int = 0
    fleet_size: int = 100
    ota_slots: int = 5
    hotpatch_slots: int = 20
    protection_ratio_target: float = 0.8
    horizon_end_minute: int = 24 * 60


@dataclass(frozen=True)
class ScheduledAction:
    """单个更新动作的调度结果。"""

    vehicle_id: str
    action_kind: str
    start_minute: int
    end_minute: int
    slot_index: int

    @property
    def duration_min(self) -> int:
        return self.end_minute - self.start_minute


@dataclass(frozen=True)
class FleetMetrics:
    """策略比较输出指标。"""

    strategy_name: str
    time_to_first_protection_min: int
    time_to_target_protection_min: int
    cumulative_exposure_window_min: int
    response_unavailable_vehicle_min: int
    total_unavailable_vehicle_min: int
    protected_vehicle_count: int
    target_protection_vehicle_count: int
    total_vehicle_count: int


@dataclass(frozen=True)
class FleetSimulationResult:
    """一次策略运行的完整结果。"""

    metrics: FleetMetrics
    actions: tuple[ScheduledAction, ...]
    protected_at_by_vehicle: dict[str, int]
    final_ota_at_by_vehicle: dict[str, int]


def build_periodic_windows(
    *,
    start_offset_min: int,
    short_window_every_min: int,
    short_window_length_min: int,
    horizon_end_minute: int,
    overnight_window_start_min: int,
    overnight_window_length_min: int,
) -> tuple[AvailabilityWindow, ...]:
    """构造重复出现的短窗口，再附加一个更长的夜间窗口。"""
    windows: list[AvailabilityWindow] = []
    current = start_offset_min
    while current < horizon_end_minute:
        windows.append(
            AvailabilityWindow(
                start_minute=current,
                end_minute=min(current + short_window_length_min, horizon_end_minute),
            )
        )
        current += short_window_every_min

    overnight_start = overnight_window_start_min
    overnight_end = min(overnight_window_start_min + overnight_window_length_min, horizon_end_minute)
    if overnight_start < overnight_end:
        windows.append(AvailabilityWindow(start_minute=overnight_start, end_minute=overnight_end))

    windows.sort(key=lambda item: item.start_minute)
    return tuple(windows)


def build_default_autonomous_fleet(
    *,
    fleet_size: int = 100,
    horizon_end_minute: int = 24 * 60,
    hotpatch_capable_ratio: float = 0.8,
) -> tuple[FleetVehicle, ...]:
    """构造一个偏向自动驾驶运营车队的抽象 fleet。"""
    vehicles: list[FleetVehicle] = []
    hotpatch_capable_count = ceil(fleet_size * hotpatch_capable_ratio)

    for index in range(fleet_size):
        offset = (index % 6) * 5
        windows = build_periodic_windows(
            start_offset_min=offset,
            short_window_every_min=240,
            short_window_length_min=45,
            horizon_end_minute=horizon_end_minute,
            overnight_window_start_min=22 * 60 + (index % 4) * 5,
            overnight_window_length_min=180,
        )
        vehicles.append(
            FleetVehicle(
                vehicle_id=f"vehicle-{index:03d}",
                availability_windows=windows,
                hotpatch_capable=index < hotpatch_capable_count,
                priority=0 if index < hotpatch_capable_count else 1,
            )
        )

    return tuple(vehicles)


def simulate_ota_only(
    vehicles: tuple[FleetVehicle, ...],
    config: FleetConfig,
) -> FleetSimulationResult:
    """只执行完整 OTA。"""
    ota_actions, ota_finish_times = _schedule_actions(
        vehicles=vehicles,
        action_kind="ota",
        slot_count=config.ota_slots,
        ready_times={vehicle.vehicle_id: config.campaign_start_minute for vehicle in vehicles},
    )

    protected_at = dict(ota_finish_times)
    return _build_result(
        strategy_name=STRATEGY_OTA_ONLY,
        vehicles=vehicles,
        config=config,
        actions=ota_actions,
        protected_at_by_vehicle=protected_at,
        final_ota_at_by_vehicle=dict(ota_finish_times),
    )


def simulate_hotpatch_first_then_ota(
    vehicles: tuple[FleetVehicle, ...],
    config: FleetConfig,
) -> FleetSimulationResult:
    """先执行短 hotpatch，再在后续窗口执行完整 OTA。"""
    hotpatch_candidates = tuple(vehicle for vehicle in vehicles if vehicle.hotpatch_capable)
    non_hotpatch_candidates = tuple(vehicle for vehicle in vehicles if not vehicle.hotpatch_capable)

    hotpatch_actions, hotpatch_finish_times = _schedule_actions(
        vehicles=hotpatch_candidates,
        action_kind="hotpatch",
        slot_count=config.hotpatch_slots,
        ready_times={vehicle.vehicle_id: config.campaign_start_minute for vehicle in hotpatch_candidates},
    )

    ota_ready_times = {
        vehicle.vehicle_id: hotpatch_finish_times.get(vehicle.vehicle_id, config.campaign_start_minute)
        for vehicle in vehicles
    }
    ota_actions, ota_finish_times = _schedule_actions(
        vehicles=vehicles,
        action_kind="ota",
        slot_count=config.ota_slots,
        ready_times=ota_ready_times,
    )

    protected_at = dict(ota_finish_times)
    for vehicle_id, hotpatch_finish in hotpatch_finish_times.items():
        protected_at[vehicle_id] = hotpatch_finish
    for vehicle in non_hotpatch_candidates:
        protected_at[vehicle.vehicle_id] = ota_finish_times[vehicle.vehicle_id]

    return _build_result(
        strategy_name=STRATEGY_HOTPATCH_FIRST,
        vehicles=vehicles,
        config=config,
        actions=hotpatch_actions + ota_actions,
        protected_at_by_vehicle=protected_at,
        final_ota_at_by_vehicle=dict(ota_finish_times),
    )


def format_fleet_result(result: FleetSimulationResult) -> list[str]:
    """把 fleet-level 结果格式化成便于 thesis 记录的文本。"""
    metrics = result.metrics
    return [
        f"strategy: {metrics.strategy_name}",
        f"time_to_first_protection_min: {metrics.time_to_first_protection_min}",
        (
            f"time_to_{metrics.target_protection_vehicle_count}_vehicle_protection_min: "
            f"{metrics.time_to_target_protection_min}"
        ),
        f"cumulative_exposure_window_min: {metrics.cumulative_exposure_window_min}",
        f"response_unavailable_vehicle_min: {metrics.response_unavailable_vehicle_min}",
        f"total_unavailable_vehicle_min: {metrics.total_unavailable_vehicle_min}",
        f"protected_vehicle_count: {metrics.protected_vehicle_count}/{metrics.total_vehicle_count}",
        f"scheduled_actions: {len(result.actions)}",
    ]


def run_default_fleet_comparison(
    *,
    fleet_size: int = 100,
    horizon_end_minute: int = 24 * 60,
) -> tuple[FleetSimulationResult, FleetSimulationResult]:
    """给 main 和测试提供一个默认 fleet 比较场景。"""
    config = FleetConfig(
        fleet_size=fleet_size,
        horizon_end_minute=horizon_end_minute,
    )
    vehicles = build_default_autonomous_fleet(
        fleet_size=fleet_size,
        horizon_end_minute=horizon_end_minute,
    )
    return simulate_ota_only(vehicles, config), simulate_hotpatch_first_then_ota(vehicles, config)


def _schedule_actions(
    *,
    vehicles: tuple[FleetVehicle, ...],
    action_kind: str,
    slot_count: int,
    ready_times: dict[str, int],
) -> tuple[tuple[ScheduledAction, ...], dict[str, int]]:
    actions: list[ScheduledAction] = []
    finish_times: dict[str, int] = {}
    slot_available_times = [0 for _ in range(slot_count)]

    sorted_vehicles = sorted(vehicles, key=lambda vehicle: (vehicle.priority, vehicle.vehicle_id))
    for vehicle in sorted_vehicles:
        duration = vehicle.hotpatch_duration_min if action_kind == "hotpatch" else vehicle.ota_duration_min
        ready_time = ready_times[vehicle.vehicle_id]
        action = _schedule_vehicle_action(
            vehicle=vehicle,
            action_kind=action_kind,
            duration=duration,
            ready_time=ready_time,
            slot_available_times=slot_available_times,
        )
        actions.append(action)
        finish_times[vehicle.vehicle_id] = action.end_minute
        slot_available_times[action.slot_index] = action.end_minute

    return tuple(actions), finish_times


def _schedule_vehicle_action(
    *,
    vehicle: FleetVehicle,
    action_kind: str,
    duration: int,
    ready_time: int,
    slot_available_times: list[int],
) -> ScheduledAction:
    best_action: ScheduledAction | None = None

    for slot_index, slot_free_time in enumerate(slot_available_times):
        for window in vehicle.availability_windows:
            candidate_start = max(window.start_minute, ready_time, slot_free_time)
            if not window.can_fit(candidate_start, duration):
                continue
            candidate_action = ScheduledAction(
                vehicle_id=vehicle.vehicle_id,
                action_kind=action_kind,
                start_minute=candidate_start,
                end_minute=candidate_start + duration,
                slot_index=slot_index,
            )
            if best_action is None or candidate_action.end_minute < best_action.end_minute:
                best_action = candidate_action
            break

    if best_action is None:
        raise RuntimeError(
            f"Unable to schedule {action_kind} for {vehicle.vehicle_id}; "
            "availability windows are too short or horizon is too small"
        )

    return best_action


def _build_result(
    *,
    strategy_name: str,
    vehicles: tuple[FleetVehicle, ...],
    config: FleetConfig,
    actions: tuple[ScheduledAction, ...],
    protected_at_by_vehicle: dict[str, int],
    final_ota_at_by_vehicle: dict[str, int],
) -> FleetSimulationResult:
    protected_times = sorted(protected_at_by_vehicle.values())
    total_vehicle_count = len(vehicles)
    target_count = ceil(total_vehicle_count * config.protection_ratio_target)
    first_protection = protected_times[0] - config.campaign_start_minute
    target_protection = protected_times[target_count - 1] - config.campaign_start_minute
    cumulative_exposure = sum(time - config.campaign_start_minute for time in protected_times)

    response_unavailable = 0
    total_unavailable = 0
    for action in actions:
        total_unavailable += action.duration_min
        if protected_at_by_vehicle[action.vehicle_id] == action.end_minute:
            response_unavailable += action.duration_min

    metrics = FleetMetrics(
        strategy_name=strategy_name,
        time_to_first_protection_min=first_protection,
        time_to_target_protection_min=target_protection,
        cumulative_exposure_window_min=cumulative_exposure,
        response_unavailable_vehicle_min=response_unavailable,
        total_unavailable_vehicle_min=total_unavailable,
        protected_vehicle_count=len(protected_at_by_vehicle),
        target_protection_vehicle_count=target_count,
        total_vehicle_count=total_vehicle_count,
    )
    return FleetSimulationResult(
        metrics=metrics,
        actions=actions,
        protected_at_by_vehicle=protected_at_by_vehicle,
        final_ota_at_by_vehicle=final_ota_at_by_vehicle,
    )
