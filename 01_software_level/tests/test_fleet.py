"""
- 这个测试文件验证 fleet-level OTA-only 与 hotpatch-first 的比较结果。
"""

import unittest

from src.hotpatch_uds.fleet import (
    FleetConfig,
    FleetVehicle,
    AvailabilityWindow,
    simulate_hotpatch_first_then_ota,
    simulate_ota_only,
)


class FleetSimulationTests(unittest.TestCase):
    def test_hotpatch_first_reduces_time_to_first_protection(self) -> None:
        vehicles = (
            FleetVehicle(
                vehicle_id="v1",
                availability_windows=(
                    AvailabilityWindow(0, 10),
                    AvailabilityWindow(120, 180),
                ),
                hotpatch_capable=True,
            ),
            FleetVehicle(
                vehicle_id="v2",
                availability_windows=(
                    AvailabilityWindow(0, 10),
                    AvailabilityWindow(120, 180),
                ),
                hotpatch_capable=True,
            ),
        )
        config = FleetConfig(fleet_size=2, ota_slots=1, hotpatch_slots=2, horizon_end_minute=180)

        ota_only = simulate_ota_only(vehicles, config)
        hotpatch_first = simulate_hotpatch_first_then_ota(vehicles, config)

        self.assertLess(
            hotpatch_first.metrics.time_to_first_protection_min,
            ota_only.metrics.time_to_first_protection_min,
        )

    def test_hotpatch_first_reduces_cumulative_exposure_window(self) -> None:
        vehicles = (
            FleetVehicle(
                vehicle_id="v1",
                availability_windows=(
                    AvailabilityWindow(0, 10),
                    AvailabilityWindow(60, 120),
                ),
                hotpatch_capable=True,
            ),
            FleetVehicle(
                vehicle_id="v2",
                availability_windows=(
                    AvailabilityWindow(5, 15),
                    AvailabilityWindow(60, 120),
                ),
                hotpatch_capable=True,
            ),
            FleetVehicle(
                vehicle_id="v3",
                availability_windows=(
                    AvailabilityWindow(10, 20),
                    AvailabilityWindow(60, 150),
                ),
                hotpatch_capable=False,
            ),
        )
        config = FleetConfig(fleet_size=3, ota_slots=1, hotpatch_slots=2, horizon_end_minute=120)

        ota_only = simulate_ota_only(vehicles, config)
        hotpatch_first = simulate_hotpatch_first_then_ota(vehicles, config)

        self.assertLess(
            hotpatch_first.metrics.cumulative_exposure_window_min,
            ota_only.metrics.cumulative_exposure_window_min,
        )

    def test_hotpatch_first_can_increase_total_unavailable_time(self) -> None:
        vehicles = (
            FleetVehicle(
                vehicle_id="v1",
                availability_windows=(AvailabilityWindow(0, 180),),
                hotpatch_capable=True,
            ),
            FleetVehicle(
                vehicle_id="v2",
                availability_windows=(AvailabilityWindow(0, 180),),
                hotpatch_capable=True,
            ),
        )
        config = FleetConfig(fleet_size=2, ota_slots=2, hotpatch_slots=2, horizon_end_minute=180)

        ota_only = simulate_ota_only(vehicles, config)
        hotpatch_first = simulate_hotpatch_first_then_ota(vehicles, config)

        self.assertGreater(
            hotpatch_first.metrics.total_unavailable_vehicle_min,
            ota_only.metrics.total_unavailable_vehicle_min,
        )


if __name__ == "__main__":
    unittest.main()
