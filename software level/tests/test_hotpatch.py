"""
- 这个测试文件验证 Kintsugi 风格 hotpatch manager 的软件级生命周期。
"""

import unittest

from src.hotpatch_uds.ecu import PatchableECU
from src.hotpatch_uds.hotpatch import (
    PATCH_STATE_LOADING,
    PATCH_STATE_PATCHED,
    PATCH_STATE_SCHEDULED,
    PATCH_STATE_VALIDATED,
    build_uds_security_hotpatch,
    HotpatchManager,
)
from src.hotpatch_uds.server import MockEcuServer


class HotpatchManagerTests(unittest.TestCase):
    def test_manager_tracks_patch_lifecycle(self) -> None:
        manager = HotpatchManager()
        descriptor = build_uds_security_hotpatch(identifier=7, vulnerability_count=3)

        manager.stage(descriptor)
        self.assertEqual(manager.patch_state, PATCH_STATE_LOADING)

        self.assertTrue(manager.validate_and_store())
        self.assertEqual(manager.patch_state, PATCH_STATE_VALIDATED)

        self.assertTrue(manager.schedule(7))
        self.assertEqual(manager.patch_state, PATCH_STATE_SCHEDULED)

        applied = manager.guard_and_apply(lambda: None)
        self.assertTrue(applied)
        self.assertEqual(manager.patch_state, PATCH_STATE_PATCHED)
        self.assertEqual(manager.active_slot_count(), 1)

    def test_server_exposes_hotpatch_runtime_metrics(self) -> None:
        server = MockEcuServer(PatchableECU())

        server.apply_patch()
        runtime = server.describe_hotpatch_runtime()

        self.assertEqual(runtime["patch_state"], PATCH_STATE_PATCHED)
        self.assertEqual(runtime["application_count"], 1)
        self.assertGreater(runtime["reserved_memory_bytes"], 0)
        self.assertGreater(runtime["peak_active_code_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
