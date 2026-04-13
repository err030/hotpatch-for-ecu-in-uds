"""中文说明：
- 这个测试文件验证完整 software-only simulation 的关键行为。
"""

import unittest

from src.hotpatch_uds_sim.ecu import PatchableECU, PatchedECU, VulnerableECU
from src.hotpatch_uds_sim.scenarios import (
    build_default_client_and_server,
    derive_key_from_seed,
)
from src.hotpatch_uds_sim.server import MockEcuServer


class SimulationTests(unittest.TestCase):
    def test_vulnerable_write_without_unlock_succeeds(self) -> None:
        server = MockEcuServer(VulnerableECU())
        client = build_default_client_and_server(server)

        client.change_to_extended_session()
        result = client.write_data_by_identifier(0x1234, b"\x01")
        self.assertTrue(result.response.positive)
        self.assertEqual(result.response.sid, 0x6E)

    def test_patched_write_without_unlock_fails(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_default_client_and_server(server)

        client.change_to_extended_session()
        result = client.write_data_by_identifier(0x1234, b"\x01")
        self.assertFalse(result.response.positive)
        self.assertEqual(result.response.nrc, 0x33)

    def test_patched_write_after_unlock_succeeds(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_default_client_and_server(server)

        client.change_to_extended_session()
        seed_result = client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        client.send_key(key)
        write_result = client.write_data_by_identifier(0x1234, b"\x02\x03\x04\x05\x06")

        self.assertTrue(write_result.response.positive)
        self.assertEqual(write_result.response.sid, 0x6E)

    def test_runtime_patch_changes_behavior(self) -> None:
        server = MockEcuServer(PatchableECU())
        client = build_default_client_and_server(server)

        client.change_to_extended_session()
        before_patch = client.write_data_by_identifier(0x1234, b"\x03")
        server.apply_patch()
        after_patch = client.write_data_by_identifier(0x1234, b"\x03")

        self.assertTrue(before_patch.response.positive)
        self.assertFalse(after_patch.response.positive)
        self.assertEqual(after_patch.response.nrc, 0x33)


if __name__ == "__main__":
    unittest.main()
