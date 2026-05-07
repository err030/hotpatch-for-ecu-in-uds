"""
- 这个测试文件验证 gateway routing 策略和扩展攻击场景。
"""

import unittest

from src.hotpatch_uds.ecu import (
    ReplayWriteVulnerableECU,
    StickyUnlockAfterFailedKeyECU,
    StickyUnlockAfterSessionChangeECU,
    VALID_WRITE_DID,
)
from src.hotpatch_uds.gateway import GATEWAY_MODE_RESTRICTED
from src.hotpatch_uds.scenarios import (
    build_gateway_routed_client_and_server,
    derive_key_from_seed,
)
from src.hotpatch_uds.server import MockEcuServer


class GatewayAndAttackTests(unittest.TestCase):
    def test_restricted_gateway_blocks_write_service(self) -> None:
        server = MockEcuServer(ReplayWriteVulnerableECU())
        client = build_gateway_routed_client_and_server(
            server,
            gateway_mode=GATEWAY_MODE_RESTRICTED,
        )

        client.change_to_extended_session()
        with self.assertRaises(RuntimeError) as context:
            client.write_data_by_identifier(VALID_WRITE_DID, b"\x01")

        self.assertIn("blocked UDS service 0x2E", str(context.exception))

    def test_failed_key_can_leave_old_unlock_state_in_buggy_ecu(self) -> None:
        server = MockEcuServer(StickyUnlockAfterFailedKeyECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        seed_result = client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        client.send_key(key)
        client.request_seed()
        client.send_key(b"\x00\x00")
        write_result = client.write_data_by_identifier(VALID_WRITE_DID, b"\x02")

        self.assertTrue(write_result.response.positive)

    def test_session_change_can_leave_old_unlock_state_in_buggy_ecu(self) -> None:
        server = MockEcuServer(StickyUnlockAfterSessionChangeECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        seed_result = client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        client.send_key(key)
        client.change_to_default_session()
        client.change_to_extended_session()
        write_result = client.write_data_by_identifier(VALID_WRITE_DID, b"\x03")

        self.assertTrue(write_result.response.positive)

    def test_replay_write_without_new_unlock_can_succeed_in_buggy_ecu(self) -> None:
        server = MockEcuServer(ReplayWriteVulnerableECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        seed_result = client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        client.send_key(key)
        client.write_data_by_identifier(VALID_WRITE_DID, b"\x04")
        client.change_to_default_session()
        client.change_to_extended_session()
        replay_result = client.write_data_by_identifier(VALID_WRITE_DID, b"\x04")

        self.assertTrue(replay_result.response.positive)


if __name__ == "__main__":
    unittest.main()
