"""
- 这个测试文件验证 gateway routing 策略和扩展攻击场景。
"""

import unittest

from src.hotpatch_uds.ecu import (
    BaseECU,
    READ_ONLY_STATUS_DID,
    ReplayWriteVulnerableECU,
    StickyUnlockAfterFailedKeyECU,
    StickyUnlockAfterSessionChangeECU,
    VALID_WRITE_DID,
)
from src.hotpatch_uds.protocol import (
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_REQUEST_OUT_OF_RANGE,
    SESSION_EXTENDED,
    SID_WRITE_DATA_BY_IDENTIFIER,
    UDSRequest,
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

    def test_restricted_gateway_allows_read_service(self) -> None:
        server = MockEcuServer(ReplayWriteVulnerableECU())
        client = build_gateway_routed_client_and_server(
            server,
            gateway_mode=GATEWAY_MODE_RESTRICTED,
        )

        result = client.read_data_by_identifier(READ_ONLY_STATUS_DID)

        self.assertTrue(result.response.positive)
        self.assertEqual(result.response.sid, 0x62)

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

    def test_replay_authorization_does_not_bypass_quarantine(self) -> None:
        ecu = BaseECU(
            write_requires_unlock=True,
            allow_replay_without_unlock=True,
            quarantine_config_write_did=True,
        )
        replay_value = b"\x04"
        ecu.state.session = SESSION_EXTENDED
        ecu.state.last_authorized_write = (VALID_WRITE_DID, replay_value)

        response = ecu.handle(
            UDSRequest(
                sid=SID_WRITE_DATA_BY_IDENTIFIER,
                did=VALID_WRITE_DID,
                data=replay_value,
            )
        )

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_REQUEST_OUT_OF_RANGE)
        self.assertNotIn(VALID_WRITE_DID, ecu.state.writes)

    def test_replay_authorization_does_not_bypass_length_check(self) -> None:
        ecu = BaseECU(
            write_requires_unlock=True,
            allow_replay_without_unlock=True,
        )
        oversized_value = b"\x01\x02\x03\x04\x05"
        ecu.state.session = SESSION_EXTENDED
        ecu.state.last_authorized_write = (VALID_WRITE_DID, oversized_value)

        response = ecu.handle(
            UDSRequest(
                sid=SID_WRITE_DATA_BY_IDENTIFIER,
                did=VALID_WRITE_DID,
                data=oversized_value,
            )
        )

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)
        self.assertNotIn(VALID_WRITE_DID, ecu.state.writes)


if __name__ == "__main__":
    unittest.main()
