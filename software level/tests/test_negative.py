"""
- 这个测试文件验证 UDS 状态机里的负面场景和异常输入。
"""

import unittest

from src.hotpatch_uds.ecu import PatchedECU
from src.hotpatch_uds.protocol import (
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_SECURITY_ACCESS_DENIED,
    UDSResponse,
)
from src.hotpatch_uds.scenarios import build_gateway_routed_client_and_server
from src.hotpatch_uds.server import MockEcuServer


class NegativeBehaviorTests(unittest.TestCase):
    def test_send_key_before_request_seed_returns_sequence_error(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        response = client.send_key(b"\x00\x00").response

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_REQUEST_SEQUENCE_ERROR)

    def test_repeated_wrong_keys_trigger_lockout(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        client.request_seed()
        first_failure = client.send_key(b"\x00\x00").response
        client.request_seed()
        second_failure = client.send_key(b"\x00\x00").response
        locked_response = client.request_seed().response

        self.assertEqual(first_failure.nrc, NRC_SECURITY_ACCESS_DENIED)
        self.assertEqual(second_failure.nrc, NRC_SECURITY_ACCESS_DENIED)
        self.assertEqual(locked_response.nrc, NRC_SECURITY_ACCESS_DENIED)

    def test_malformed_session_control_payload_returns_length_error(self) -> None:
        ecu = PatchedECU()

        response = UDSResponse.from_payload(ecu.handle_payload(b"\x10"))

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)

    def test_malformed_read_payload_returns_length_error(self) -> None:
        ecu = PatchedECU()

        response = UDSResponse.from_payload(ecu.handle_payload(b"\x22\x12"))

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)

    def test_unknown_read_did_returns_out_of_range(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_gateway_routed_client_and_server(server)

        response = client.read_data_by_identifier(0x9999).response

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_REQUEST_OUT_OF_RANGE)

    def test_oversized_write_payload_returns_length_error_after_unlock(self) -> None:
        server = MockEcuServer(PatchedECU())
        client = build_gateway_routed_client_and_server(server)

        client.change_to_extended_session()
        seed_result = client.request_seed()
        seed = int.from_bytes(seed_result.response.data[1:], "big")
        client.send_key((seed ^ 0xA55A).to_bytes(2, "big"))
        response = client.write_data_by_identifier(0x1234, b"\x01\x02\x03\x04\x05").response

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)


if __name__ == "__main__":
    unittest.main()
