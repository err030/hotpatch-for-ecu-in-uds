"""
- 这个测试文件验证可选的 SocketCAN/vcan backend。
- 若宿主机没有准备 `vcan0`，这些测试会自动跳过。
"""

import unittest

from src.hotpatch_uds.ecu import PatchedECU, VulnerableECU
from src.hotpatch_uds.frameworks import probe_socketcan_status
from src.hotpatch_uds.socketcan import socketcan_raw_socket_usable
from src.hotpatch_uds.gateway import GATEWAY_MODE_RESTRICTED
from src.hotpatch_uds.scenarios import (
    build_socketcan_direct_client_and_server,
    build_socketcan_gateway_routed_client_and_server,
    derive_key_from_seed,
)
from src.hotpatch_uds.server import MockEcuServer


class SocketCanIntegrationTests(unittest.TestCase):
    interface_name = "vcan0"

    def require_vcan(self) -> None:
        status = probe_socketcan_status(self.interface_name)
        if not status.python_socketcan_supported:
            self.skipTest("Python runtime does not expose SocketCAN raw sockets")
        if not status.interface_exists:
            self.skipTest("SocketCAN interface vcan0 is not configured on this host")
        if not socketcan_raw_socket_usable(self.interface_name):
            self.skipTest("Current process cannot open raw CAN sockets on vcan0")

    def test_direct_roundtrip_over_vcan(self) -> None:
        self.require_vcan()
        live = build_socketcan_direct_client_and_server(
            MockEcuServer(VulnerableECU()),
            interface=self.interface_name,
        )
        self.addCleanup(live.close)

        result = live.client.change_to_extended_session()

        self.assertTrue(result.response.positive)
        self.assertEqual(result.response.sid, 0x50)

    def test_patched_write_requires_unlock_over_vcan(self) -> None:
        self.require_vcan()
        live = build_socketcan_direct_client_and_server(
            MockEcuServer(PatchedECU()),
            interface=self.interface_name,
        )
        self.addCleanup(live.close)

        live.client.change_to_extended_session()
        failed = live.client.write_data_by_identifier(0x1234, b"\x01")

        seed_result = live.client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        live.client.send_key(key)
        succeeded = live.client.write_data_by_identifier(0x1234, b"\x02")

        self.assertFalse(failed.response.positive)
        self.assertEqual(failed.response.nrc, 0x33)
        self.assertTrue(succeeded.response.positive)

    def test_gateway_policy_is_enforced_over_vcan(self) -> None:
        self.require_vcan()
        live = build_socketcan_gateway_routed_client_and_server(
            MockEcuServer(VulnerableECU()),
            interface=self.interface_name,
            gateway_mode=GATEWAY_MODE_RESTRICTED,
        )
        self.addCleanup(live.close)

        live.client.change_to_extended_session()
        with self.assertRaises(RuntimeError) as context:
            live.client.write_data_by_identifier(0x1234, b"\x03")

        self.assertIn("blocked UDS service 0x2E", str(context.exception))


if __name__ == "__main__":
    unittest.main()
