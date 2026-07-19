"""
- 这个测试文件验证可选的 python-can + can-isotp + udsoncan backend。
- 如果相关依赖没有安装，则自动跳过。
"""

import unittest

from src.hotpatch_uds.ecu import PatchedECU, VulnerableECU
from src.hotpatch_uds.frameworks import missing_framework_names, probe_socketcan_status
from src.hotpatch_uds.gateway import GATEWAY_MODE_RESTRICTED
from src.hotpatch_uds.socketcan import socketcan_raw_socket_usable
from src.hotpatch_uds.scenarios import (
    build_python_can_socketcan_direct_client_and_server,
    build_python_can_socketcan_gateway_routed_client_and_server,
    build_python_can_virtual_direct_client_and_server,
    build_python_can_virtual_gateway_routed_client_and_server,
    derive_key_from_seed,
)
from src.hotpatch_uds.server import MockEcuServer


class PythonCanIntegrationTests(unittest.TestCase):
    socketcan_interface = "vcan0"

    def require_frameworks(self) -> None:
        missing = set(missing_framework_names())
        needed = {"python-can", "can-isotp", "udsoncan"}
        unresolved = sorted(needed.intersection(missing))
        if unresolved:
            self.skipTest(f"Missing optional frameworks: {', '.join(unresolved)}")

    def require_socketcan(self) -> None:
        self.require_frameworks()
        status = probe_socketcan_status(self.socketcan_interface)
        if not status.interface_exists:
            self.skipTest("SocketCAN interface vcan0 is not configured on this host")
        if not socketcan_raw_socket_usable(self.socketcan_interface):
            self.skipTest("Current process cannot open raw CAN sockets on vcan0")

    def test_virtual_direct_roundtrip(self) -> None:
        self.require_frameworks()
        live = build_python_can_virtual_direct_client_and_server(
            MockEcuServer(VulnerableECU()),
            channel="test-hotpatch-uds",
        )
        self.addCleanup(live.close)

        result = live.client.change_to_extended_session()

        self.assertTrue(result.response.positive)
        self.assertEqual(result.response.sid, 0x50)

    def test_virtual_patched_write_requires_unlock(self) -> None:
        self.require_frameworks()
        live = build_python_can_virtual_direct_client_and_server(
            MockEcuServer(PatchedECU()),
            channel="test-hotpatch-uds-auth",
        )
        self.addCleanup(live.close)

        live.client.change_to_extended_session()
        failed = live.client.write_data_by_identifier(0x1234, b"\x01")
        seed_result = live.client.request_seed()
        key = derive_key_from_seed(seed_result.response)
        live.client.send_key(key)
        succeeded = live.client.write_data_by_identifier(0x1234, b"\x02")

        self.assertFalse(failed.response.positive)
        self.assertTrue(succeeded.response.positive)

    def test_virtual_gateway_policy_enforcement(self) -> None:
        self.require_frameworks()
        live = build_python_can_virtual_gateway_routed_client_and_server(
            MockEcuServer(VulnerableECU()),
            channel="test-hotpatch-uds-gw",
            gateway_mode=GATEWAY_MODE_RESTRICTED,
        )
        self.addCleanup(live.close)

        live.client.change_to_extended_session()
        with self.assertRaises(RuntimeError) as context:
            live.client.write_data_by_identifier(0x1234, b"\x03")

        self.assertIn("blocked UDS service 0x2E", str(context.exception))

    def test_socketcan_direct_roundtrip(self) -> None:
        self.require_socketcan()
        live = build_python_can_socketcan_direct_client_and_server(
            MockEcuServer(VulnerableECU()),
            interface=self.socketcan_interface,
        )
        self.addCleanup(live.close)

        result = live.client.change_to_extended_session()

        self.assertTrue(result.response.positive)
        self.assertEqual(result.response.sid, 0x50)

    def test_socketcan_patched_write_requires_unlock(self) -> None:
        self.require_socketcan()
        live = build_python_can_socketcan_direct_client_and_server(
            MockEcuServer(PatchedECU()),
            interface=self.socketcan_interface,
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

    def test_socketcan_gateway_policy_enforcement(self) -> None:
        self.require_socketcan()
        live = build_python_can_socketcan_gateway_routed_client_and_server(
            MockEcuServer(VulnerableECU()),
            interface=self.socketcan_interface,
            gateway_mode=GATEWAY_MODE_RESTRICTED,
        )
        self.addCleanup(live.close)

        live.client.change_to_extended_session()
        with self.assertRaises(RuntimeError) as context:
            live.client.write_data_by_identifier(0x1234, b"\x03")

        self.assertIn("blocked UDS service 0x2E", str(context.exception))


if __name__ == "__main__":
    unittest.main()
