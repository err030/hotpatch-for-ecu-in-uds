"""
- 这个测试文件补充更系统的负面测试，覆盖 parser、DID 长度和 ISO-TP 异常序号。
"""

import unittest

from src.hotpatch_uds.ecu import PatchedECU
from src.hotpatch_uds.isotp import CanFrame, IsoTpReassembler, IsoTpSender
from src.hotpatch_uds.protocol import NRC_INCORRECT_MESSAGE_LENGTH, UDSResponse


class FuzzishTests(unittest.TestCase):
    def test_malformed_write_payload_returns_length_error(self) -> None:
        ecu = PatchedECU()

        response = UDSResponse.from_payload(ecu.handle_payload(b"\x2E\x12"))

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)

    def test_empty_payload_returns_length_error(self) -> None:
        ecu = PatchedECU()

        response = UDSResponse.from_payload(ecu.handle_payload(b""))

        self.assertFalse(response.positive)
        self.assertEqual(response.nrc, NRC_INCORRECT_MESSAGE_LENGTH)

    def test_unexpected_isotp_sequence_number_raises(self) -> None:
        payload = b"\x2E\x12\x34\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        sender = IsoTpSender(arbitration_id=0x7E0, payload=payload)
        receiver = IsoTpReassembler(tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0)

        first_result = receiver.accept(sender.initial_frame())
        self.assertIsNotNone(first_result.flow_control_frame)

        malformed_cf = CanFrame(
            arbitration_id=0x7E0,
            data=bytes([0x25]) + b"\x01\x02\x03\x04\x05\x06\x07",
        )

        with self.assertRaises(ValueError):
            receiver.accept(malformed_cf)


if __name__ == "__main__":
    unittest.main()
