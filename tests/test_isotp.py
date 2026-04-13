"""中文说明：
- 这个测试文件验证简化 ISO-TP 分帧和重组逻辑。
"""

import unittest

from src.hotpatch_uds_sim.isotp import IsoTpReassembler, IsoTpSender


class IsoTpTests(unittest.TestCase):
    def test_single_frame_roundtrip(self) -> None:
        sender = IsoTpSender(arbitration_id=0x7E0, payload=b"\x10\x03")
        receiver = IsoTpReassembler(tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0)

        result = receiver.accept(sender.initial_frame())
        self.assertEqual(result.complete_payload, b"\x10\x03")

    def test_multi_frame_roundtrip(self) -> None:
        payload = b"\x2E\x12\x34\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        sender = IsoTpSender(arbitration_id=0x7E0, payload=payload)
        receiver = IsoTpReassembler(tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0)

        first_result = receiver.accept(sender.initial_frame())
        self.assertIsNotNone(first_result.flow_control_frame)
        self.assertIsNone(first_result.complete_payload)

        complete_payload = None
        for frame in sender.consecutive_frames():
            result = receiver.accept(frame)
            if result.complete_payload is not None:
                complete_payload = result.complete_payload

        self.assertEqual(complete_payload, payload)


if __name__ == "__main__":
    unittest.main()
