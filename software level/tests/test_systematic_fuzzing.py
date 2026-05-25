"""中文说明：
- 这个测试文件验证系统化 fuzzing corpus 可以被稳定运行。
"""

import unittest

from src.hotpatch_uds.differential import compare_case_across_backends
from src.hotpatch_uds.ecu import PatchedECU
from src.hotpatch_uds.fuzzing import (
    build_isotp_frame_corpus,
    build_protocol_payload_corpus,
    build_state_sequence_corpus,
)
from src.hotpatch_uds.isotp import CanFrame, IsoTpReassembler, IsoTpSender
from src.hotpatch_uds.protocol import UDSResponse


class SystematicFuzzingTests(unittest.TestCase):
    def test_protocol_payload_corpus_runs_without_crashing(self) -> None:
        ecu = PatchedECU()
        corpus = build_protocol_payload_corpus()

        self.assertGreaterEqual(len(corpus), 10)
        for case in corpus:
            response_payload = ecu.handle_payload(case.payload)
            response = UDSResponse.from_payload(response_payload)
            self.assertIsNotNone(response.sid)

    def test_state_sequence_corpus_runs_on_differential_harness(self) -> None:
        corpus = build_state_sequence_corpus()

        for case in corpus:
            comparison = compare_case_across_backends(case)
            self.assertTrue(comparison.matched)

    def test_isotp_corpus_detects_invalid_sequence_numbers(self) -> None:
        corpus = build_isotp_frame_corpus()

        for case in corpus:
            sender = IsoTpSender(arbitration_id=0x7E0, payload=case.first_frame_payload)
            receiver = IsoTpReassembler(tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0)
            first_result = receiver.accept(sender.initial_frame())
            self.assertIsNotNone(first_result.flow_control_frame)

            for seq_number in case.malformed_sequence_numbers:
                malformed_cf = CanFrame(
                    arbitration_id=0x7E0,
                    data=bytes([0x20 | (seq_number & 0x0F)]) + b"\x01\x02\x03\x04\x05\x06\x07",
                )
                with self.assertRaises(ValueError):
                    receiver.accept(malformed_cf)


if __name__ == "__main__":
    unittest.main()
