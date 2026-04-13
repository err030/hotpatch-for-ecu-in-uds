"""中文说明：
- 这个测试文件验证 UDS 报文编解码是否正确。
"""

import unittest

from src.hotpatch_uds_sim.protocol import (
    NEGATIVE_RESPONSE_SID,
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_WRITE_DATA_BY_IDENTIFIER,
    UDSRequest,
    UDSResponse,
    negative_response,
)


class ProtocolTests(unittest.TestCase):
    def test_encode_session_control_request(self) -> None:
        request = UDSRequest(sid=SID_DIAGNOSTIC_SESSION_CONTROL, subfunction=0x03)
        self.assertEqual(request.to_payload(), b"\x10\x03")

    def test_decode_write_request(self) -> None:
        request = UDSRequest.from_payload(b"\x2E\x12\x34\xAA\xBB")
        self.assertEqual(request.sid, SID_WRITE_DATA_BY_IDENTIFIER)
        self.assertEqual(request.did, 0x1234)
        self.assertEqual(request.data, b"\xAA\xBB")

    def test_negative_response_roundtrip(self) -> None:
        response = negative_response(0x2E, 0x33)
        payload = response.to_payload()
        parsed = UDSResponse.from_payload(payload)

        self.assertEqual(payload, bytes([NEGATIVE_RESPONSE_SID, 0x2E, 0x33]))
        self.assertFalse(parsed.positive)
        self.assertEqual(parsed.original_sid, 0x2E)
        self.assertEqual(parsed.nrc, 0x33)


if __name__ == "__main__":
    unittest.main()
