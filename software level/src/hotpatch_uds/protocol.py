"""UDS 报文对象与基础编解码。

- 这个文件负责“标准 UDS 语义”这一层。
- 它定义了 request/response 数据结构。
- 它把常用服务编码成字节串，也把字节串解析回对象。

参考来源：
- python-udsoncan 仓库: https://github.com/pylessard/python-udsoncan
- udsoncan 文档: https://udsoncan.readthedocs.io/en/latest/
"""

from __future__ import annotations

from dataclasses import dataclass, field


SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_SECURITY_ACCESS = 0x27
SID_WRITE_DATA_BY_IDENTIFIER = 0x2E
NEGATIVE_RESPONSE_SID = 0x7F

SESSION_DEFAULT = 0x01
SESSION_EXTENDED = 0x03

NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_MESSAGE_LENGTH = 0x13
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33


@dataclass
class UDSRequest:
    """抽象后的 UDS 请求对象"""

    sid: int
    subfunction: int | None = None
    did: int | None = None
    data: bytes = field(default_factory=bytes)

    def to_payload(self) -> bytes:
        """把请求对象编码成 UDS payload"""
        if self.sid == SID_DIAGNOSTIC_SESSION_CONTROL:
            if self.subfunction is None:
                raise ValueError("DiagnosticSessionControl requires a subfunction")
            return bytes([self.sid, self.subfunction])

        if self.sid == SID_SECURITY_ACCESS:
            if self.subfunction is None:
                raise ValueError("SecurityAccess requires a subfunction")
            return bytes([self.sid, self.subfunction]) + self.data

        if self.sid == SID_WRITE_DATA_BY_IDENTIFIER:
            if self.did is None:
                raise ValueError("WriteDataByIdentifier requires a DID")
            return bytes([self.sid]) + self.did.to_bytes(2, "big") + self.data

        return bytes([self.sid]) + self.data

    @classmethod
    def from_payload(cls, payload: bytes) -> "UDSRequest":
        """把 payload 解析成请求对象"""
        if not payload:
            raise ValueError("Empty UDS request payload")

        sid = payload[0]

        if sid == SID_DIAGNOSTIC_SESSION_CONTROL:
            if len(payload) != 2:
                raise ValueError("DiagnosticSessionControl payload must be 2 bytes")
            return cls(sid=sid, subfunction=payload[1])

        if sid == SID_SECURITY_ACCESS:
            if len(payload) < 2:
                raise ValueError("SecurityAccess payload must be at least 2 bytes")
            return cls(sid=sid, subfunction=payload[1], data=payload[2:])

        if sid == SID_WRITE_DATA_BY_IDENTIFIER:
            if len(payload) < 3:
                raise ValueError("WriteDataByIdentifier payload must be at least 3 bytes")
            did = int.from_bytes(payload[1:3], "big")
            return cls(sid=sid, did=did, data=payload[3:])

        return cls(sid=sid, data=payload[1:])


@dataclass
class UDSResponse:
    """抽象后的 UDS 响应对象"""

    positive: bool
    sid: int
    data: bytes = field(default_factory=bytes)
    nrc: int | None = None
    original_sid: int | None = None

    def to_payload(self) -> bytes:
        """把响应对象编码成 UDS payload"""
        if self.positive:
            return bytes([self.sid]) + self.data

        if self.original_sid is None or self.nrc is None:
            raise ValueError("Negative response requires original_sid and nrc")
        return bytes([NEGATIVE_RESPONSE_SID, self.original_sid, self.nrc])

    @classmethod
    def from_payload(cls, payload: bytes) -> "UDSResponse":
        """把 payload 解析成响应对象"""
        if not payload:
            raise ValueError("Empty UDS response payload")

        sid = payload[0]
        if sid == NEGATIVE_RESPONSE_SID:
            if len(payload) != 3:
                raise ValueError("Negative response payload must be 3 bytes")
            return cls(
                positive=False,
                sid=sid,
                nrc=payload[2],
                original_sid=payload[1],
                data=payload[1:],
            )

        return cls(positive=True, sid=sid, data=payload[1:])


def positive_response_sid(request_sid: int) -> int:
    """标准 UDS 正响应 SID = 请求 SID + 0x40"""
    return request_sid + 0x40


def positive_response(request_sid: int, data: bytes = b"") -> UDSResponse:
    """根据请求 SID 生成正响应对象"""
    return UDSResponse(positive=True, sid=positive_response_sid(request_sid), data=data)


def negative_response(request_sid: int, nrc: int) -> UDSResponse:
    """生成负响应对象"""
    return UDSResponse(
        positive=False,
        sid=NEGATIVE_RESPONSE_SID,
        data=bytes([request_sid, nrc]),
        nrc=nrc,
        original_sid=request_sid,
    )
