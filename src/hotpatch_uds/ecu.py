"""Mock ECU 状态机。

- 这个文件模拟 ECU 这一侧的 UDS 服务逻辑。
- 它维护 session、安全访问状态和 DID 写入结果。
- 它同时提供 vulnerable / patched 两种行为。

这里的 hotpatch 简化为：
- 初始模式不强制检查 security unlock
- apply_patch() 之后强制检查 security unlock

这样能直接展示 runtime 行为切换。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .protocol import (
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_SECURITY_ACCESS_DENIED,
    NRC_SUBFUNCTION_NOT_SUPPORTED,
    SESSION_DEFAULT,
    SESSION_EXTENDED,
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_SECURITY_ACCESS,
    SID_WRITE_DATA_BY_IDENTIFIER,
    UDSRequest,
    UDSResponse,
    negative_response,
    positive_response,
)


VALID_WRITE_DID = 0x1234
SEED_MASK = 0xA55A


@dataclass
class ECUState:
    """ECU 运行状态。"""

    session: int = SESSION_DEFAULT
    security_unlocked: bool = False
    writes: dict[int, bytes] = field(default_factory=dict)
    pending_seed: bytes | None = None
    seed_counter: int = 0


class BaseECU:
    """ECU 基类，定义公共状态和公共服务"""

    def __init__(self, write_requires_unlock: bool) -> None:
        self.state = ECUState()
        self.write_requires_unlock = write_requires_unlock

    def mode_name(self) -> str:
        return "patched" if self.write_requires_unlock else "vulnerable"

    def apply_patch(self) -> None:
        """模拟运行时打补丁，把写入路径切到严格检查模式"""
        self.write_requires_unlock = True

    def handle(self, request: UDSRequest) -> UDSResponse:
        if request.sid == SID_DIAGNOSTIC_SESSION_CONTROL:
            return self._handle_session_control(request)
        if request.sid == SID_SECURITY_ACCESS:
            return self._handle_security_access(request)
        if request.sid == SID_WRITE_DATA_BY_IDENTIFIER:
            return self._handle_write_data_by_identifier(request)
        return negative_response(request.sid, NRC_REQUEST_OUT_OF_RANGE)

    def handle_payload(self, request_payload: bytes) -> bytes:
        """server 入口，直接处理字节 payload"""
        try:
            request = UDSRequest.from_payload(request_payload)
        except ValueError:
            response = negative_response(
                request_payload[0] if request_payload else 0x00,
                NRC_INCORRECT_MESSAGE_LENGTH,
            )
            return response.to_payload()
        return self.handle(request).to_payload()

    def _handle_session_control(self, request: UDSRequest) -> UDSResponse:
        if request.subfunction != SESSION_EXTENDED:
            return negative_response(request.sid, NRC_SUBFUNCTION_NOT_SUPPORTED)
        self.state.session = SESSION_EXTENDED
        self.state.security_unlocked = False
        self.state.pending_seed = None
        return positive_response(request.sid, bytes([SESSION_EXTENDED]))

    def _handle_security_access(self, request: UDSRequest) -> UDSResponse:
        if request.subfunction == 0x01:
            if self.state.session != SESSION_EXTENDED:
                return negative_response(request.sid, NRC_CONDITIONS_NOT_CORRECT)

            self.state.seed_counter += 1
            seed_value = 0x1200 + self.state.seed_counter
            self.state.pending_seed = seed_value.to_bytes(2, "big")
            return positive_response(request.sid, bytes([0x01]) + self.state.pending_seed)

        if request.subfunction == 0x02:
            if self.state.session != SESSION_EXTENDED:
                return negative_response(request.sid, NRC_CONDITIONS_NOT_CORRECT)
            if self.state.pending_seed is None:
                return negative_response(request.sid, NRC_REQUEST_SEQUENCE_ERROR)
            if request.data != self._expected_key_from_seed(self.state.pending_seed):
                self.state.security_unlocked = False
                return negative_response(request.sid, NRC_SECURITY_ACCESS_DENIED)

            self.state.security_unlocked = True
            self.state.pending_seed = None
            return positive_response(request.sid, bytes([0x02]))

        return negative_response(request.sid, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def _handle_write_data_by_identifier(self, request: UDSRequest) -> UDSResponse:
        if request.did != VALID_WRITE_DID:
            return negative_response(request.sid, NRC_REQUEST_OUT_OF_RANGE)
        if self.state.session != SESSION_EXTENDED:
            return negative_response(request.sid, NRC_CONDITIONS_NOT_CORRECT)
        if self.write_requires_unlock and not self.state.security_unlocked:
            return negative_response(request.sid, NRC_SECURITY_ACCESS_DENIED)

        self.state.writes[request.did] = request.data
        return positive_response(request.sid, request.did.to_bytes(2, "big"))

    @staticmethod
    def _expected_key_from_seed(seed: bytes) -> bytes:
        """这里用一个简单可解释的映射来模拟 seed/key"""
        value = int.from_bytes(seed, "big") ^ SEED_MASK
        return value.to_bytes(2, "big")


class VulnerableECU(BaseECU):
    """漏洞版本，写路径不要求 unlock"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=False)


class PatchedECU(BaseECU):
    """补丁版本，写路径必须 unlock"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=True)


class PatchableECU(BaseECU):
    """可在运行时从 vulnerable 切到 patched"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=False)
