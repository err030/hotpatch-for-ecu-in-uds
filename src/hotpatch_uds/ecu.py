"""Mock ECU 状态机。

- 这个文件模拟 ECU 这一侧的 UDS 服务逻辑。
- 它维护 session、安全访问状态、失败计数、锁定时间和 DID 写入结果。
- 它同时提供 vulnerable / patched 以及多种安全缺陷变体，方便 thesis 做攻击组。

这里的 hotpatch 简化为：
- 初始模式允许局部状态/授权检查缺陷存在
- apply_patch() 之后恢复到严格检查模式

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
    failed_attempts: int = 0
    lockout_ticks_remaining: int = 0
    periodic_task_tick: int = 0
    last_authorized_write: tuple[int, bytes] | None = None

    def security_phase(self) -> str:
        if self.lockout_ticks_remaining > 0:
            return "locked_out"
        if self.security_unlocked:
            return "unlocked"
        if self.pending_seed is not None:
            return "seed_issued"
        if self.session == SESSION_EXTENDED:
            return "extended_session"
        return "default_session"


class BaseECU:
    """ECU 基类，定义公共状态和公共服务"""

    def __init__(
        self,
        write_requires_unlock: bool,
        clear_unlock_on_failed_key: bool = True,
        clear_unlock_on_session_change: bool = True,
        allow_replay_without_unlock: bool = False,
        max_failed_attempts: int = 2,
        lockout_duration_ticks: int = 3,
    ) -> None:
        self.state = ECUState()
        self.write_requires_unlock = write_requires_unlock
        self.clear_unlock_on_failed_key = clear_unlock_on_failed_key
        self.clear_unlock_on_session_change = clear_unlock_on_session_change
        self.allow_replay_without_unlock = allow_replay_without_unlock
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration_ticks = lockout_duration_ticks
        self._initial_policy = self._capture_policy()

    def mode_name(self) -> str:
        if self.is_fully_patched():
            return "patched"
        return "vulnerable"

    def apply_patch(self) -> None:
        """模拟运行时打补丁，把本地策略切到严格检查模式。"""
        self.write_requires_unlock = True
        self.clear_unlock_on_failed_key = True
        self.clear_unlock_on_session_change = True
        self.allow_replay_without_unlock = False

    def rollback_patch(self) -> None:
        """把策略恢复到补丁前配置，模拟回滚。"""
        self._restore_policy(self._initial_policy)

    def tick(self) -> None:
        """模拟一个本地周期任务 tick，同时推进锁定计时。"""
        self.state.periodic_task_tick += 1
        if self.state.lockout_ticks_remaining > 0:
            self.state.lockout_ticks_remaining -= 1

    def handle(self, request: UDSRequest) -> UDSResponse:
        self.tick()
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
        if request.subfunction not in {SESSION_DEFAULT, SESSION_EXTENDED}:
            return negative_response(request.sid, NRC_SUBFUNCTION_NOT_SUPPORTED)
        self.state.session = request.subfunction
        if self.clear_unlock_on_session_change:
            self.state.security_unlocked = False
        self.state.pending_seed = None
        return positive_response(request.sid, bytes([request.subfunction]))

    def _handle_security_access(self, request: UDSRequest) -> UDSResponse:
        if self.state.lockout_ticks_remaining > 0:
            return negative_response(request.sid, NRC_SECURITY_ACCESS_DENIED)

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
                if self.clear_unlock_on_failed_key:
                    self.state.security_unlocked = False
                self.state.failed_attempts += 1
                self.state.pending_seed = None
                if self.state.failed_attempts >= self.max_failed_attempts:
                    self.state.lockout_ticks_remaining = self.lockout_duration_ticks
                return negative_response(request.sid, NRC_SECURITY_ACCESS_DENIED)

            self.state.security_unlocked = True
            self.state.failed_attempts = 0
            self.state.pending_seed = None
            return positive_response(request.sid, bytes([0x02]))

        return negative_response(request.sid, NRC_SUBFUNCTION_NOT_SUPPORTED)

    def _handle_write_data_by_identifier(self, request: UDSRequest) -> UDSResponse:
        if request.did != VALID_WRITE_DID:
            return negative_response(request.sid, NRC_REQUEST_OUT_OF_RANGE)
        if self.state.session != SESSION_EXTENDED:
            return negative_response(request.sid, NRC_CONDITIONS_NOT_CORRECT)
        if self.write_requires_unlock and not self.state.security_unlocked:
            if self._allow_replay(request):
                self.state.writes[request.did] = request.data
                return positive_response(request.sid, request.did.to_bytes(2, "big"))
            return negative_response(request.sid, NRC_SECURITY_ACCESS_DENIED)

        self.state.writes[request.did] = request.data
        if self.state.security_unlocked:
            self.state.last_authorized_write = (request.did, request.data)
        return positive_response(request.sid, request.did.to_bytes(2, "big"))

    @staticmethod
    def _expected_key_from_seed(seed: bytes) -> bytes:
        """这里用一个简单可解释的映射来模拟 seed/key"""
        value = int.from_bytes(seed, "big") ^ SEED_MASK
        return value.to_bytes(2, "big")

    def _allow_replay(self, request: UDSRequest) -> bool:
        return self.allow_replay_without_unlock and self.state.last_authorized_write == (
            request.did,
            request.data,
        )

    def describe_runtime_state(self) -> dict[str, int | bool | str]:
        """给测试和场景导出当前状态。"""
        return {
            "session": self.state.session,
            "security_unlocked": self.state.security_unlocked,
            "failed_attempts": self.state.failed_attempts,
            "lockout_ticks_remaining": self.state.lockout_ticks_remaining,
            "periodic_task_tick": self.state.periodic_task_tick,
            "security_phase": self.state.security_phase(),
        }

    def is_fully_patched(self) -> bool:
        return (
            self.write_requires_unlock
            and self.clear_unlock_on_failed_key
            and self.clear_unlock_on_session_change
            and not self.allow_replay_without_unlock
        )

    def _capture_policy(self) -> dict[str, int | bool]:
        return {
            "write_requires_unlock": self.write_requires_unlock,
            "clear_unlock_on_failed_key": self.clear_unlock_on_failed_key,
            "clear_unlock_on_session_change": self.clear_unlock_on_session_change,
            "allow_replay_without_unlock": self.allow_replay_without_unlock,
            "max_failed_attempts": self.max_failed_attempts,
            "lockout_duration_ticks": self.lockout_duration_ticks,
        }

    def _restore_policy(self, policy: dict[str, int | bool]) -> None:
        self.write_requires_unlock = bool(policy["write_requires_unlock"])
        self.clear_unlock_on_failed_key = bool(policy["clear_unlock_on_failed_key"])
        self.clear_unlock_on_session_change = bool(policy["clear_unlock_on_session_change"])
        self.allow_replay_without_unlock = bool(policy["allow_replay_without_unlock"])
        self.max_failed_attempts = int(policy["max_failed_attempts"])
        self.lockout_duration_ticks = int(policy["lockout_duration_ticks"])


class VulnerableECU(BaseECU):
    """漏洞版本，写路径不要求 unlock"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=False)


class PatchedECU(BaseECU):
    """补丁版本，写路径必须 unlock"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=True)


class PatchableECU(BaseECU):
    """可在运行时从 vulnerable 切到 patched。"""

    def __init__(self) -> None:
        super().__init__(write_requires_unlock=False)


class StickyUnlockAfterFailedKeyECU(BaseECU):
    """错误 key 后未清除旧 unlock 状态的漏洞版本。"""

    def __init__(self) -> None:
        super().__init__(
            write_requires_unlock=True,
            clear_unlock_on_failed_key=False,
        )


class StickyUnlockAfterSessionChangeECU(BaseECU):
    """session 切换后仍保留旧 unlock 状态的漏洞版本。"""

    def __init__(self) -> None:
        super().__init__(
            write_requires_unlock=True,
            clear_unlock_on_session_change=False,
        )


class ReplayWriteVulnerableECU(BaseECU):
    """允许重放旧授权写请求的漏洞版本。"""

    def __init__(self) -> None:
        super().__init__(
            write_requires_unlock=True,
            allow_replay_without_unlock=True,
        )
