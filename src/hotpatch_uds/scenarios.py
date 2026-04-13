"""场景脚本。

- 这个文件把 client/server/transport 组合成 thesis 需要的实验场景。
- 每个场景都输出易读的结果，方便从命令行看行为差异。
"""

from __future__ import annotations

from .bus import InMemoryCanBus
from .client import UdsClient
from .ecu import PatchableECU, PatchedECU, VALID_WRITE_DID, VulnerableECU
from .protocol import UDSResponse
from .server import MockEcuServer
from .transport import EndpointConfig, InMemoryIsoTpConnection


def format_response(label: str, response: UDSResponse) -> str:
    """把响应对象打印成便于 thesis 记录的字符串"""
    if response.positive:
        return f"{label}: POSITIVE sid=0x{response.sid:02X} data={response.data.hex() or '-'}"
    return (
        f"{label}: NEGATIVE sid=0x{response.sid:02X} "
        f"orig=0x{response.original_sid:02X} nrc=0x{response.nrc:02X}"
    )


def build_default_client_and_server(server: MockEcuServer) -> UdsClient:
    """建立默认的 tester 与 target ECU 通道"""
    bus = InMemoryCanBus()
    connection = InMemoryIsoTpConnection(
        bus=bus,
        client=EndpointConfig(name="tester", tx_arbitration_id=0x7E0, rx_arbitration_id=0x7E8),
        server=EndpointConfig(name="ecu", tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0),
    )
    return UdsClient(connection=connection, server_handler=server.handle_payload)


def derive_key_from_seed(seed_response: UDSResponse) -> bytes:
    """根据 mock ECU 的 seed 计算 key"""
    seed = seed_response.data[1:]
    seed_value = int.from_bytes(seed, "big")
    return (seed_value ^ 0xA55A).to_bytes(2, "big")


def run_attack_without_unlock(server: MockEcuServer, write_payload: bytes = b"\x01") -> list[str]:
    """先切 session，再直接写 DID，不走 unlock"""
    client = build_default_client_and_server(server)
    lines: list[str] = []

    session_result = client.change_to_extended_session()
    lines.append(format_response("session", session_result.response))

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_without_unlock", write_result.response))
    return lines


def run_attack_with_unlock(server: MockEcuServer, write_payload: bytes = b"\x02") -> list[str]:
    """完整走 0x10 -> 0x27 -> 0x2E"""
    client = build_default_client_and_server(server)
    lines: list[str] = []

    session_result = client.change_to_extended_session()
    lines.append(format_response("session", session_result.response))

    seed_result = client.request_seed()
    lines.append(format_response("request_seed", seed_result.response))

    key = derive_key_from_seed(seed_result.response)
    key_result = client.send_key(key)
    lines.append(format_response("send_key", key_result.response))

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_unlock", write_result.response))
    return lines


def run_runtime_patch_demo(write_payload: bytes = b"\x03") -> list[str]:
    """演示运行时打补丁前后行为变化"""
    patchable = MockEcuServer(PatchableECU())
    client = build_default_client_and_server(patchable)
    lines: list[str] = []

    session_result = client.change_to_extended_session()
    lines.append(format_response("session_before_patch", session_result.response))

    before_patch = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_before_patch", before_patch.response))

    patchable.apply_patch()
    lines.append(f"patch_applied: mode={patchable.mode_name()}")

    after_patch = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_patch", after_patch.response))
    return lines


def build_reference_servers() -> tuple[MockEcuServer, MockEcuServer]:
    """为 main 和测试提供标准 server"""
    return MockEcuServer(VulnerableECU()), MockEcuServer(PatchedECU())
