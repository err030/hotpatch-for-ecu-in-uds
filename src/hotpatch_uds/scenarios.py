"""场景脚本。

- 这个文件把 client/server/transport 组合成 thesis 需要的实验场景。
- 每个场景都输出易读的结果，方便从命令行看行为差异。
- 当前重点是 gateway-routed diagnostics、0x10 -> 0x27 -> 0x2E
  攻击链，以及 hotpatch 前后的行为差异。
"""

from __future__ import annotations

from .bus import InMemoryCanBus
from .client import UdsClient
from .ecu import (
    PatchableECU,
    PatchedECU,
    ReplayWriteVulnerableECU,
    StickyUnlockAfterFailedKeyECU,
    StickyUnlockAfterSessionChangeECU,
    VALID_WRITE_DID,
    VulnerableECU,
)
from .gateway import GATEWAY_MODE_MISCONFIGURED, GatewayRoute, RoutedDiagnosticGateway
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


def build_direct_client_and_server(server: MockEcuServer) -> UdsClient:
    """建立不经过 gateway 的直接 tester 与 target ECU 通道。"""
    bus = InMemoryCanBus()
    connection = InMemoryIsoTpConnection(
        bus=bus,
        client=EndpointConfig(name="tester", tx_arbitration_id=0x7E0, rx_arbitration_id=0x7E8),
        server=EndpointConfig(name="ecu", tx_arbitration_id=0x7E8, rx_arbitration_id=0x7E0),
    )
    return UdsClient(connection=connection, server_handler=server.handle_payload)


def build_gateway_routed_client_and_server(
    server: MockEcuServer,
    gateway_mode: str = GATEWAY_MODE_MISCONFIGURED,
) -> UdsClient:
    """建立 tester -> gateway -> target ECU 的 routed diagnostics 通道。"""
    bus = InMemoryCanBus()
    route = GatewayRoute()
    gateway = RoutedDiagnosticGateway(bus=bus, route=route, mode=gateway_mode)
    connection = InMemoryIsoTpConnection(
        bus=bus,
        client=EndpointConfig(
            name="tester",
            tx_arbitration_id=route.external_request_id,
            rx_arbitration_id=route.external_response_id,
        ),
        server=EndpointConfig(
            name="ecu",
            tx_arbitration_id=route.internal_response_id,
            rx_arbitration_id=route.internal_request_id,
        ),
        gateway=gateway,
    )
    return UdsClient(connection=connection, server_handler=server.handle_payload)


def build_default_client_and_server(server: MockEcuServer) -> UdsClient:
    """默认用 gateway-routed 模式，更贴近 thesis 目标场景。"""
    return build_gateway_routed_client_and_server(server)


def derive_key_from_seed(seed_response: UDSResponse) -> bytes:
    """根据 mock ECU 的 seed 计算 key"""
    seed = seed_response.data[1:]
    seed_value = int.from_bytes(seed, "big")
    return (seed_value ^ 0xA55A).to_bytes(2, "big")


def format_runtime_state(server: MockEcuServer) -> str:
    state = server.ecu.describe_runtime_state()
    return (
        "state: "
        f"session=0x{int(state['session']):02X} "
        f"phase={state['security_phase']} "
        f"unlocked={state['security_unlocked']} "
        f"failed_attempts={state['failed_attempts']} "
        f"lockout={state['lockout_ticks_remaining']} "
        f"periodic_tick={state['periodic_task_tick']}"
    )


def run_attack_without_unlock(
    server: MockEcuServer,
    write_payload: bytes = b"\x01",
    gateway_mode: str = GATEWAY_MODE_MISCONFIGURED,
) -> list[str]:
    """先切 session，再直接写 DID，不走 unlock。"""
    client = build_gateway_routed_client_and_server(server, gateway_mode=gateway_mode)
    lines: list[str] = []

    session_result = client.change_to_extended_session()
    lines.append(format_response("session", session_result.response))

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_without_unlock", write_result.response))
    lines.append(format_runtime_state(server))
    return lines


def run_attack_with_unlock(
    server: MockEcuServer,
    write_payload: bytes = b"\x02",
    gateway_mode: str = GATEWAY_MODE_MISCONFIGURED,
) -> list[str]:
    """完整走 0x10 -> 0x27 -> 0x2E。"""
    client = build_gateway_routed_client_and_server(server, gateway_mode=gateway_mode)
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
    lines.append(format_runtime_state(server))
    return lines


def run_failed_key_state_retention_attack(write_payload: bytes = b"\x04") -> list[str]:
    """演示错误 key 后旧 unlock 状态未清除的问题。"""
    server = MockEcuServer(StickyUnlockAfterFailedKeyECU())
    client = build_gateway_routed_client_and_server(server)
    lines: list[str] = []

    client.change_to_extended_session()
    seed_result = client.request_seed()
    key = derive_key_from_seed(seed_result.response)
    client.send_key(key)

    seed_result_again = client.request_seed()
    lines.append(format_response("request_seed_again", seed_result_again.response))
    wrong_key_result = client.send_key(b"\x00\x00")
    lines.append(format_response("wrong_key_after_unlock", wrong_key_result.response))

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_failed_key", write_result.response))
    lines.append(format_runtime_state(server))
    return lines


def run_session_change_state_retention_attack(write_payload: bytes = b"\x05") -> list[str]:
    """演示 session 切换后旧 unlock 状态仍保留的问题。"""
    server = MockEcuServer(StickyUnlockAfterSessionChangeECU())
    client = build_gateway_routed_client_and_server(server)
    lines: list[str] = []

    client.change_to_extended_session()
    seed_result = client.request_seed()
    key = derive_key_from_seed(seed_result.response)
    client.send_key(key)
    client.change_to_default_session()
    client.change_to_extended_session()

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_session_reentry", write_result.response))
    lines.append(format_runtime_state(server))
    return lines


def run_replay_attack(write_payload: bytes = b"\x06") -> list[str]:
    """演示旧授权写请求被重放的问题。"""
    server = MockEcuServer(ReplayWriteVulnerableECU())
    client = build_gateway_routed_client_and_server(server)
    lines: list[str] = []

    client.change_to_extended_session()
    seed_result = client.request_seed()
    key = derive_key_from_seed(seed_result.response)
    client.send_key(key)
    first_write = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("authorized_write", first_write.response))

    client.change_to_default_session()
    client.change_to_extended_session()
    replay_write = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("replay_write_without_new_unlock", replay_write.response))
    lines.append(format_runtime_state(server))
    return lines


def run_runtime_patch_demo(write_payload: bytes = b"\x03") -> list[str]:
    """演示运行时打补丁前后行为变化和 patch 生命周期。"""
    patchable = MockEcuServer(PatchableECU())
    client = build_gateway_routed_client_and_server(patchable)
    lines: list[str] = []

    session_result = client.change_to_extended_session()
    lines.append(format_response("session_before_patch", session_result.response))

    before_patch = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_before_patch", before_patch.response))

    patchable.start_patch_loading()
    lines.append(f"patch_state: {patchable.mode_name()}")
    patchable.activate_patch()
    lines.append(
        f"patch_state: {patchable.mode_name()} "
        f"steps_to_protection={patchable.patch_steps_to_protection}"
    )

    after_patch = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_patch", after_patch.response))
    lines.append(format_runtime_state(patchable))
    return lines


def run_patch_failure_demo(write_payload: bytes = b"\x07") -> list[str]:
    """演示 patch 失败后 ECU 仍保持漏洞行为。"""
    patchable = MockEcuServer(PatchableECU())
    client = build_gateway_routed_client_and_server(patchable)
    lines: list[str] = []

    client.change_to_extended_session()
    patchable.start_patch_loading()
    lines.append(f"patch_state: {patchable.mode_name()}")
    patchable.fail_patch()
    lines.append(f"patch_state: {patchable.mode_name()}")

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_failed_patch", write_result.response))
    lines.append(format_runtime_state(patchable))
    return lines


def run_patch_rollback_demo(write_payload: bytes = b"\x08") -> list[str]:
    """演示补丁激活后又回滚，漏洞行为重新出现。"""
    patchable = MockEcuServer(PatchableECU())
    client = build_gateway_routed_client_and_server(patchable)
    lines: list[str] = []

    client.change_to_extended_session()
    patchable.start_patch_loading()
    patchable.activate_patch()
    lines.append(f"patch_state: {patchable.mode_name()}")
    patchable.rollback_patch()
    lines.append(f"patch_state: {patchable.mode_name()}")

    write_result = client.write_data_by_identifier(VALID_WRITE_DID, write_payload)
    lines.append(format_response("write_after_rollback", write_result.response))
    lines.append(format_runtime_state(patchable))
    return lines


def build_reference_servers() -> tuple[MockEcuServer, MockEcuServer]:
    """为 main 和测试提供标准 server"""
    return MockEcuServer(VulnerableECU()), MockEcuServer(PatchedECU())
