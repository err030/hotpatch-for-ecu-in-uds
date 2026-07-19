"""Differential testing harness.

- 这个文件用于做差分测试。
- 当前环境里没有安装 `python-can / can-isotp / udsoncan`，所以当前差分测试先比较
  两种本地后端：`direct` 和 `gateway-routed`。
- 这样可以先验证：同一组 UDS 语义请求，在不同 transport / routing 结构下是否得到一致结果。
- 后续一旦安装真实框架，可以把新的 backend adapter 接进来，而不需要重写整个测试框架。
"""

from __future__ import annotations

from dataclasses import dataclass
import csv
from io import StringIO

from .client import UdsClient
from .ecu import PatchedECU
from .frameworks import missing_framework_names, probe_socketcan_status
from .gateway import GATEWAY_MODE_MISCONFIGURED
from .scenarios import (
    build_direct_client_and_server,
    build_gateway_routed_client_and_server,
    build_python_can_socketcan_gateway_routed_client_and_server,
    build_python_can_virtual_gateway_routed_client_and_server,
    derive_key_from_seed,
)
from .server import MockEcuServer


@dataclass(frozen=True)
class DifferentialOperation:
    """差分测试里的一个语义操作。"""

    kind: str
    did: int | None = None
    data: bytes = b""


@dataclass(frozen=True)
class DifferentialCase:
    """一组需要在多个 backend 上重复执行的操作。"""

    name: str
    operations: tuple[DifferentialOperation, ...]


@dataclass(frozen=True)
class NormalizedResponse:
    """归一化后的响应，便于 backend 间比较。"""

    positive: bool
    sid: int
    original_sid: int | None
    nrc: int | None
    data_hex: str


@dataclass(frozen=True)
class DifferentialObservation:
    """一个 backend 对一个 case 的执行结果。"""

    backend_name: str
    case_name: str
    responses: tuple[NormalizedResponse, ...]


@dataclass(frozen=True)
class DifferentialComparison:
    """多个 backend 的差分比较结果。"""

    case_name: str
    backend_names: tuple[str, ...]
    matched: bool
    observations: tuple[DifferentialObservation, ...]


class LocalBackendAdapter:
    """本地 backend adapter。"""

    def __init__(self, name: str, *, routed: bool) -> None:
        self.name = name
        self.routed = routed

    def build_client(self) -> UdsClient:
        server = MockEcuServer(PatchedECU())
        if self.routed:
            return build_gateway_routed_client_and_server(
                server,
                gateway_mode=GATEWAY_MODE_MISCONFIGURED,
            )
        return build_direct_client_and_server(server)

    def run_case(self, case: DifferentialCase) -> DifferentialObservation:
        return run_case_on_client(self.name, case, self.build_client())


class OptionalRuntimeBackendAdapter:
    """可关闭 runtime 的 backend adapter。"""

    def __init__(self, name: str, builder) -> None:
        self.name = name
        self.builder = builder

    def run_case(self, case: DifferentialCase) -> DifferentialObservation:
        live = self.builder(MockEcuServer(PatchedECU()))
        try:
            return run_case_on_client(self.name, case, live.client)
        finally:
            live.close()


def run_case_on_client(
    backend_name: str,
    case: DifferentialCase,
    client: UdsClient,
) -> DifferentialObservation:
    """在一个已构造 client 上执行 case。"""
    seed_response = None
    responses: list[NormalizedResponse] = []
    for operation in case.operations:
        if operation.kind == "change_to_extended_session":
            response = client.change_to_extended_session().response
        elif operation.kind == "change_to_default_session":
            response = client.change_to_default_session().response
        elif operation.kind == "request_seed":
            response = client.request_seed().response
            if response.positive:
                seed_response = response
        elif operation.kind == "send_valid_key":
            if seed_response is None:
                raise RuntimeError("send_valid_key requires a previous positive seed response")
            response = client.send_key(derive_key_from_seed(seed_response)).response
        elif operation.kind == "send_invalid_key":
            response = client.send_key(operation.data or b"\x00\x00").response
        elif operation.kind == "write":
            if operation.did is None:
                raise ValueError("write operation requires a DID")
            response = client.write_data_by_identifier(operation.did, operation.data).response
        elif operation.kind == "read":
            if operation.did is None:
                raise ValueError("read operation requires a DID")
            response = client.read_data_by_identifier(operation.did).response
        else:
            raise ValueError(f"Unsupported differential operation: {operation.kind}")
        responses.append(normalize_response(response))
    return DifferentialObservation(
        backend_name=backend_name,
        case_name=case.name,
        responses=tuple(responses),
    )


def normalize_response(response) -> NormalizedResponse:
    """把本地 response 对象映射成稳定比较格式。"""
    return NormalizedResponse(
        positive=response.positive,
        sid=response.sid,
        original_sid=response.original_sid,
        nrc=response.nrc,
        data_hex=response.data.hex(),
    )


def default_differential_cases() -> tuple[DifferentialCase, ...]:
    """当前默认的差分测试用例。"""
    return (
        DifferentialCase(
            name="unauthorized_write",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("write", did=0x1234, data=b"\x01"),
            ),
        ),
        DifferentialCase(
            name="authorized_write",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
                DifferentialOperation("write", did=0x1234, data=b"\xAA\xBB"),
            ),
        ),
        DifferentialCase(
            name="read_after_authorized_write",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
                DifferentialOperation("write", did=0x1234, data=b"\xAA\xBB"),
                DifferentialOperation("read", did=0x1234),
            ),
        ),
        DifferentialCase(
            name="read_only_status_did",
            operations=(DifferentialOperation("read", did=0x1001),),
        ),
        DifferentialCase(
            name="sequence_error",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("send_invalid_key", data=b"\x00\x00"),
            ),
        ),
        DifferentialCase(
            name="seed_request_without_extended_session",
            operations=(DifferentialOperation("request_seed"),),
        ),
        DifferentialCase(
            name="write_out_of_range_did",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
                DifferentialOperation("write", did=0x9999, data=b"\x10"),
            ),
        ),
        DifferentialCase(
            name="write_after_session_reset",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
                DifferentialOperation("change_to_default_session"),
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("write", did=0x1234, data=b"\x33"),
            ),
        ),
        DifferentialCase(
            name="double_seed_then_valid_key",
            operations=(
                DifferentialOperation("change_to_extended_session"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("request_seed"),
                DifferentialOperation("send_valid_key"),
            ),
        ),
    )


def default_local_backends() -> tuple[LocalBackendAdapter, ...]:
    """当前默认差分测试使用的 backend 集合。"""
    return (
        LocalBackendAdapter("direct_patched_backend", routed=False),
        LocalBackendAdapter("gateway_routed_patched_backend", routed=True),
    )


def optional_stack_backends() -> tuple[OptionalRuntimeBackendAdapter, ...]:
    """如果第三方协议栈可用，则把它们加进差分比较。"""
    missing = set(missing_framework_names())
    if {"python-can", "can-isotp", "udsoncan"}.intersection(missing):
        return ()

    adapters: list[OptionalRuntimeBackendAdapter] = [
        OptionalRuntimeBackendAdapter(
            "python_can_virtual_gateway_backend",
            lambda server: build_python_can_virtual_gateway_routed_client_and_server(
                server,
                channel="diff-hotpatch-uds",
                gateway_mode=GATEWAY_MODE_MISCONFIGURED,
            ),
        )
    ]
    socketcan_status = probe_socketcan_status("vcan0")
    if socketcan_status.interface_exists:
        adapters.append(
            OptionalRuntimeBackendAdapter(
                "python_can_socketcan_gateway_backend",
                lambda server: build_python_can_socketcan_gateway_routed_client_and_server(
                    server,
                    interface="vcan0",
                    gateway_mode=GATEWAY_MODE_MISCONFIGURED,
                ),
            )
        )
    return tuple(adapters)


def compare_case_across_backends(
    case: DifferentialCase,
    backends: tuple[LocalBackendAdapter | OptionalRuntimeBackendAdapter, ...] | None = None,
) -> DifferentialComparison:
    """对单个 case 做差分比较。"""
    resolved_backends = backends or (default_local_backends() + optional_stack_backends())
    observations = tuple(backend.run_case(case) for backend in resolved_backends)
    baseline = observations[0].responses
    matched = all(observation.responses == baseline for observation in observations[1:])
    return DifferentialComparison(
        case_name=case.name,
        backend_names=tuple(observation.backend_name for observation in observations),
        matched=matched,
        observations=observations,
    )


def run_default_differential_suite() -> tuple[DifferentialComparison, ...]:
    """执行当前默认差分测试集合。"""
    return tuple(compare_case_across_backends(case) for case in default_differential_cases())


def format_differential_comparison(comparison: DifferentialComparison) -> list[str]:
    """把差分比较结果格式化成便于 thesis 记录的文本。"""
    lines = [
        f"case: {comparison.case_name}",
        f"backends: {', '.join(comparison.backend_names)}",
        f"matched: {comparison.matched}",
    ]
    for observation in comparison.observations:
        lines.append(f"backend: {observation.backend_name}")
        for index, response in enumerate(observation.responses):
            lines.append(
                "  "
                f"step={index} positive={response.positive} sid=0x{response.sid:02X} "
                f"orig={('-' if response.original_sid is None else f'0x{response.original_sid:02X}')} "
                f"nrc={('-' if response.nrc is None else f'0x{response.nrc:02X}')} "
                f"data={response.data_hex or '-'}"
            )
    return lines


def differential_summary_rows(
    comparisons: tuple[DifferentialComparison, ...] | None = None,
) -> list[dict[str, str]]:
    """把差分结果压成适合导出的摘要行。"""
    resolved = comparisons or run_default_differential_suite()
    rows: list[dict[str, str]] = []
    for comparison in resolved:
        rows.append(
            {
                "case_name": comparison.case_name,
                "backend_count": str(len(comparison.backend_names)),
                "matched": str(comparison.matched),
                "step_count": str(len(comparison.observations[0].responses)),
                "backend_names": "|".join(comparison.backend_names),
            }
        )
    return rows


def differential_detail_rows(
    comparisons: tuple[DifferentialComparison, ...] | None = None,
) -> list[dict[str, str]]:
    """把差分结果展开成逐 backend、逐 step 的细节行。"""
    resolved = comparisons or run_default_differential_suite()
    rows: list[dict[str, str]] = []
    for comparison in resolved:
        for observation in comparison.observations:
            for step_index, response in enumerate(observation.responses):
                rows.append(
                    {
                        "case_name": comparison.case_name,
                        "backend_name": observation.backend_name,
                        "matched": str(comparison.matched),
                        "step_index": str(step_index),
                        "positive": str(response.positive),
                        "sid_hex": f"0x{response.sid:02X}",
                        "original_sid_hex": (
                            "" if response.original_sid is None else f"0x{response.original_sid:02X}"
                        ),
                        "nrc_hex": "" if response.nrc is None else f"0x{response.nrc:02X}",
                        "data_hex": response.data_hex,
                    }
                )
    return rows


def differential_summary_csv(
    comparisons: tuple[DifferentialComparison, ...] | None = None,
) -> str:
    """导出差分测试摘要 CSV。"""
    rows = differential_summary_rows(comparisons)
    fieldnames = ["case_name", "backend_count", "matched", "step_count", "backend_names"]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def differential_detail_csv(
    comparisons: tuple[DifferentialComparison, ...] | None = None,
) -> str:
    """导出差分测试细节 CSV。"""
    rows = differential_detail_rows(comparisons)
    fieldnames = [
        "case_name",
        "backend_name",
        "matched",
        "step_index",
        "positive",
        "sid_hex",
        "original_sid_hex",
        "nrc_hex",
        "data_hex",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def differential_markdown_report(
    comparisons: tuple[DifferentialComparison, ...] | None = None,
) -> str:
    """导出便于 thesis 记录的 Markdown 报告。"""
    resolved = comparisons or run_default_differential_suite()
    lines = [
        "<!--",
        "中文说明：",
        "- 这个文件用于记录当前默认差分测试的导出结果。",
        "- 结果比较的是 direct backend 和 gateway-routed backend 在相同 UDS 语义 case 下的行为是否一致。",
        "-->",
        "",
        "# Differential Results",
        "",
        "## Summary",
        "",
        "| Case | Backends | Matched | Steps |",
        "|---|---|---:|---:|",
    ]
    for row in differential_summary_rows(resolved):
        lines.append(
            f"| {row['case_name']} | {row['backend_names']} | {row['matched']} | {row['step_count']} |"
        )

    lines.extend(["", "## Detailed Results", ""])
    for comparison in resolved:
        lines.append(f"### {comparison.case_name}")
        lines.append("")
        lines.append(f"- matched: `{comparison.matched}`")
        lines.append(f"- backends: `{', '.join(comparison.backend_names)}`")
        lines.append("")
        lines.append("| Backend | Step | Positive | SID | Original SID | NRC | Data |")
        lines.append("|---|---:|---:|---|---|---|---|")
        for observation in comparison.observations:
            for step_index, response in enumerate(observation.responses):
                lines.append(
                    "| "
                    f"{observation.backend_name} | "
                    f"{step_index} | "
                    f"{response.positive} | "
                    f"0x{response.sid:02X} | "
                    f"{('-' if response.original_sid is None else f'0x{response.original_sid:02X}')} | "
                    f"{('-' if response.nrc is None else f'0x{response.nrc:02X}')} | "
                    f"{response.data_hex or '-'} |"
                )
        lines.append("")
    return "\n".join(lines) + "\n"
