"""最小 UDS client。

- 这个文件模拟 tester/attacker 这一侧。
- 它先构造标准 UDS payload，再通过 transport 发出去。
- 这一步的职责和后续接入 udsoncan 的职责相近，但这里先保持轻量。

参考来源：
- python-udsoncan 仓库: https://github.com/pylessard/python-udsoncan
- udsoncan client 文档:
  https://udsoncan.readthedocs.io/en/latest/udsoncan/client.html
"""

from __future__ import annotations

from dataclasses import dataclass

from .protocol import (
    SESSION_EXTENDED,
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_SECURITY_ACCESS,
    SID_WRITE_DATA_BY_IDENTIFIER,
    UDSRequest,
    UDSResponse,
)
from .transport import ExchangeResult, InMemoryIsoTpConnection


@dataclass
class ClientCallResult:
    """一次 client 调用的解析结果"""

    response: UDSResponse
    exchange: ExchangeResult


class UdsClient:
    """用于软件仿真的最小 client"""

    def __init__(self, connection: InMemoryIsoTpConnection, server_handler) -> None:
        self.connection = connection
        self.server_handler = server_handler

    def raw_request(self, request: UDSRequest) -> ClientCallResult:
        request_payload = request.to_payload()
        exchange = self.connection.request(request_payload, self.server_handler)
        response = UDSResponse.from_payload(exchange.response_payload)
        return ClientCallResult(response=response, exchange=exchange)

    def change_to_extended_session(self) -> ClientCallResult:
        return self.raw_request(
            UDSRequest(
                sid=SID_DIAGNOSTIC_SESSION_CONTROL,
                subfunction=SESSION_EXTENDED,
            )
        )

    def request_seed(self) -> ClientCallResult:
        return self.raw_request(UDSRequest(sid=SID_SECURITY_ACCESS, subfunction=0x01))

    def send_key(self, key: bytes) -> ClientCallResult:
        return self.raw_request(UDSRequest(sid=SID_SECURITY_ACCESS, subfunction=0x02, data=key))

    def write_data_by_identifier(self, did: int, data: bytes) -> ClientCallResult:
        return self.raw_request(UDSRequest(sid=SID_WRITE_DATA_BY_IDENTIFIER, did=did, data=data))
