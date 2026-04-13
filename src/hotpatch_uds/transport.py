"""基于内存总线的简化 UDS/ISO-TP 连接。

- 这个文件把UDS payload放到ISO-TP over CAN上。
- 它是专门给 thesis 的 software-only simulation 用，目标是让 client 和 mock ECU 不再直接函数调用，而是通过字节 payload
  和帧交换来交互。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .bus import BusEvent, InMemoryCanBus
from .isotp import IsoTpReassembler, IsoTpSender


@dataclass
class EndpointConfig:
    """一个节点在总线上的收发配置"""

    name: str
    tx_arbitration_id: int
    rx_arbitration_id: int


@dataclass
class ExchangeResult:
    """一次 request/response 往返后的结果"""

    request_payload: bytes
    response_payload: bytes
    trace: list[BusEvent] = field(default_factory=list)


class InMemoryIsoTpConnection:
    """client 和 server 之间的同步请求通道"""

    def __init__(self, bus: InMemoryCanBus, client: EndpointConfig, server: EndpointConfig) -> None:
        self.bus = bus
        self.client = client
        self.server = server
        self.bus.register(client.name)
        self.bus.register(server.name)

    def request(self, request_payload: bytes, server_handler) -> ExchangeResult:
        self.bus.clear_trace()
        server_request = self._deliver(
            sender=self.client,
            receiver=self.server,
            payload=request_payload,
        )
        response_payload = server_handler(server_request)
        client_response = self._deliver(
            sender=self.server,
            receiver=self.client,
            payload=response_payload,
        )

        return ExchangeResult(
            request_payload=request_payload,
            response_payload=client_response,
            trace=list(self.bus.trace),
        )

    def _deliver(self, sender: EndpointConfig, receiver: EndpointConfig, payload: bytes) -> bytes:
        sender_state = IsoTpSender(arbitration_id=sender.tx_arbitration_id, payload=payload)
        receiver_state = IsoTpReassembler(
            tx_arbitration_id=receiver.tx_arbitration_id,
            rx_arbitration_id=receiver.rx_arbitration_id,
        )

        first_frame = sender_state.initial_frame()
        self.bus.send(sender.name, first_frame)

        incoming = self.bus.receive(receiver.name, receiver.rx_arbitration_id)
        if incoming is None:
            raise RuntimeError("Receiver did not receive the initial frame")

        result = receiver_state.accept(incoming)

        if result.complete_payload is not None:
            return result.complete_payload

        if result.flow_control_frame is None:
            raise RuntimeError("Expected flow control for a multi-frame transfer")

        self.bus.send(receiver.name, result.flow_control_frame)
        flow_control = self.bus.receive(sender.name, sender.rx_arbitration_id)
        if flow_control is None:
            raise RuntimeError("Sender did not receive flow control")

        for frame in sender_state.consecutive_frames():
            self.bus.send(sender.name, frame)
            incoming_cf = self.bus.receive(receiver.name, receiver.rx_arbitration_id)
            if incoming_cf is None:
                raise RuntimeError("Receiver did not receive a consecutive frame")
            result = receiver_state.accept(incoming_cf)
            if result.complete_payload is not None:
                return result.complete_payload

        raise RuntimeError("Payload delivery ended before message completion")
