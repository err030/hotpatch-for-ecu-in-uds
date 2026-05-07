"""SocketCAN/vcan runtime for the existing UDS simulation.

- 这个模块把当前的 software-first UDS/ISO-TP 栈接到 Linux SocketCAN。
- 它不依赖 python-can / can-isotp / udsoncan，直接使用标准库 socket.AF_CAN。
- 目标是让 thesis 当前的 mock ECU / gateway / attack flow 可以先在 `vcan0`
  上跑起来，再决定是否切到外部框架。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import struct
import threading
from typing import Iterable

from .bus import BusEvent
from .gateway import GatewayRoute, gateway_allowed_services, service_id_from_can_frame
from .isotp import CanFrame, IsoTpReassembler, IsoTpSender
from .transport import EndpointConfig, ExchangeResult


CAN_FRAME_FORMAT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FORMAT)
CAN_FILTER_FORMAT = "=II"
CAN_STANDARD_ID_MASK = getattr(socket, "CAN_SFF_MASK", 0x7FF)
SOCKET_RECV_TIMEOUT_S = 0.2


def socketcan_supported() -> bool:
    """当前 Python / kernel 是否提供原始 CAN socket 能力。"""
    return hasattr(socket, "AF_CAN") and hasattr(socket, "CAN_RAW")


def socketcan_raw_socket_usable(interface: str) -> bool:
    """当前进程是否能成功打开并绑定 raw CAN socket。"""
    if not socketcan_supported() or not socketcan_interface_exists(interface):
        return False
    try:
        probe = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        try:
            probe.bind((interface,))
        finally:
            probe.close()
        return True
    except OSError:
        return False


def socketcan_interface_exists(interface: str) -> bool:
    """检查给定的网络接口是否存在。"""
    return Path("/sys/class/net", interface).exists()


def _pack_can_frame(frame: CanFrame) -> bytes:
    data = frame.data.ljust(8, b"\x00")
    return struct.pack(CAN_FRAME_FORMAT, frame.arbitration_id, len(frame.data), data)


def _unpack_can_frame(raw_frame: bytes) -> CanFrame:
    can_id, data_length, data = struct.unpack(CAN_FRAME_FORMAT, raw_frame[:CAN_FRAME_SIZE])
    return CanFrame(arbitration_id=can_id & CAN_STANDARD_ID_MASK, data=data[:data_length])


def _pack_filter(arbitration_id: int) -> bytes:
    return struct.pack(CAN_FILTER_FORMAT, arbitration_id, CAN_STANDARD_ID_MASK)


def _open_can_socket(
    interface: str,
    *,
    accepted_arbitration_ids: Iterable[int],
    timeout_s: float = SOCKET_RECV_TIMEOUT_S,
) -> socket.socket:
    if not socketcan_supported():
        raise RuntimeError("Python socket module does not expose AF_CAN/CAN_RAW support")
    if not socketcan_interface_exists(interface):
        raise RuntimeError(
            f"SocketCAN interface '{interface}' does not exist. "
            "Create it first, for example with: sudo modprobe vcan; "
            "sudo ip link add dev vcan0 type vcan; sudo ip link set up vcan0"
        )

    can_socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    filters = b"".join(_pack_filter(arbitration_id) for arbitration_id in accepted_arbitration_ids)
    if filters:
        can_socket.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, filters)
    can_socket.settimeout(timeout_s)
    can_socket.bind((interface,))
    return can_socket


class SocketCanIsoTpConnection:
    """通过 SocketCAN 发送请求并等待 ECU 响应。"""

    def __init__(
        self,
        *,
        interface: str,
        client: EndpointConfig,
        server: EndpointConfig,
        gateway: "SocketCanGatewayRuntime | None" = None,
        timeout_s: float = SOCKET_RECV_TIMEOUT_S,
    ) -> None:
        self.interface = interface
        self.client = client
        self.server = server
        self.gateway = gateway
        self.timeout_s = timeout_s
        self.socket = _open_can_socket(
            interface,
            accepted_arbitration_ids={client.rx_arbitration_id},
            timeout_s=timeout_s,
        )

    def close(self) -> None:
        self.socket.close()

    def request(self, request_payload: bytes, server_handler=None) -> ExchangeResult:
        del server_handler
        if self.gateway is not None:
            self.gateway.last_drop_reason = None
        trace: list[BusEvent] = []
        self._send_payload(
            payload=request_payload,
            tx_arbitration_id=self.client.tx_arbitration_id,
            rx_flow_control_id=self.client.rx_arbitration_id,
            sender_name=self.client.name,
            receiver_name=self.server.name,
            trace=trace,
        )
        response_payload = self._receive_payload(
            rx_arbitration_id=self.client.rx_arbitration_id,
            tx_flow_control_id=self.client.tx_arbitration_id,
            sender_name=self.server.name,
            receiver_name=self.client.name,
            trace=trace,
        )
        return ExchangeResult(
            request_payload=request_payload,
            response_payload=response_payload,
            trace=trace,
        )

    def _send_payload(
        self,
        *,
        payload: bytes,
        tx_arbitration_id: int,
        rx_flow_control_id: int,
        sender_name: str,
        receiver_name: str,
        trace: list[BusEvent],
    ) -> None:
        sender = IsoTpSender(arbitration_id=tx_arbitration_id, payload=payload)
        initial = sender.initial_frame()
        self._send_frame(initial, sender_name=sender_name, receiver_name=receiver_name, trace=trace)

        if len(payload) <= 7:
            return

        self._receive_matching_frame(rx_flow_control_id)
        for frame in sender.consecutive_frames():
            self._send_frame(frame, sender_name=sender_name, receiver_name=receiver_name, trace=trace)

    def _receive_payload(
        self,
        *,
        rx_arbitration_id: int,
        tx_flow_control_id: int,
        sender_name: str,
        receiver_name: str,
        trace: list[BusEvent],
    ) -> bytes:
        reassembler = IsoTpReassembler(
            tx_arbitration_id=tx_flow_control_id,
            rx_arbitration_id=rx_arbitration_id,
        )

        while True:
            incoming = self._receive_matching_frame(rx_arbitration_id)
            trace.append(
                BusEvent(
                    sender=sender_name,
                    receiver=receiver_name,
                    arbitration_id=incoming.arbitration_id,
                    data=incoming.data,
                )
            )
            result = reassembler.accept(incoming)
            if result.complete_payload is not None:
                return result.complete_payload
            if result.flow_control_frame is not None:
                self._send_frame(
                    result.flow_control_frame,
                    sender_name=receiver_name,
                    receiver_name=sender_name,
                    trace=trace,
                )

    def _send_frame(
        self,
        frame: CanFrame,
        *,
        sender_name: str,
        receiver_name: str,
        trace: list[BusEvent],
    ) -> None:
        self.socket.send(_pack_can_frame(frame))
        trace.append(
            BusEvent(
                sender=sender_name,
                receiver=receiver_name,
                arbitration_id=frame.arbitration_id,
                data=frame.data,
            )
        )

    def _receive_matching_frame(self, arbitration_id: int) -> CanFrame:
        while True:
            try:
                raw_frame = self.socket.recv(CAN_FRAME_SIZE)
            except TimeoutError as exc:
                if self.gateway is not None and self.gateway.last_drop_reason is not None:
                    raise RuntimeError(self.gateway.last_drop_reason) from exc
                raise RuntimeError(
                    f"Timed out waiting for CAN frame 0x{arbitration_id:03X} on {self.interface}"
                ) from exc

            frame = _unpack_can_frame(raw_frame)
            if frame.arbitration_id == arbitration_id:
                return frame


class SocketCanUdsServer:
    """在后台线程里监听 CAN 帧并调用现有 ECU server。"""

    def __init__(
        self,
        *,
        interface: str,
        endpoint: EndpointConfig,
        server_handler,
        timeout_s: float = SOCKET_RECV_TIMEOUT_S,
    ) -> None:
        self.interface = interface
        self.endpoint = endpoint
        self.server_handler = server_handler
        self.timeout_s = timeout_s
        self.socket = _open_can_socket(
            interface,
            accepted_arbitration_ids={endpoint.rx_arbitration_id},
            timeout_s=timeout_s,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._serve_forever, daemon=True, name="uds-ecu-server")
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        self.socket.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _serve_forever(self) -> None:
        while not self._stop_event.is_set():
            try:
                request_payload = self._receive_payload()
            except OSError:
                break
            except RuntimeError:
                continue

            response_payload = self.server_handler(request_payload)
            try:
                self._send_payload(response_payload)
            except OSError:
                break

    def _receive_payload(self) -> bytes:
        reassembler = IsoTpReassembler(
            tx_arbitration_id=self.endpoint.tx_arbitration_id,
            rx_arbitration_id=self.endpoint.rx_arbitration_id,
        )
        while not self._stop_event.is_set():
            try:
                raw_frame = self.socket.recv(CAN_FRAME_SIZE)
            except TimeoutError:
                continue

            frame = _unpack_can_frame(raw_frame)
            if frame.arbitration_id != self.endpoint.rx_arbitration_id:
                continue

            result = reassembler.accept(frame)
            if result.complete_payload is not None:
                return result.complete_payload
            if result.flow_control_frame is not None:
                self.socket.send(_pack_can_frame(result.flow_control_frame))

        raise RuntimeError("SocketCAN ECU server stopped before a request was fully received")

    def _send_payload(self, payload: bytes) -> None:
        sender = IsoTpSender(arbitration_id=self.endpoint.tx_arbitration_id, payload=payload)
        self.socket.send(_pack_can_frame(sender.initial_frame()))

        if len(payload) <= 7:
            return

        while not self._stop_event.is_set():
            try:
                raw_frame = self.socket.recv(CAN_FRAME_SIZE)
            except TimeoutError:
                continue
            frame = _unpack_can_frame(raw_frame)
            if frame.arbitration_id != self.endpoint.rx_arbitration_id:
                continue
            break
        else:
            raise RuntimeError("SocketCAN ECU server stopped before flow control arrived")

        for frame in sender.consecutive_frames():
            self.socket.send(_pack_can_frame(frame))


class SocketCanGatewayRuntime:
    """把当前 gateway 策略放到 SocketCAN 后台线程里运行。"""

    def __init__(
        self,
        *,
        interface: str,
        route: GatewayRoute | None = None,
        mode: str,
        timeout_s: float = SOCKET_RECV_TIMEOUT_S,
    ) -> None:
        self.interface = interface
        self.route = route or GatewayRoute()
        self.timeout_s = timeout_s
        self.mode = mode
        self.allowed_services = gateway_allowed_services(mode)
        self.last_drop_reason: str | None = None
        self.socket = _open_can_socket(
            interface,
            accepted_arbitration_ids={
                self.route.external_request_id,
                self.route.internal_response_id,
            },
            timeout_s=timeout_s,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._forward_forever, daemon=True, name="uds-gateway")
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        self.socket.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _forward_forever(self) -> None:
        while not self._stop_event.is_set():
            try:
                raw_frame = self.socket.recv(CAN_FRAME_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break

            frame = _unpack_can_frame(raw_frame)
            forwarded = self._translate_frame(frame)
            if forwarded is not None:
                self.socket.send(_pack_can_frame(forwarded))

    def _translate_frame(self, frame: CanFrame) -> CanFrame | None:
        if frame.arbitration_id == self.route.external_request_id:
            if not self._allow_request_frame(frame):
                return None
            return CanFrame(arbitration_id=self.route.internal_request_id, data=frame.data)
        if frame.arbitration_id == self.route.internal_response_id:
            return CanFrame(arbitration_id=self.route.external_response_id, data=frame.data)
        return None

    def _allow_request_frame(self, frame: CanFrame) -> bool:
        sid = service_id_from_can_frame(frame)
        if self.allowed_services is None or sid is None:
            return True
        if sid in self.allowed_services:
            return True
        self.last_drop_reason = f"gateway mode '{self.mode}' blocked UDS service 0x{sid:02X}"
        return False


@dataclass
class SocketCanRuntime:
    """一个完整的 SocketCAN 场景 runtime。"""

    connection: SocketCanIsoTpConnection
    server: SocketCanUdsServer
    gateway: SocketCanGatewayRuntime | None = None

    def start(self) -> None:
        if self.gateway is not None:
            self.gateway.start()
        self.server.start()

    def close(self) -> None:
        self.connection.close()
        if self.gateway is not None:
            self.gateway.close()
        self.server.close()
