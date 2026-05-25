"""python-can + can-isotp + udsoncan integration runtime.

- 这个模块把当前 mock ECU / gateway 接到第三方 CAN / ISO-TP / UDS 栈。
- backend 分两类：
  1. `python-can` virtual：用于不依赖 OS CAN 设备的进程内测试
  2. `python-can` socketcan：用于 Linux `vcan0` / `can0`
- 这里仍然保留本仓库的 ECU / gateway / patch 逻辑，只替换更真实的通信栈。
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Any

from .bus import BusEvent
from .gateway import GatewayRoute, gateway_allowed_services, service_id_from_can_frame
from .isotp import CanFrame
from .transport import ExchangeResult


DEFAULT_ISOTP_PARAMS = {
    "stmin": 0,
    "blocksize": 8,
    "wftmax": 0,
    "tx_data_length": 8,
    "tx_padding": 0,
    "rx_flowcontrol_timeout": 1000,
    "rx_consecutive_frame_timeout": 1000,
    "max_frame_size": 4095,
    "blocking_send": True,
}


def _import_python_can_stack() -> tuple[Any, Any, Any]:
    try:
        import can
    except ImportError as exc:
        raise RuntimeError("python-can is required for this backend") from exc

    try:
        import isotp
    except ImportError as exc:
        raise RuntimeError("can-isotp is required for this backend") from exc

    try:
        from udsoncan.connections import PythonIsoTpConnection
    except ImportError as exc:
        raise RuntimeError("udsoncan is required for this backend") from exc

    return can, isotp, PythonIsoTpConnection


def _open_bus(
    *,
    interface: str,
    channel: str,
    accepted_arbitration_ids: tuple[int, ...],
) -> Any:
    can, _, _ = _import_python_can_stack()
    bus = can.interface.Bus(
        interface=interface,
        channel=channel,
        receive_own_messages=False,
    )
    filters = [
        {
            "can_id": arbitration_id,
            "can_mask": 0x7FF,
            "extended": False,
        }
        for arbitration_id in accepted_arbitration_ids
    ]
    try:
        bus.set_filters(filters)
    except Exception:
        pass
    return bus


def _make_isotp_address(*, txid: int, rxid: int) -> Any:
    _, isotp, _ = _import_python_can_stack()
    return isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=rxid)


class PythonCanGatewayListener:
    """raw CAN frame gateway for python-can backends."""

    def __init__(self, bus: Any, route: GatewayRoute, mode: str) -> None:
        self.bus = bus
        self.route = route
        self.mode = mode
        self.allowed_services = gateway_allowed_services(mode)
        self.last_drop_reason: str | None = None

    def on_message_received(self, message: Any) -> None:
        if getattr(message, "is_error_frame", False) or getattr(message, "is_remote_frame", False):
            return

        if message.arbitration_id == self.route.external_request_id:
            if not self._allow_request(message):
                return
            self.bus.send(
                self._clone_message(
                    message,
                    arbitration_id=self.route.internal_request_id,
                )
            )
            return

        if message.arbitration_id == self.route.internal_response_id:
            self.bus.send(
                self._clone_message(
                    message,
                    arbitration_id=self.route.external_response_id,
                )
            )

    def __call__(self, message: Any) -> None:
        self.on_message_received(message)

    def stop(self) -> None:
        return

    def _allow_request(self, message: Any) -> bool:
        sid = service_id_from_can_frame(
            CanFrame(
                arbitration_id=message.arbitration_id,
                data=bytes(message.data),
            )
        )
        if self.allowed_services is None or sid is None:
            return True
        if sid in self.allowed_services:
            return True
        self.last_drop_reason = f"gateway mode '{self.mode}' blocked UDS service 0x{sid:02X}"
        return False

    @staticmethod
    def _clone_message(message: Any, *, arbitration_id: int) -> Any:
        can, _, _ = _import_python_can_stack()
        return can.Message(
            arbitration_id=arbitration_id,
            data=bytes(message.data),
            is_extended_id=False,
        )


class UdsoncanTransportConnection:
    """把 udsoncan connection 适配成当前仓库的 request/response 接口。"""

    def __init__(
        self,
        connection: Any,
        *,
        request_timeout_s: float = 1.0,
        gateway_listener: PythonCanGatewayListener | None = None,
    ) -> None:
        self.connection = connection
        self.request_timeout_s = request_timeout_s
        self.gateway_listener = gateway_listener

    def request(self, request_payload: bytes, server_handler=None) -> ExchangeResult:
        del server_handler
        if self.gateway_listener is not None:
            self.gateway_listener.last_drop_reason = None

        self.connection.send(request_payload)
        response_payload = self.connection.wait_frame(timeout=self.request_timeout_s)
        if response_payload is None:
            if self.gateway_listener is not None and self.gateway_listener.last_drop_reason is not None:
                raise RuntimeError(self.gateway_listener.last_drop_reason)
            raise RuntimeError("Timed out waiting for a UDS response over python-can/can-isotp")

        return ExchangeResult(
            request_payload=request_payload,
            response_payload=response_payload,
            trace=[],
        )


class PythonCanIsoTpServer:
    """后台线程中的 ISO-TP server。"""

    def __init__(
        self,
        *,
        stack: Any,
        server_handler,
        send_timeout_s: float = 1.0,
        recv_timeout_s: float = 0.1,
    ) -> None:
        self.stack = stack
        self.server_handler = server_handler
        self.send_timeout_s = send_timeout_s
        self.recv_timeout_s = recv_timeout_s
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self.stack.start()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True, name="python-can-uds-server")
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        try:
            self.stack.stop()
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _serve_forever(self) -> None:
        while not self._stop_event.is_set():
            try:
                payload = self.stack.recv(block=True, timeout=self.recv_timeout_s)
            except Exception:
                if self._stop_event.is_set():
                    return
                continue

            if payload is None:
                continue

            response_payload = self.server_handler(bytes(payload))
            try:
                self.stack.send(response_payload, send_timeout=self.send_timeout_s)
            except Exception:
                if self._stop_event.is_set():
                    return


@dataclass
class PythonCanRuntime:
    """完整的 python-can backend runtime。"""

    connection: UdsoncanTransportConnection
    server: PythonCanIsoTpServer
    client_connection: Any
    client_stack: Any
    server_stack: Any
    buses: tuple[Any, ...]
    notifiers: tuple[Any, ...]

    def start(self) -> None:
        self.client_connection.open()
        self.server.start()

    def close(self) -> None:
        try:
            self.client_connection.close()
        except Exception:
            pass

        self.server.close()

        try:
            self.client_stack.stop()
        except Exception:
            pass
        try:
            self.server_stack.stop()
        except Exception:
            pass

        for notifier in self.notifiers:
            try:
                notifier.stop()
            except Exception:
                pass
        for bus in self.buses:
            try:
                bus.shutdown()
            except Exception:
                pass


def build_python_can_runtime(
    *,
    interface: str,
    channel: str,
    client_name: str,
    client_txid: int,
    client_rxid: int,
    server_name: str,
    server_txid: int,
    server_rxid: int,
    server_handler,
    gateway_route: GatewayRoute | None = None,
    gateway_mode: str | None = None,
    isotp_params: dict[str, Any] | None = None,
) -> PythonCanRuntime:
    """构造 direct 或 gateway-routed python-can backend runtime。"""
    can, isotp, PythonIsoTpConnection = _import_python_can_stack()

    route = gateway_route
    resolved_isotp_params = dict(DEFAULT_ISOTP_PARAMS)
    if isotp_params:
        resolved_isotp_params.update(isotp_params)

    client_bus = _open_bus(
        interface=interface,
        channel=channel,
        accepted_arbitration_ids=(client_rxid,),
    )
    server_bus = _open_bus(
        interface=interface,
        channel=channel,
        accepted_arbitration_ids=(server_rxid,),
    )

    gateway_listener = None
    gateway_bus = None
    gateway_notifier = None
    if route is not None and gateway_mode is not None:
        gateway_bus = _open_bus(
            interface=interface,
            channel=channel,
            accepted_arbitration_ids=(route.external_request_id, route.internal_response_id),
        )
        gateway_listener = PythonCanGatewayListener(gateway_bus, route, gateway_mode)
        gateway_notifier = can.Notifier(gateway_bus, [gateway_listener])

    client_notifier = can.Notifier(client_bus, [])
    client_stack = isotp.NotifierBasedCanStack(
        bus=client_bus,
        notifier=client_notifier,
        address=_make_isotp_address(txid=client_txid, rxid=client_rxid),
        params=resolved_isotp_params,
    )
    client_connection = PythonIsoTpConnection(client_stack, name=client_name)

    server_notifier = can.Notifier(server_bus, [])
    server_stack = isotp.NotifierBasedCanStack(
        bus=server_bus,
        notifier=server_notifier,
        address=_make_isotp_address(txid=server_txid, rxid=server_rxid),
        params=resolved_isotp_params,
    )
    server_runtime = PythonCanIsoTpServer(
        stack=server_stack,
        server_handler=server_handler,
    )

    buses = [client_bus, server_bus]
    notifiers = [client_notifier, server_notifier]
    if gateway_bus is not None and gateway_notifier is not None:
        buses.append(gateway_bus)
        notifiers.append(gateway_notifier)

    return PythonCanRuntime(
        connection=UdsoncanTransportConnection(
            client_connection,
            gateway_listener=gateway_listener,
        ),
        server=server_runtime,
        client_connection=client_connection,
        client_stack=client_stack,
        server_stack=server_stack,
        buses=tuple(buses),
        notifiers=tuple(notifiers),
    )
