"""内存中的 CAN 总线。

- 这是 software-only simulation 的虚拟总线层。
- 不依赖真实 SocketCAN，也不依赖真实 USB-CAN 硬件。
- 目前做了最小的 arbitration-id 过滤、接收队列和 trace 记录。

参考来源：
- python-can 仓库: https://github.com/hardbyte/python-can
- python-can virtual bus 文档:
  https://python-can.readthedocs.io/en/stable/interfaces/virtual.html
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

from .isotp import CanFrame


@dataclass
class BusEvent:
    """用于记录一次帧发送事件，便于后面做 trace"""

    sender: str
    receiver: str
    arbitration_id: int
    data: bytes


class InMemoryCanBus:
    """最小可用的内存 CAN 总线"""

    def __init__(self) -> None:
        self._queues: dict[str, deque[CanFrame]] = defaultdict(deque)
        self._filters: dict[str, set[int]] = {}
        self.trace: list[BusEvent] = []

    def register(self, node_name: str, accepted_arbitration_ids: Iterable[int] | None = None) -> None:
        self._queues[node_name]
        if accepted_arbitration_ids is None:
            self._filters[node_name] = set()
            return
        self._filters[node_name] = set(accepted_arbitration_ids)

    def send(self, sender: str, frame: CanFrame) -> None:
        for receiver, queue in self._queues.items():
            if receiver == sender:
                continue
            accepted_ids = self._filters.get(receiver, set())
            if accepted_ids and frame.arbitration_id not in accepted_ids:
                continue
            queue.append(frame)
            self.trace.append(
                BusEvent(
                    sender=sender,
                    receiver=receiver,
                    arbitration_id=frame.arbitration_id,
                    data=frame.data,
                )
            )

    def receive(self, receiver: str, arbitration_id: int) -> CanFrame | None:
        queue = self._queues[receiver]
        for _ in range(len(queue)):
            frame = queue.popleft()
            if frame.arbitration_id == arbitration_id:
                return frame
            queue.append(frame)
        return None

    def drain(self, receiver: str) -> list[CanFrame]:
        """取出一个节点队列里的所有帧，保持先到先出顺序"""
        queue = self._queues[receiver]
        drained: list[CanFrame] = []
        while queue:
            drained.append(queue.popleft())
        return drained

    def clear_trace(self) -> None:
        self.trace = []
