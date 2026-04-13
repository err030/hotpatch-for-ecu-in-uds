"""简化版 ISO-TP 编解码。

- 这个文件只实现了以下内容：
- 支持 normal addressing 下的 Single Frame / First Frame /
  Consecutive Frame / Flow Control。
- 目标不是替代 can-isotp，而是为 software-only simulation 提供
  一个可读、可测试、可解释的最小实现。

参考来源：
- can-isotp 仓库: https://github.com/pylessard/python-can-isotp
- can-isotp 文档: https://can-isotp.readthedocs.io/
- Linux kernel ISO-TP 文档:
  https://docs.kernel.org/networking/iso15765-2.html
"""

from __future__ import annotations

from dataclasses import dataclass, field


FRAME_TYPE_SINGLE = 0x0
FRAME_TYPE_FIRST = 0x1
FRAME_TYPE_CONSECUTIVE = 0x2
FRAME_TYPE_FLOW_CONTROL = 0x3

FLOW_STATUS_CONTINUE_TO_SEND = 0x0

MAX_CAN_DATA = 8
SINGLE_FRAME_MAX_PAYLOAD = 7
FIRST_FRAME_INITIAL_PAYLOAD = 6
CONSECUTIVE_FRAME_PAYLOAD = 7


@dataclass
class CanFrame:
    """最小 CAN 帧对象"""

    arbitration_id: int
    data: bytes

    def __post_init__(self) -> None:
        if len(self.data) > MAX_CAN_DATA:
            raise ValueError("CAN frame data must be 8 bytes or less")


@dataclass
class IsoTpReceiveResult:
    """接收一帧后可能产生的结果"""

    complete_payload: bytes | None = None
    flow_control_frame: CanFrame | None = None


@dataclass
class IsoTpReassembler:
    """把多帧 ISO-TP 重新组装成完整 payload"""

    tx_arbitration_id: int
    rx_arbitration_id: int
    expected_length: int | None = None
    buffer: bytearray = field(default_factory=bytearray)
    next_sequence_number: int = 1

    def accept(self, frame: CanFrame) -> IsoTpReceiveResult:
        pci_type = frame.data[0] >> 4

        if pci_type == FRAME_TYPE_SINGLE:
            payload_length = frame.data[0] & 0x0F
            payload = frame.data[1 : 1 + payload_length]
            return IsoTpReceiveResult(complete_payload=bytes(payload))

        if pci_type == FRAME_TYPE_FIRST:
            total_length = ((frame.data[0] & 0x0F) << 8) | frame.data[1]
            self.expected_length = total_length
            self.buffer = bytearray(frame.data[2:])
            self.next_sequence_number = 1
            flow_control = build_flow_control_frame(self.tx_arbitration_id)

            if len(self.buffer) >= self.expected_length:
                payload = bytes(self.buffer[: self.expected_length])
                self.reset()
                return IsoTpReceiveResult(complete_payload=payload, flow_control_frame=flow_control)

            return IsoTpReceiveResult(flow_control_frame=flow_control)

        if pci_type == FRAME_TYPE_CONSECUTIVE:
            if self.expected_length is None:
                raise ValueError("Received consecutive frame without a first frame")

            sequence_number = frame.data[0] & 0x0F
            if sequence_number != (self.next_sequence_number & 0x0F):
                raise ValueError("Unexpected ISO-TP sequence number")

            self.buffer.extend(frame.data[1:])
            self.next_sequence_number = (self.next_sequence_number + 1) & 0x0F

            if len(self.buffer) >= self.expected_length:
                payload = bytes(self.buffer[: self.expected_length])
                self.reset()
                return IsoTpReceiveResult(complete_payload=payload)

            return IsoTpReceiveResult()

        if pci_type == FRAME_TYPE_FLOW_CONTROL:
            return IsoTpReceiveResult()

        raise ValueError("Unsupported ISO-TP frame type")

    def reset(self) -> None:
        self.expected_length = None
        self.buffer = bytearray()
        self.next_sequence_number = 1


@dataclass
class IsoTpSender:
    """按 ISO-TP 规则把完整 payload 切分成帧"""

    arbitration_id: int
    payload: bytes

    def initial_frame(self) -> CanFrame:
        if len(self.payload) <= SINGLE_FRAME_MAX_PAYLOAD:
            pci = bytes([len(self.payload)])
            frame_data = pci + self.payload
            return CanFrame(self.arbitration_id, pad_to_eight(frame_data))

        length = len(self.payload)
        pci = bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF])
        chunk = self.payload[:FIRST_FRAME_INITIAL_PAYLOAD]
        frame_data = pci + chunk
        return CanFrame(self.arbitration_id, pad_to_eight(frame_data))

    def consecutive_frames(self) -> list[CanFrame]:
        if len(self.payload) <= SINGLE_FRAME_MAX_PAYLOAD:
            return []

        frames: list[CanFrame] = []
        offset = FIRST_FRAME_INITIAL_PAYLOAD
        sequence_number = 1

        while offset < len(self.payload):
            chunk = self.payload[offset : offset + CONSECUTIVE_FRAME_PAYLOAD]
            pci = bytes([0x20 | (sequence_number & 0x0F)])
            frames.append(CanFrame(self.arbitration_id, pad_to_eight(pci + chunk)))
            offset += CONSECUTIVE_FRAME_PAYLOAD
            sequence_number = (sequence_number + 1) & 0x0F

        return frames


def build_flow_control_frame(arbitration_id: int, block_size: int = 0, st_min: int = 0) -> CanFrame:
    """构造最常见的 Continue To Send Flow Control 帧"""
    pci = bytes([(FRAME_TYPE_FLOW_CONTROL << 4) | FLOW_STATUS_CONTINUE_TO_SEND, block_size, st_min])
    return CanFrame(arbitration_id, pad_to_eight(pci))


def pad_to_eight(frame_data: bytes) -> bytes:
    """测试里统一补齐到 8 字节"""
    return frame_data + bytes(MAX_CAN_DATA - len(frame_data))
