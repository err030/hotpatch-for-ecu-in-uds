# Current Framework Inventory

这份清单只列当前仓库已经有的 `software-level` 框架，以及它们对后续硬件迁移的价值。

## 1. 协议与传输层

- [src/hotpatch_uds/protocol.py](../../src/hotpatch_uds/protocol.py)
  已有 `UDS request/response` 编解码，包含 `0x10`、`0x27`、`0x2E` 和 negative response 语义。
- [src/hotpatch_uds/isotp.py](../../src/hotpatch_uds/isotp.py)
  已有简化 ISO-TP 分帧/重组。
- [src/hotpatch_uds/bus.py](../../src/hotpatch_uds/bus.py)
  已有内存 CAN 总线抽象。
- [src/hotpatch_uds/transport.py](../../src/hotpatch_uds/transport.py)
  已有同步 request-response 交互过程。
- [src/hotpatch_uds/pythoncan.py](../../src/hotpatch_uds/pythoncan.py) 与 [src/hotpatch_uds/socketcan.py](../../src/hotpatch_uds/socketcan.py)
  已经把软件模型向 `python-can` 和 `SocketCAN / vcan0` 推进了一层。

## 2. UDS 语义层

- [src/hotpatch_uds/ecu.py](../../src/hotpatch_uds/ecu.py)
  这是当前最重要的行为基线。里面已经有：
  - session 状态
  - seed/key
  - failed attempts
  - lockout ticks
  - local periodic tick
  - `WriteDataByIdentifier` 检查
  - replay 缺陷建模
- [src/hotpatch_uds/client.py](../../src/hotpatch_uds/client.py)
  已有最小 client 封装。
- [src/hotpatch_uds/gateway.py](../../src/hotpatch_uds/gateway.py)
  已有 routed diagnostics 与 gateway policy 模型。
- [src/hotpatch_uds/server.py](../../src/hotpatch_uds/server.py)
  已有 server 侧包装与 patch 生命周期挂接点。

## 3. Hotpatch 软件模型

- [src/hotpatch_uds/hotpatch.py](../../src/hotpatch_uds/hotpatch.py)
  已经把 `Kintsugi` 的关键结构抽象成：
  - quarantine
  - slot
  - validation
  - scheduling
  - guard/applicator
  - resource accounting

这个文件不是 RTOS/MPU 真实现，但它对后续硬件设计非常有价值，因为它已经把你要保留的状态和生命周期讲清楚了。

## 4. 评估与验证层

- [src/hotpatch_uds/timing.py](../../src/hotpatch_uds/timing.py)
  已有 UDS handler 与周期任务抖动模型。
- [src/hotpatch_uds/evaluation.py](../../src/hotpatch_uds/evaluation.py)
  已有 exposure window、资源占用、实时性、攻击阻挡率汇总。
- [src/hotpatch_uds/differential.py](../../src/hotpatch_uds/differential.py)
  已有 direct / gateway-routed 一致性差分框架。
- [src/hotpatch_uds/fuzzing.py](../../src/hotpatch_uds/fuzzing.py)
  已有 parser/state/ISO-TP 异常输入 corpus。

## 5. 对你当前硬件任务的直接价值

- Session 状态机
  `ecu.py` 可以直接作为 C 版状态机的行为标准。
- UDS Dispatcher
  `BaseECU.handle()` 可以直接翻译成 C 版 `switch(sid)` 结构。
- DID Write
  `protocol.py + ecu.py` 可以提供 `0x2E` 的最小正负响应规则。
- Replay Check
  当前 Python 侧已经把“漏洞版本”和“修复版本”都做出来了，适合先固定预期。
- Hotpatch
  `hotpatch.py` 能告诉你板级代码至少要保留哪些 manager/slot/runtime 元数据。

## 6. 当前 software-level 还不能替代的东西

- 真正的 `nRF52840-DK` 工程目录
- `SEGGER RTT` / `APP_UART` 真实日志链路
- `FreeRTOS` 上下文切换钩子
- `MPU` 保护与 `MemManage` 异常处理
- 真正的 `UDS-over-CAN` 固件实现

这些内容需要到 `hardware level/` 里接旧 `kintsugi_artifact_zenodo` 资产。
