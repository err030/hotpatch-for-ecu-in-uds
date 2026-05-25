# Software Level

这里对应当前仓库已经存在的、可运行的 `software-level baseline`。它不是硬件工程，但已经把你后续要落到板子上的很多语义先做成了可验证模型。

## 当前存放方式

- 根目录下的 `src/`、`tests/`、`charts/` 继续保留为原始工作区
- 另外复制了一份单独归档副本到：
  [python_baseline_bundle/README_zh.md](python_baseline_bundle/README_zh.md)

## 直接对应你这轮任务的内容

- Session 状态机
  见 [src/hotpatch_uds/ecu.py](../../src/hotpatch_uds/ecu.py)
- UDS Dispatcher
  见 `BaseECU.handle()`，按 `0x10 / 0x27 / 0x2E` 分发
- DID Write
  见 [src/hotpatch_uds/protocol.py](../../src/hotpatch_uds/protocol.py)、[src/hotpatch_uds/client.py](../../src/hotpatch_uds/client.py)、[src/hotpatch_uds/ecu.py](../../src/hotpatch_uds/ecu.py)
- Replay Check
  见 `allow_replay_without_unlock`、[src/hotpatch_uds/scenarios.py](../../src/hotpatch_uds/scenarios.py)、[tests/test_gateway.py](../../tests/test_gateway.py)
- Hotpatch 生命周期
  见 [src/hotpatch_uds/hotpatch.py](../../src/hotpatch_uds/hotpatch.py)、[src/hotpatch_uds/server.py](../../src/hotpatch_uds/server.py)
- Timing / evaluation / differential / fuzzing
  见 [src/hotpatch_uds/timing.py](../../src/hotpatch_uds/timing.py)、[src/hotpatch_uds/evaluation.py](../../src/hotpatch_uds/evaluation.py)、[src/hotpatch_uds/differential.py](../../src/hotpatch_uds/differential.py)、[src/hotpatch_uds/fuzzing.py](../../src/hotpatch_uds/fuzzing.py)

## 它适合做什么

- 固化 `0x10 -> 0x27 -> 0x2E` 的预期语义
- 先决定 session / unlock / replay 的边界条件
- 在移植到 C / RTOS 之前先把负面测试和回归测试定住
- 作为板级实现的行为基准

## 它还不是什么

- 不是 `nRF52840-DK` 固件工程
- 不是真实 `FreeRTOS` 上下文切换里的 hotpatch
- 不是带 `CAN controller / ISO-TP stack / UDS server` 的板级实现

所以，`software level` 的角色不是被替代，而是给 `hardware level` 提供一份已经跑通的行为规范。
