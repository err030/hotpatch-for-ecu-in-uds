# Architecture Assessment

## 当前结构的优点

- `protocol.py -> client.py -> transport.py -> gateway.py -> server.py -> ecu.py` 这一条主链足够清晰，论文里容易解释。
- ECU 状态机和通信层是分离的，所以把底层从 `in-memory` 换成 `python-can / can-isotp / udsoncan / socketcan` 时，不需要重写 UDS 攻击语义。
- `fleet.py`、`timing.py`、`differential.py`、`fuzzing.py` 都建立在同一套主链之上，结构上适合做 thesis 的多维评估。

## 当前结构原本的主要不足

- 早期版本的通信层主要是 `InMemoryCanBus`，只能证明“协议语义”，不能证明“OS 级 CAN stack 行为”。
- hotpatch 原本只是 `apply_patch()` 的布尔切换，缺少 `quarantine / validation / scheduling / guard / applicator / slot` 这些能支撑评估的生命周期。
- exposure window、资源占用、实时性、抵挡率原本分散在不同模块里，没有统一成一个软件级评估出口。

## 当前这轮整理后的状态

- backend 现在明确分成三层：
  - `in-memory`
  - `python-can virtual`
  - `python-can socketcan/vcan0`
- 第三方协议栈已经预留到：
  - `python-can`
  - `can-isotp`
  - `udsoncan`
- hotpatch 现在提升成 Kintsugi 风格的软件模型：
  - `hotpatch.py`
  - `server.py` 中的 manager 生命周期
  - `evaluation.py` 中的资源、实时性、攻击阻挡率、exposure window 评估

## 仍然需要保持清醒的限制

- 这里的 Kintsugi 参考仍然是 software-level abstraction，不是真正的 RTOS context switch integration。
- `guard/applicator` 在这里是 safe-point 模型，不是 MPU/RTOS 级硬保护。
- `python-can virtual` 不是 OS 级 CAN；真正进入 OS 层的是 `socketcan + vcan0`。
- 当前 `udsoncan` 集成重点在 connection path，仍保留了本仓库自己的 UDS request/response 语义层，以便兼容已有测试与差分框架。

## 对 thesis 的结论意义

- 现在这套结构已经足够支撑“software-first”论证：
  - hotpatch 是否能在 OTA 前更快提供 first protection
  - 这种更快保护是否理论上缩短 exposure window
  - 为此需要付出多少资源与实时性代价
  - 对当前 UDS attack flow 的阻挡率能提高多少
- 但如果论文要主张“可直接落地到 RTOS/hardware”，还需要下一阶段把这些结果推进到真实硬件和真实调度上下文。 
