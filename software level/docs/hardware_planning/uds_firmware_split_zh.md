# UDS Firmware Split

这部分不是现成代码，而是给后续板上实现预留的模块边界。目的只有一个：不要把 `BMS 业务逻辑`、`UDS 状态机`、`replay`、`board driver` 全塞回一个 `main.c`。

## 建议的模块拆分

- `app/main.c`
  只做时钟、日志、UART/CAN、任务创建、启动调度器。
- `diagnostics/session_state.[ch]`
  负责 default / extended / seed-issued / unlocked / lockout 状态。
- `diagnostics/uds_dispatcher.[ch]`
  负责按 `SID` 分发 `0x10 / 0x27 / 0x2E`。
- `diagnostics/config_table.[ch]`
  负责阈值表、校准表、访问属性、查表写入。
- `diagnostics/did_handlers.[ch]`
  负责 `DID -> config_table entry` 映射和正负响应逻辑。
- `security/replay_check.[ch]`
  负责 `seq/nonce/session binding`，不再只是打印重复 `seq`。
- `transport/transport_adapter.[ch]`
  负责板上使用的是 `UART bridge`、`CAN` 还是后续 `ISO-TP`。
- `hotpatch/hotpatch_port.[ch]`
  负责把 UDS 诊断路径和 `Kintsugi` manager 接起来。

## 各模块的语义来源

- `session_state`、`uds_dispatcher`、`did_handlers`
  语义优先参考当前仓库 [src/hotpatch_uds/ecu.py](../../../src/hotpatch_uds/ecu.py)
- `config_table`
  数据布局优先参考旧 BMS 的 `g_bms_thresholds`、`g_bms_calibration`
- `replay_check`
  入口参考旧 BMS 的 `g_bms_last_seq`，正确行为参考当前仓库 replay 场景
- `hotpatch_port`
  参考旧 `kintsugi` 的 `hp_manager.c`、`hp_guard.c`、`hp_exception.c`

## 这样拆分的原因

- `main.c` 只负责 bring-up，后续不会失控
- UDS 行为能和 transport 解耦
- replay / DID / session 能分别测试
- 从 Python 行为模型移植到 C 时，有明确的一对一落点
