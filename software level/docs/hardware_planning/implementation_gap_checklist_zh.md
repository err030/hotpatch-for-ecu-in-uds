# Hardware Gap Checklist

下面这张表按你这轮点名的 8 项工作，把“当前已有”、“建议复用来源”和“还缺什么”拆开。

| 项目 | 当前已有 | 建议复用来源 | 还缺什么 |
| --- | --- | --- | --- |
| 环境构造 | 当前仓库没有板级环境，只做到 `python-can / socketcan / vcan0` | 旧项目 `README.md`、`Dockerfile`、`before_patching/Makefile`、`nrfjprog/JLink` 说明 | 缺 repo-local bootstrap、依赖版本锁定、flash/debug 脚本 |
| FreeRTOS 工程建立 | 当前仓库没有 MCU 工程 | `before_patching/Makefile`、`FreeRTOSConfig.h`、`main.c` 的 `xTaskCreate` 框架 | 缺一个清理过的、面向 UDS ECU 而不是 MiniBMS 演示的工程骨架 |
| RTT 日志 | 当前仓库没有 RTT | `Makefile` 已引入 `nrf_log_backend_rtt.c`，`main.c` 已调用 `NRF_LOG_DEFAULT_BACKENDS_INIT()` | 缺单独整理的 `sdk_config.h` RTT 配置、JLink RTT 使用流程、日志策略选择 |
| Config Table | Python 侧只有抽象状态与 `VALID_WRITE_DID` | `g_bms_thresholds`、`g_bms_calibration`、`BMS_REG_*` | 缺通用 config table API、DID 映射、访问权限、持久化策略 |
| Session 状态机 | `src/hotpatch_uds/ecu.py` 已有 default/extended/seed-issued/unlocked/lockout | 当前仓库 `software_level` | 缺一份 C 版状态机实现和对应单元测试 |
| UDS Dispatcher | `BaseECU.handle()` 已按 `SID` 分发 | 当前仓库 `software_level` | 缺板上 `switch(sid)` dispatcher、transport 入口、negative response 输出 |
| DID Write | Python 侧已实现 `0x2E` 写与授权检查 | Python 的 `0x2E` 语义 + 旧 BMS 的 `WRITEDEVICE/WRITEALL` 下游写动作 | 缺 `DID -> config table` 绑定、NRC 规则、权限检查、回写确认 |
| Replay Check | Python 侧已建模漏洞与修复预期；旧 BMS 只有重复 `seq` 打印 | 当前仓库 replay 场景 + 旧 BMS `g_bms_last_seq` 入口 | 缺真正的 anti-replay 拒绝逻辑、session 绑定、计数器生命周期 |

## 关键判断

- `Session 状态机 / UDS Dispatcher / DID Write / Replay Check`
  这四项的“正确行为规范”应当优先来自当前仓库，不应优先来自旧 BMS UART 代码。
- `环境构造 / FreeRTOS 工程 / RTT / Kintsugi hotpatch runtime`
  这四项的工程入口应当优先来自旧 `kintsugi_artifact_zenodo`。

## 建议落地顺序

1. 用旧 `before_patching` 先起一个最小 `nRF52840 + FreeRTOS + RTT + UART` 工程。
2. 把 `g_bms_thresholds` 和 `g_bms_calibration` 提炼成真正的 `Config Table` 模块。
3. 按当前 `ecu.py` 语义补一版 C 侧 `session_state + uds_dispatcher + did_write`。
4. 最后再把 `replay check` 做成“拒绝”而不是“仅记录”，并决定它是否和 session/unlock 绑定。
