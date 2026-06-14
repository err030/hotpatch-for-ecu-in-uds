# Hardware Gap Checklist

下面这张表按你这轮点名的 8 项工作，把“当前已有”、“建议复用来源”和“还缺什么”拆开。

| 项目 | 当前已有 | 建议复用来源 | 还缺什么 |
| --- | --- | --- | --- |
| 环境构造 | 已有 `hardware level/board_baseline`、nRF5 SDK、FreeRTOS、MCP2515、CANable/can0 测试脚本和实测 CSV 记录 | 旧项目 `README.md`、`Dockerfile`、`before_patching/Makefile`、`nrfjprog/JLink` 说明 | 缺 repo-local bootstrap、依赖版本锁定、flash/debug/RTT 一键脚本 |
| FreeRTOS 工程建立 | 已有可编译的 `nRF52840 + FreeRTOS + UDS_DIAG task` baseline；已加入 secure/vulnerable/gateway-secure profile 构建入口 | `before_patching/Makefile`、`FreeRTOSConfig.h`、`main.c` 的 `xTaskCreate` 框架 | 缺 CI/host build 入口 |
| RTT 日志 | 已接 `NRF_LOG_DEFAULT_BACKENDS_INIT()` 和 RTT backend | 旧工程 RTT 配置 | 缺单独整理的 RTT 使用流程和日志分级策略 |
| Config Table | C 侧已有 `0x1234` 可写 DID 和 `0x1001` 只读 status DID；Python 侧也能读回 | `g_bms_thresholds`、`g_bms_calibration`、`BMS_REG_*` | 缺更多 DID、持久化策略、写后掉电/重启语义 |
| Session 状态机 | Python 和 C 侧都有 default/extended/seed-issued/unlocked/lockout | 当前仓库 `software_level` | 缺 C 侧 host 单元测试和更系统的 property 测试 |
| UDS Dispatcher | C 侧已有 `0x10 / 0x22 / 0x27 / 0x2E` dispatcher、NRC 输出和 CAN single-frame 入口 | 当前仓库 `software_level` | 缺完整 ISO-TP 多帧、`0x3E TesterPresent`、可选 `0x31 RoutineControl` |
| DID Write | C/Python 已绑定 DID 权限、长度规则、授权检查和 `0x22` 读回验证 | Python 的 `0x2E` 语义 + 旧 BMS 的 `WRITEDEVICE/WRITEALL` 下游写动作 | 缺和真实业务对象/持久化配置的绑定 |
| Replay Check | strict policy 已拒绝 replay；patch 切换会清 replay guard | 当前仓库 replay 场景 + 旧 BMS `g_bms_last_seq` 入口 | 缺 per-session nonce/freshness counter 和持久化失败计数策略 |

## 关键判断

- `Session 状态机 / UDS Dispatcher / DID Write / Replay Check`
  这四项的“正确行为规范”应当优先来自当前仓库，不应优先来自旧 BMS UART 代码。
- `环境构造 / FreeRTOS 工程 / RTT / Kintsugi hotpatch runtime`
  这四项的工程入口应当优先来自旧 `kintsugi_artifact_zenodo`。

## 建议落地顺序

1. 给 C dispatcher 增加 host 单元测试/property 测试，和 Python corpus 对齐。
2. 补完整 ISO-TP 多帧或明确把多帧验证放到 host/Linux ISO-TP 层。
3. 接 Kintsugi `hp_manager_init -> schedule -> guard/applicator -> strict patch` 的真实硬件闭环。

已完成：`python-can / can-isotp / udsoncan`、raw SocketCAN、`vcan0` 回归已经从
skipped 状态推进为可执行结果；CANable2.0 / `can0` 到 nRF52840 的 UDS security
baseline 和 SecurityAccess-derived `0x2E` attack 检查也已经形成真实硬件 CSV 记录；board baseline
已经拆出默认 secure profile、显式 vulnerable profile 和 gateway-secure 对照 profile。
