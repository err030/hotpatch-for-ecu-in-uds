# Legacy Reuse Inventory

这份清单把旧 `kintsugi_artifact_zenodo` 里的相关资产分成三类：

- 可以直接拿来做当前板级工程底座
- 适合参考，但不能原样照搬
- 不建议搬进当前仓库

## 1. 可以直接拿来做底座的内容

- `/home/beibei/Downloads/kintsugi_artifact_zenodo/experiments/security/before_patching/Makefile`
  这是最有价值的板级入口文件。它已经把 `nRF5 SDK`、`FreeRTOS-Kernel`、`Kintsugi`、`APP_UART`、`RTT backend`、链接脚本都串起来了。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/experiments/security/before_patching/include/config/FreeRTOSConfig.h`
  已经打开了 `configUSE_HP_FRAMEWORK` 和 `configHP_TASK_NAME`，适合继续保留为 hotpatch 版 FreeRTOS 配置基线。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/example_rtos_integration/freertos/tasks.c`
  这是 FreeRTOS `tasks.c` 被改过后的完整版本，能直接看出 Kintsugi 需要把哪些钩子塞进 context switch。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/external/patches/FreeRTOS-Kernel.patch`
  和上面的 `tasks.c` 一致，适合在你后续换不同 FreeRTOS 版本时做 patch 参考。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/kintsugi/include/`
  和 `/home/beibei/Downloads/kintsugi_artifact_zenodo/kintsugi/src/`
  这是 Kintsugi 真正的 manager / guard / applicator / slot / exception / measure 实现。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/kintsugi/hp_layout_freertos.ld`
  这是板级链接布局的关键文件，后续如果要保留 hotpatch code/slot/context/quarantine 的分区，必须参考它。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/kintsugi/src/hp_freertos_mpu.c`
  已经把 hotpatch code/slot/context/quarantine 区域映射到 `MPU` 保护逻辑里了。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/kintsugi/src/hp_exception.c`
  已经把 `MemManage` 诊断变量、fault 地址记录和重要日志输出做好了。

## 2. 适合复用的 BMS / UART 业务资产

- `/home/beibei/Downloads/kintsugi_artifact_zenodo/experiments/security/before_patching/src/main.c`
  这里面已经有一个完整的 `nRF52840 + FreeRTOS + BMS demo`，包含：
  - `BMS_MON / BMS_EST / BMS_PROT / BMS_COMM / BMS_UART_RX`
  - 全局状态、阈值表、校准表
  - UART 帧解析器
- `g_bms_thresholds` 与 `g_bms_calibration`
  这两个结构非常适合拿来当当前项目里 `Config Table` 的第一个硬件侧原型。
- `BMS_REG_STATE_*` 与 `BMS_REG_CALIB_*`
  这套寄存器号可以继续保留为硬件内部对象标识，再在上层额外映射成 `UDS DID`。
- `bms_uart_apply_write_device()`
  这里已经有寄存器级写入路径，适合当 `DID Write` 的下游写入动作原型。
- `bms_uart_rx_task()`
  已经有状态机式的 UART 帧接收逻辑，适合继续作为板上 debug/attack 注入口。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/bms_threads_scripts/send_bms_uart_attack.py`
  这是现成的 host-side 注入脚本，已经能生成 `writeall / overflow / state / calib / replay` 几类帧。

## 3. 只适合参考，不能原样照搬的内容

- `experiments/security/during_patching/src/main.c`
  它对“攻击发生在 patch 期间”的测量更有价值，但不适合拿来当 clean baseline。
- `experiments/security/after_patching/src/main.c`
  它偏重验证 `MPU / MemManage` 拦截效果，也不适合当最初工程入口。
- `bms_threads_scripts/*.sh`
  这些脚本对复现实验很有用，但当前 `hotpatch-for-ecu-in-uds` 更需要的是把它们的协议知识提炼进硬件固件设计。
- `bms_measurement_results/`
  这些结果适合做论文或复盘参考，不是运行时资产。

## 4. RTT 日志方面可以复用什么

- 旧工程的 `Makefile` 已经显式编入：
  - `nrf_log_backend_rtt.c`
  - `nrf_log_backend_serial.c`
  - `nrf_log_default_backends.c`
- 旧工程的 `main.c` 已经调用：
  - `NRF_LOG_INIT(NULL)`
  - `NRF_LOG_DEFAULT_BACKENDS_INIT()`

这说明旧项目已经接过 `RTT backend`，不是从零开始。

但也要注意：

- 旧 BMS 代码主体仍然大量用 `printf` 和 `APP_UART`
- 它更像“UART 为主，RTT 已接入”的双通道日志状态
- 当前项目还没有一份单独整理过的“RTT-only 日志策略”

## 5. 哪些东西更应该从当前仓库拿，而不是从旧项目拿

- Session 状态机
  旧 BMS 工程没有 UDS session 语义，当前仓库 [src/hotpatch_uds/ecu.py](../../src/hotpatch_uds/ecu.py) 更完整。
- UDS Dispatcher
  旧工程只有 UART 帧分发，没有 `0x10 / 0x27 / 0x2E` 的 C 版 dispatcher。
- DID Write 的授权规则
  旧工程只有寄存器写，没有 UDS negative response 语义。
- Replay Check 的正确修复逻辑
  旧工程只会打印 `replay seq=%u (no anti-replay)`，并不会真正拒绝重放。

## 6. 不建议直接搬进当前仓库的内容

- `/home/beibei/Downloads/kintsugi_artifact_zenodo/external/sdk/nRF5_SDK_17.1.0_ddde560`
  体积太大，而且当前仓库还没正式切成固件仓库。
- `/home/beibei/Downloads/kintsugi_artifact_zenodo/external/rtos/`
  当前阶段更适合保留 patch 和入口说明，而不是把整套第三方源直接 vendoring 进来。
- `build/`、`build_user/`、`.map`、`.out`、`.hex`
  这些都是产物，不是源码资产。

## 7. 最实际的复用策略

- 板级工程从 `before_patching` 起
- FreeRTOS context-switch 钩子从 `FreeRTOS-Kernel.patch` 起
- hotpatch runtime 从 `kintsugi/include + src` 起
- Config Table 和寄存器写路径从 `MiniBMS main.c + send_bms_uart_attack.py` 起
- UDS 状态机、`0x2E` 授权规则、replay 预期行为从当前仓库 `software_level` 起
