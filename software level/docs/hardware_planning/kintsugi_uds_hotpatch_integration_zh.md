# Kintsugi UDS Hotpatch Integration

这份文件只回答两个问题：

1. 为了把 `attack entry -> ECU -> Kintsugi hotpatch` 这条链接起来，旧 `Kintsugi` 里到底要引哪些组件。
2. 在当前仓库里，这些组件现在被放到了什么位置，以及 software / hardware 如何分离。

## 1. 必须带进来的 Kintsugi 组件

### RTOS hook 层

- `external/patches/FreeRTOS-Kernel.patch`
- `example_rtos_integration/freertos/tasks.c`
- `experiments/security/before_patching/include/config/FreeRTOSConfig.h`

用途：

- 把 hotpatch applicator 接进 `FreeRTOS` 的 context-switch safe point
- 标识 `HP manager task`
- 给 guard 提供“何时可以切 patch”的最小调度钩子

### Kintsugi core runtime

- `kintsugi/include/hp_manager.h`
- `kintsugi/include/hp_guard.h`
- `kintsugi/include/hp_applicator.h`
- `kintsugi/include/hp_slot.h`
- `kintsugi/include/hp_code.h`
- `kintsugi/src/hp_manager.c`
- `kintsugi/src/hp_guard.c`
- `kintsugi/src/hp_applicator.c`
- `kintsugi/src/hp_slot.c`
- `kintsugi/src/hp_code.c`

用途：

- quarantine / slot / validation / scheduling
- guard / applicator
- patch storage 与 patch lifecycle

### Memory protection / fault handling

- `kintsugi/include/hp_freertos_mpu.h`
- `kintsugi/include/hp_exception.h`
- `kintsugi/src/hp_freertos_mpu.c`
- `kintsugi/src/hp_exception.c`
- `kintsugi/hp_layout_freertos.ld`

用途：

- 把 hotpatch code/slot/context/quarantine 区分成独立内存区
- 用 `MPU + MemManage` 拦截非法写
- 把攻击阻挡变成可观察事件

### Board/build wiring

- `experiments/security/before_patching/Makefile`
- `experiments/security/before_patching/include/hp_config.h`

用途：

- 把 `nRF5 SDK`、`FreeRTOS`、`Kintsugi`、`RTT/UART` 和链接脚本串起来

## 2. 可以只拿语义、不必整块搬入的内容

- `experiments/security/before_patching/src/main.c`
  这里适合拿任务初始化顺序、`APP_UART` 和 `RTT` 接线方式，不适合整文件照搬。
- `bms_threads_scripts/send_bms_uart_attack.py`
  适合继续作为 host-side 攻击注入脚本。
- `BMS_REG_*`、`g_bms_thresholds`、`g_bms_calibration`
  适合提炼成你当前项目的 `Config Table` 和 `DID` 下游写入对象。

## 3. 当前仓库里的落点

### 3.1 software level 保持独立

- 当前 Python baseline 的主工作区在 `software level/src/`、`software level/tests/`、`software level/charts/`
- 另外单独保留了一份归档副本在 `software level/archive/`

这意味着：

- 现有 Python 代码不会因为 hardware 工作继续被混改
- hardware 只复用 Python 里已经明确的状态机语义和方法

### 3.2 hardware C 组件现在单独放在这里

当前代码位置是：

- `hardware level/third_party/kintsugi_minimal/`
  放复制进来的 Kintsugi C 组件
- `hardware level/board_baseline/`
  放 `before_patching` 提取出来的板级入口
- `hardware level/app/`
  预留给后续你自己的 ECU firmware C 模块

对应说明文档不再放进 `hardware level/`，而是统一放在 `software level/docs/hardware_planning/`，例如：

- [app_layout_zh.md](app_layout_zh.md)
- [kintsugi_minimal_bundle_zh.md](kintsugi_minimal_bundle_zh.md)
- [uds_security_contract_zh.md](uds_security_contract_zh.md)

### 3.3 measurement 目前没有带进来

- 没有复制 `hp_measure.h`
- 没有复制 `hp_measure.c`
- 已经从本地复制版 `hp_manager.c`、`tasks.c`、`FreeRTOS-Kernel.patch` 里去掉了对 `hp_measure.h` 的直接依赖

## 4. 对你当前目标的直接建议

如果你的主线是：

- 先把攻击入口打到 ECU
- 再在 ECU 侧挂 `Kintsugi hotpatch`
- 最后修改 guard 规则适配诊断环境

那最小引入集合应当是：

1. `FreeRTOS-Kernel.patch` / `tasks.c`
2. `hp_manager + hp_guard + hp_applicator + hp_slot + hp_code`
3. `hp_freertos_mpu + hp_exception + hp_layout_freertos.ld`
4. `before_patching/Makefile + FreeRTOSConfig.h + hp_config.h`

不必先把：

- `measurement_results/`
- `realworld_cves/`
- `zephyr/`
- 整套 `external/sdk`

全部搬进当前仓库。

## 5. 当前还没在仓库里自动做的事

- 还没有把 `nRF5 SDK` 和 `FreeRTOS` 第三方源码真正 vendoring 进来
- 还没有把 `app/` 里的 `UDS dispatcher / config table / replay check` C 源补出来
- 还没有把 `DID Write` 和板上的 `Config Table` 真的翻译成 C

如果你下一步要我继续，我应该直接做的是：

1. 在 `hardware level/app/` 里起 `Config Table + UDS dispatcher + replay check` 的 C 骨架
2. 把 [uds_security_contract_zh.md](uds_security_contract_zh.md) 翻译成头文件接口和状态机枚举
3. 再决定具体是 `UART bridge` 还是后续 `CAN/ISO-TP` 先接进板子
