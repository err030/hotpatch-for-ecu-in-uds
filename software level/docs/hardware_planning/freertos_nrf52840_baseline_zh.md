# FreeRTOS nRF52840 Baseline

如果现在就要在板子上开始做，最合适的起点是旧项目：

- `/home/beibei/Downloads/kintsugi_artifact_zenodo/experiments/security/before_patching`

## 为什么选它

- 它已经能在 `nRF52840-DK` 上编译和启动
- 它已经接入 `FreeRTOS`
- 它已经把 `Kintsugi` manager / MPU 初始化串起来了
- 它已经有 `APP_UART` 和 `RTT backend`
- 它的任务集合比 `during_patching`、`after_patching` 更接近 clean baseline

## 起工程时优先保留的文件

- `Makefile`
- `include/config/FreeRTOSConfig.h`
- `include/hp_config.h`
- `FreeRTOS_gcc_nrf52.ld`
- `src/main.c` 里的初始化顺序

## 建议保留的初始化顺序

1. `hp_manager_init()`
2. `hp_mpu_init()`
3. `nrf_drv_clock_init()`
4. `NRF_LOG_INIT(NULL)` 和 `NRF_LOG_DEFAULT_BACKENDS_INIT()`
5. `APP_UART_FIFO_INIT(...)`
6. 创建 BMS/UDS 业务任务
7. 创建 `task_hp_manager`
8. `vTaskStartScheduler()`

## 现在不建议直接做的事

- 不建议把整个 `external/sdk` 和 `external/rtos` 直接拷到当前仓库
- 不建议直接从 `during_patching` 或 `after_patching` 起工程
- 不建议先写大而全的 UDS 固件，再去补最基本的 board bring-up

先把 `nRF52840 + FreeRTOS + RTT/UART + task_hp_manager` 这个壳子稳定住，再接 UDS 语义更稳。
