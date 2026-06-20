# Nucleo-G474RE CAN Observer

这个工程只用于增强现有 baseline 的数据可信度，不替代当前链路：

```text
CANable2.0 / can0 -> nRF52840 + MCP2515 -> UDS ECU + Kintsugi hotpatch
```

Nucleo-G474RE + Waveshare SN65HVD230 作为独立观测节点：

```text
same CAN bus
  CANable2.0 tester
  nRF52840/MCP2515 ECU
  Nucleo-G474RE passive observer
```

## 输出格式

Nucleo 只监听 `0x7E0` 和 `0x7E8`，通过 UART 输出：

```text
MON,<timestamp_us>,<can_id_hex>,<dlc>,<data_hex>
```

示例：

```text
MON,0000012450,7E0,8,0210030000000000
MON,0000015120,7E8,8,0650030032138800
MON,0000048220,7E0,8,052E1234CAFE0000
MON,0000051130,7E8,8,037F2E3100000000
```

## 硬件连接

### FDCAN 到 SN65HVD230

推荐用 CubeMX 配置 `FDCAN1`：

```text
Nucleo PA12 / FDCAN1_TX -> Waveshare CTX/TXD
Nucleo PA11 / FDCAN1_RX -> Waveshare CRX/RXD
Nucleo 3V3              -> Waveshare VCC
Nucleo GND              -> Waveshare GND
Waveshare CANH          -> CAN bus H
Waveshare CANL          -> CAN bus L
```

如果你的 Waveshare 模块有 `RS` 引脚，把它接 GND 或按模块说明配置为高速正常模式，避免悬空。

### UART 日志

先使用 Nucleo 自带 ST-LINK VCP，后面再接 Raspberry Pi Debug Probe：

```text
USART2_TX / PA2 -> Debug Probe UART RX
GND             -> Debug Probe GND
USART2_RX / PA3 <- Debug Probe UART TX   optional
```

只采日志时，Debug Probe TX 可以不接。不要让多个外部 TX 同时驱动 Nucleo 的 `PA3`。

UART 参数：

```text
115200 8N1
```

## 总线注意事项

- Nucleo observer 必须使用 `FDCAN_MODE_BUS_MONITORING`，也就是 listen-only / silent。
- Observer 不应 ACK 或发送任何 CAN frame。
- 不要额外打开 Waveshare 模块上的 120 ohm 终端电阻，除非它确实是总线末端之一。
- 正式论文实验不要使用“Waveshare 断电但 CANH/CANL 仍挂总线”的配置。

## CubeMX 使用步骤

1. 打开 STM32CubeMX / STM32CubeIDE。
2. New Project，选择 `NUCLEO-G474RE`。
3. 按 [cubemx_settings_zh.md](./cubemx_settings_zh.md) 配置 FDCAN1 和 USART2。
4. 生成工程。
5. 把 [Core/Inc/can_observer_user.h](./Core/Inc/can_observer_user.h) 和 [Core/Src/can_observer_user.c](./Core/Src/can_observer_user.c) 拷入 CubeMX 生成工程。
6. 在生成的 `Core/Src/main.c` 里加入：

```c
/* USER CODE BEGIN Includes */
#include "can_observer_user.h"
/* USER CODE END Includes */
```

在 `MX_FDCAN1_Init();` 和 `MX_USART2_UART_Init();` 之后加入：

```c
/* USER CODE BEGIN 2 */
can_observer_init();
/* USER CODE END 2 */
```

在 `while (1)` 中加入：

```c
/* USER CODE BEGIN WHILE */
while (1)
{
  can_observer_poll_uart();
/* USER CODE END WHILE */

/* USER CODE BEGIN 3 */
}
/* USER CODE END 3 */
```

## 采集日志

Nucleo 自带 ST-LINK VCP 或 Raspberry Pi Debug Probe 都会显示成 `/dev/serial/by-id/...`：

```bash
ls -l /dev/serial/by-id
stty -F /dev/serial/by-id/<nucleo-or-debug-probe-uart> 115200 raw -echo
cat /dev/serial/by-id/<nucleo-or-debug-probe-uart> | tee "software level/charts/nucleo_can_monitor_latest.log"
```

转 CSV：

```bash
python3 "software level/tools/parse_nucleo_can_monitor_log.py" \
  --log "software level/charts/nucleo_can_monitor_latest.log" \
  --csv "software level/charts/nucleo_can_monitor_latest.csv"
```

