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

当前默认固件使用 CubeMX 中的 `FDCAN1 PB8/PB9`：

```text
Nucleo PB9 / FDCAN1_TX -> Waveshare CTX/TXD
Nucleo PB8 / FDCAN1_RX -> Waveshare CRX/RXD
Nucleo 3V3              -> Waveshare VCC
Nucleo GND              -> Waveshare GND
Waveshare CANH          -> CAN bus H
Waveshare CANL          -> CAN bus L
```

如果改用 `PA11/PA12`，连接为 `PA12/FDCAN1_TX -> CTX/TXD`、`PA11/FDCAN1_RX -> CRX/RXD`，并用 `make FDCAN_PINS=PA11_PA12` 重新编译烧录。

默认 bitrate 是 `250000`，和当前 nRF/MCP2515 baseline 一致。如果整条 CAN bus 都切到 `500000`，Nucleo 也可以用 `make FDCAN_BITRATE=500000 ...` 重新编译。不要让 Nucleo 单独使用 500 kbit/s 去监听 250 kbit/s 总线。

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

- 正式 passive observer 优先使用 `FDCAN_MODE=BUS_MONITORING`，也就是 listen-only / silent。
- 硬件 bring-up 可以临时使用 `FDCAN_MODE=NORMAL`，用于确认 PB8/PB9、transceiver、bitrate 和 filter 都能收到帧。
- Observer 不应主动发送任何 CAN frame；`NORMAL` bring-up 模式可能参与 ACK，因此不要把它作为最终 passive 论文实验配置。
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

当前已验证的接收路径是 FIFO polling。接 Raspberry Pi Debug Probe 或使用板载 ST-LINK VCP 采日志前，建议先烧录 polling UART 版本：

```bash
cd "hardware level/nucleo_g474re_can_observer"
make clean
make CAN_POLL_UART=1 FDCAN_MODE=NORMAL FDCAN_BITRATE=250000 flash
```

如果 `NORMAL` polling UART 已经能稳定输出 `MON` 日志，再切换为正式 passive 配置复测：

```bash
make clean
make CAN_POLL_UART=1 FDCAN_MODE=BUS_MONITORING FDCAN_BITRATE=250000 flash
```

Nucleo 自带 ST-LINK VCP 或 Raspberry Pi Debug Probe 都会显示成 `/dev/serial/by-id/...`：

```bash
ls -l /dev/serial/by-id
stty -F /dev/serial/by-id/<nucleo-or-debug-probe-uart> 115200 raw -echo
cat /dev/serial/by-id/<nucleo-or-debug-probe-uart> | tee "software level/charts/nucleo_can_monitor_latest.log"
```

也可以用仓库脚本在采集时自动触发若干个 can0 请求：

```bash
python3 "software level/tools/capture_nucleo_can_monitor.py" \
  --serial /dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_0034002C3235511437333439-if02 \
  --duration 4 \
  --send-requests 5 \
  --log "software level/charts/nucleo_can_monitor_latest.log"
```

转 CSV：

```bash
python3 "software level/tools/parse_nucleo_can_monitor_log.py" \
  --log "software level/charts/nucleo_can_monitor_latest.log" \
  --csv "software level/charts/nucleo_can_monitor_latest.csv"
```
