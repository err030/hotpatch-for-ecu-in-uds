# Nucleo-G474RE 独立 CAN 观测节点计划

## 目标

不要替换当前 baseline：

```text
CANable2.0 / can0 -> nRF52840 + MCP2515 -> UDS ECU + Kintsugi hotpatch
```

Nucleo-G474RE + Waveshare SN65HVD230 只作为增强可信度的独立节点：

```text
same CAN bus
  CANable2.0 tester
  nRF52840 ECU
  Nucleo-G474RE passive monitor
```

论文中要证明的不是“又做了一个 ECU”，而是：

- 主机 `can0` timeline 观察到的请求/响应；
- 独立 MCU 监听节点也观察到同一组 CAN frame；
- hotpatch 前 `0x2E` 写入成功，hotpatch 后 `0x2E` 返回 `7F2E31`；
- 正常诊断请求仍然通过。

## 推荐阶段

### Stage 1：Nucleo passive CAN monitor

这是最推荐、风险最低、最适合论文的增强实验。

Nucleo 只监听 CAN，不发送任何攻击请求。每收到一帧，通过 UART 输出：

```text
MON,<timestamp_us>,<can_id_hex>,<dlc>,<data_hex>
```

示例：

```text
MON,0000123456,7E0,8,0210030000000000
MON,0000126123,7E8,8,06500300321388
MON,0000168001,7E0,8,062E1234CAFE0000
MON,0000171204,7E8,8,037F2E3100000000
```

论文价值：

```text
Host SocketCAN log and an independent MCU monitor observed the same UDS exchange.
```

### Stage 2：Nucleo as second tester

只有 Stage 1 稳定后再做。

Nucleo 改成主动发送同一条攻击链：

```text
0x10 03
0x27 01
0x27 02 <key>
0x2E 1234 CAFE
0x22 1234
```

论文价值：

```text
The attack chain is not specific to the Python/CANable toolchain.
```

这一步不是必须。当前论文最缺的是独立观测证据，不是第二套攻击器。

## 硬件连接

### CAN 总线

Waveshare SN65HVD230 模块通常有：

```text
VCC   -> 3.3 V
GND   -> common ground
CTX/TXD -> MCU FDCAN_TX
CRX/RXD -> MCU FDCAN_RX
CANH  -> CAN bus H
CANL  -> CAN bus L
```

必须共地：

```text
Nucleo GND
SN65HVD230 GND
nRF/MCP2515 CAN module GND
CANable GND
```

Nucleo-G474RE 的 FDCAN 引脚请用 STM32CubeMX 对 `FDCAN1` 选择可用 pin。
常见候选是 `PA11/PA12` 或 `PB8/PB9` 一类 alternate-function 组合，但以
CubeMX 对 Nucleo-G474RE board package 显示为准。

### UART 日志

Raspberry Pi Debug Probe 的 UART 口用于采集 Nucleo 日志：

```text
Probe GND -> Nucleo GND
Probe RX  -> Nucleo UART_TX
Probe TX  -> Nucleo UART_RX   optional
```

如果只打印日志，`Probe TX -> Nucleo RX` 可以不接。

建议 UART 参数：

```text
115200 8N1
```

日志量大时可以提高到：

```text
921600 8N1
```

## Nucleo firmware 要点

用 STM32CubeIDE / CubeMX 建最小工程即可：

- Board：`NUCLEO-G474RE`
- Peripheral：`FDCAN1`
- Mode：classic CAN, normal mode
- Bitrate：`250 kbps`
- Filter：accept all standard IDs
- UART：一个可接到 Raspberry Pi Debug Probe 的 USART
- Timer：`TIM2` 或 DWT cycle counter，提供 microsecond timestamp

当前仓库已经新增 observer 工程骨架：

```text
hardware level/nucleo_g474re_can_observer/
```

入口文档：

```text
hardware level/nucleo_g474re_can_observer/README_zh.md
hardware level/nucleo_g474re_can_observer/cubemx_settings_zh.md
```

CubeMX 生成工程后，把下面两个用户代码文件加入工程：

```text
hardware level/nucleo_g474re_can_observer/Core/Inc/can_observer_user.h
hardware level/nucleo_g474re_can_observer/Core/Src/can_observer_user.c
```

FDCAN 接收 filter 建议：

```text
standard ID
filter type: mask
filter ID1: 0x000
filter ID2: 0x000
action: FIFO0
```

也就是接收所有 standard ID。

只需要记录这些 ID：

```text
0x7E0  external tester request
0x7E8  external ECU response
0x7E1  internal gateway request, 如果接在外部总线通常看不到
0x7E9  internal gateway response, 如果接在外部总线通常看不到
```

当前真实外部 CAN bus 上主要应看到：

```text
7E0#...
7E8#...
```

## 实验步骤

### 1. 保持现有 baseline

不要改变 nRF firmware 主线。继续使用：

```bash
make -C "hardware level/board_baseline" kintsugi-runtime
nrfjprog -f nrf52 --program "hardware level/board_baseline/build/nrf52840_xxaa.hex" --sectorerase --verify
nrfjprog -f nrf52 --reset
```

CANable：

```bash
sudo pkill slcand
sudo ip link delete can0
sudo slcand -o -f -s5 /dev/serial/by-id/usb-Openlight_Labs_CANable2_b158aa7_github.com_normaldotcom_canable2.git_20A036913945-if00 can0
sudo ip link set up can0
```

`-s5` 对应 `250 kbps`，和当前 `8 MHz MCP2515 / 250 kbps` 配置匹配。

### 2. 启动 Nucleo monitor log

找到 Raspberry Pi Debug Probe UART：

```bash
ls -l /dev/serial/by-id
```

假设 UART 是：

```text
/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe_...-if00
```

采集日志：

```bash
stty -F /dev/serial/by-id/<debug-probe-uart> 115200 raw -echo
cat /dev/serial/by-id/<debug-probe-uart> | tee "software level/charts/nucleo_can_monitor_latest.log"
```

如果用 921600：

```bash
stty -F /dev/serial/by-id/<debug-probe-uart> 921600 raw -echo
```

### 3. 采 hotpatch 前真实 timeline

```bash
nrfjprog -f nrf52 --reset
python3 "software level/tools/measure_can0_request_timeline.py" \
  --interface can0 \
  --timeout 0.5 \
  --inter-step-delay-ms 20 \
  --csv "software level/charts/can0_request_timeline_latest.csv" \
  --pdf "software level/thesis_figures/pdf/fig12_can0_request_timeline_real_latest.pdf" \
  --title "Real CAN0 UDS Request Timeline Before Hotpatch"
```

预期：

```text
2E1234CAFE -> 6E1234
221234     -> 621234CAFE
```

### 4. 采 Kintsugi hotpatch 后真实 timeline

```bash
nrfjprog -f nrf52 --reset
python3 "software level/tools/measure_can0_request_timeline.py" \
  --interface can0 \
  --timeout 0.5 \
  --inter-step-delay-ms 20 \
  --trigger-kintsugi-hotpatch \
  --csv "software level/charts/can0_request_timeline_kintsugi_after_latest.csv" \
  --pdf "software level/thesis_figures/pdf/fig12_can0_request_timeline_real_kintsugi_after.pdf" \
  --title "Real CAN0 UDS Request Timeline After Kintsugi Hotpatch"
```

预期：

```text
2EF19001   -> 6EF190
2702....   -> 6702
2E1234CAFE -> 7F2E31
221234     -> 621234
```

### 5. 对齐三份证据

最终应有：

```text
software level/charts/can0_request_timeline_latest.csv
software level/charts/can0_request_timeline_kintsugi_after_latest.csv
software level/charts/nucleo_can_monitor_latest.log
software level/thesis_figures/pdf/fig12_can0_request_timeline.pdf
```

论文中可以写：

```text
The SocketCAN tester log and an independent Nucleo-G474RE CAN monitor log
showed the same request-response sequence. Before hotpatching, the authorized
0x2E write returned a positive response and the DID readback contained CAFE.
After triggering the Kintsugi hotpatch, SecurityAccess still completed, but the
same 0x2E write returned NRC 0x31 and the readback remained unchanged.
```

## 结果表建议

| Evidence source | Before hotpatch | After Kintsugi hotpatch | Role |
|---|---|---|---|
| Python SocketCAN CSV | `0x2E -> 6E1234` | `0x2E -> 7F2E31` | tester-side ground truth |
| Nucleo passive monitor | observes `7E0/7E8` frames | observes `7E0/7E8` frames | independent bus observer |
| nRF board trace / diagnostics | optional | optional | ECU-local explanation |

## 不建议现在做的事

- 不要把 Nucleo 改成 gateway ECU。
- 不要用 Nucleo 替代 nRF baseline。
- 不要同时引入 CAN-FD；当前实验是 classic CAN + single-frame ISO-TP。
- 不要让 Nucleo monitor 和 CANable tester 同时发送，除非进入 Stage 2。

## 当前项目中最合适的论文表述

```text
The additional Nucleo-G474RE node was used only as an independent CAN-bus
observer. It did not replace the nRF52840 ECU baseline. This separation reduces
the risk that the reported request-response sequence is an artifact of the
SocketCAN tester implementation.
```
