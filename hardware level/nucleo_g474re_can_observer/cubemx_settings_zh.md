# CubeMX 配置：NUCLEO-G474RE Passive CAN Observer

这个配置的目标是只监听外部 CAN bus 上的 UDS frame：

```text
0x7E0 tester request
0x7E8 ECU response
```

## Project

```text
Board selector: NUCLEO-G474RE
Toolchain/IDE: STM32CubeIDE
Firmware package: STM32Cube FW_G4
Generate peripheral initialization as a pair of .c/.h files: enabled
```

## Clock

为了让 CAN timing 简单，建议先用默认 HSI 16 MHz，不需要外部晶振：

```text
SYSCLK: 16 MHz
HCLK:   16 MHz
PCLK1:  16 MHz
FDCAN kernel clock: 16 MHz / PCLK1
```

如果你后面用 80 MHz 或 170 MHz 系统时钟，也可以，但要重新计算 FDCAN nominal timing。

## FDCAN1

Pins:

```text
PA11 -> FDCAN1_RX
PA12 -> FDCAN1_TX
```

Mode:

```text
Frame Format: Classic mode
Mode: Bus Monitoring / Listen Only
Auto Retransmission: disabled
Transmit Pause: disabled
Protocol Exception: enabled
```

Nominal bit timing for 250 kbps with 16 MHz FDCAN clock:

```text
Nominal Prescaler: 4
Nominal Sync Jump Width: 2
Nominal Time Seg1: 13
Nominal Time Seg2: 2
```

Explanation:

```text
bitrate = 16 MHz / (4 * (1 + 13 + 2)) = 250000 bit/s
sample point = (1 + 13) / (1 + 13 + 2) = 87.5%
```

Data bit timing is unused in classic CAN. Set it to a valid conservative value if CubeMX requires it.

NVIC:

```text
FDCAN1 interrupt line 0: enabled
```

Filters are installed by `can_observer_init()` in user code:

```text
standard ID dual filter: 0x7E0 and 0x7E8 -> RX FIFO0
global filter: reject non-matching standard and extended frames
```

## USART2

Use the Nucleo ST-LINK VCP first. Raspberry Pi Debug Probe can later tap the same TX pin.

Pins:

```text
PA2 -> USART2_TX
PA3 -> USART2_RX
```

Parameters:

```text
Mode: Asynchronous
Baud rate: 115200
Word length: 8 bits
Parity: None
Stop bits: 1
Hardware flow control: None
```

DMA is not required.

## User Code Integration

After code generation, add:

```c
#include "can_observer_user.h"
```

Then after `MX_FDCAN1_Init();` and `MX_USART2_UART_Init();`:

```c
can_observer_init();
```

Inside the main loop:

```c
can_observer_poll_uart();
```

