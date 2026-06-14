# Kintsugi 接入改动记录

日期：2026-05-31

## 结论

这次接入最初阶段，`kintsugi/` 目录下导入的原始运行时源码没有被直接修改。

随后为了让 `board_baseline` 在当前工具链下干净构建，又对 `kintsugi/src` 做了极小范围的 warning 修复。这些修复不改变 hotpatch 逻辑，只修正日志格式和未使用变量。

真正改动的是 `Kintsugi` 接入点周围的外围工程文件，以及 `FreeRTOS-Kernel` 的调度切换挂点。这样做的目的，是把“上游 Kintsugi 代码”和“当前 UDS/board 环境适配层”分开，后面更容易追踪差异和同步上游。

## 未直接修改的导入内容

- `kintsugi/include/*.h`
- `kintsugi/hp_layout_freertos.ld`
- `hotpatches/freertos/sample.c`

说明：

- `hp_measure.h` 仍然被 `FreeRTOS` 和 `Kintsugi` 头文件引用，但当前没有去改它的实现逻辑。
- `measurement` 相关功能目前没有额外扩展，只是保留原有接口。

## 对 `kintsugi/src` 的直接修改

### 1. `kintsugi/src/hp_manager.c`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_manager.c](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_manager.c:60)

修改内容：

- 把 `DEBUG_LOG` 中不匹配的 `%d/%lu` 格式改成与实际参数类型一致的格式。
- 对 `header->type` 使用 `unsigned long` 打印。
- 对 `manager_result` 使用 `unsigned` 打印。

目的：

- 消除 ARM GCC 下的 `-Wformat` warning，避免后续把 warning 升级成 error 时影响构建。

### 2. `kintsugi/src/hp_slot.c`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_slot.c](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_slot.c:115)

修改内容：

- 将目标地址日志格式从 `0x%08X` 改成 `0x%08lX`，并显式转换为 `unsigned long`。

目的：

- 消除 `uint32_t` 与格式字符串不匹配的 warning。

### 3. `kintsugi/src/hp_exception.c`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_exception.c](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/kintsugi/src/hp_exception.c:19)

修改内容：

- 删除未使用的 `fault`、`hardfault` 局部变量。
- 用 `(void)SCB->ICSR;` 保留对寄存器读取的显式痕迹。
- 将 `mmfar` 的日志格式从 `0x%08X` 改成 `0x%08lX`，并显式转换为 `unsigned long`。

目的：

- 消除 `-Wunused-variable` 和 `-Wformat` warning。
- 不改变 `MemManage` 异常路径的控制流和行为。

## 实际修改的文件

### 1. `external/rtos/FreeRTOS-Kernel/tasks.c`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/external/rtos/FreeRTOS-Kernel/tasks.c](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/external/rtos/FreeRTOS-Kernel/tasks.c:44)

修改内容：

- 增加 `hp_config.h`、`hp_guard.h`、`hp_measure.h` 头文件引用。
- 在 `TCB_t` 里新增 `uxHPManager` 字段，用来标记当前 task 是否是 hotpatch manager。
- 在 `prvInitialiseNewTask()` 里，根据 `configHP_TASK_NAME` 给 task 打标。
- 在 `vTaskSwitchContext()` 里记录前一个 task 的 hotpatch manager 状态，并在任务切换后调用 `hp_guard_applicator(...)`。

目的：

- 让 `Kintsugi guard/applicator` 进入 `FreeRTOS` 的真实 context switch safe point。

### 2. `hardware level/board_baseline/FreeRTOS_gcc_nrf52.ld`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/FreeRTOS_gcc_nrf52.ld](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/FreeRTOS_gcc_nrf52.ld:60)

修改内容：

- 将 `hp_layout_freertos.ld` 的 include 路径改成当前仓库结构可用的 `../../kintsugi/hp_layout_freertos.ld`。

目的：

- 让 `__hotpatch_*`、`__ramfunc_*` 等 linker symbol 能正确落到当前工程里。

### 3. `hardware level/board_baseline/include/config/sdk_config.h`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/include/config/sdk_config.h](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/include/config/sdk_config.h:3784)

修改内容：

- 基于旧 `before_patching` 模板导入 `sdk_config.h`。
- 在文件尾部追加 board baseline override：
  - 启用 `NRFX_SPIM_ENABLED`
  - 启用 `NRFX_SPIM3_ENABLED`
  - 保留 `RTT` backend 开关
  - 补 `SEGGER_RTT` buffer 配置

目的：

- 为 `MCP2515 SPI` 和 `RTT logs` 提供最小构建配置。

### 4. `hardware level/board_baseline/Makefile`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/Makefile](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/Makefile:5)

修改内容：

- 把旧的 `HP_PROJ_DIR` 路径体系改成当前仓库的 `REPO_ROOT`。
- 新增 `APP_DIR := ../app`。
- 加入 `nrfx_spim.c`、`SEGGER_RTT.c`、`SEGGER_RTT_printf.c`。
- 加入 `hardware level/app` 下的 UDS/CAN/board adapter 源文件。
- 加入 `APP_DIR/include` 和 `external/segger_rtt` 头文件目录。
- 将 `SDK_CONFIG_FILE` 修正为 `include/config/sdk_config.h`。
- 新增：
  - `GNU_INSTALL_ROOT ?=`
  - `GNU_PREFIX ?= arm-none-eabi`

目的：

- 让 `board_baseline` 能按当前项目结构引用 SDK、RTOS、Kintsugi 和 UDS app。

### 5. `hardware level/board_baseline/include/board_baseline_config.h`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/include/board_baseline_config.h](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/include/board_baseline_config.h:12)

修改内容：

- 新增板级配置头文件。
- 定义 `nRF52840-DK <-> MCP2515` 的默认 SPI 引脚。
- 定义 `MCP2515` 默认 `CNF1/2/3`。
- 定义 `gateway external/internal request/response ID`。
- 定义 profile 选择：`secure` profile 使用 permissive/misconfigured gateway
  加 strict ECU，`vulnerable` profile 使用 permissive/misconfigured gateway 加 vulnerable
  ECU，`gateway-secure` profile 使用 restricted gateway 加 strict ECU。

目的：

- 把板级接线和 UDS 路由从 `main.c` 里抽离出来，方便后续按真实板子改。

### 6. `hardware level/board_baseline/src/main.c`

文件：[/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/src/main.c](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/hardware level/board_baseline/src/main.c:149)

修改内容：

- 引入 `board_baseline_config.h`。
- 去掉原来的占位 `MCP2515_SPI_*` / `CNF1/2/3` 默认空值。
- 修正 `nrfx_spim` 默认配置用法。
- 将运行路径从 `direct ECU` 改成：
  - `gateway task`
  - `adjacent ECU task`
  - `board adapter gateway path`
- 启动时打印 gateway route、CAN bitrate、oscillator 和 task priority。

目的：

- 让板级入口真正具备 `tester -> gateway -> adjacent ECU -> response` 这条执行路径。

## 当前状态

- `Kintsugi` 原目录大部分代码保持原样，只有 `hp_manager.c`、`hp_slot.c`、`hp_exception.c` 做了 warning 级修正。
- `FreeRTOS-Kernel/tasks.c` 已经加入 hotpatch safe-point 挂钩。
- `board_baseline` 已经具备 `MCP2515 + RTT + gateway/adjacent ECU` 的工程接线。
- `board_baseline` 已经在本机通过 `arm-none-eabi-gcc` 完整构建，并生成：
  - `build/nrf52840_xxaa.out`
  - `build/nrf52840_xxaa.hex`
  - `build/nrf52840_xxaa.bin`
- 固件已经烧录进 `nRF52840`，当前板级联调已经通过 `MCP2515` 初始化，并进入 `FreeRTOS scheduler` 和 `UDS task` 启动路径。
- 失败路径已经改成可诊断路径，不再直接进入 `APP_ERROR_CHECK`；最新实测 `g_board_mcp2515_init_status = 0`。

## 板级验证结果

### 1. 构建

- 已安装并验证 `arm-none-eabi-gcc`。
- `hardware level/board_baseline` 下 `make default` 已通过。

### 2. 烧录

- 已使用 `nrfjprog` 将 `build/nrf52840_xxaa.hex` 烧录到板子并复位。

### 3. RTT 日志

- `SEGGER_RTT` 已经链接进固件，`_SEGGER_RTT` control block 位于 RAM 中。
- `JLinkRTTLogger` 连接不稳定，但可以通过 `nrfjprog --memrd` 读取 RTT buffer。
- 最新 RTT buffer 已经打印：
  - `[BOOT] hotpatch UDS board baseline starting`
  - `[BOOT] gateway route ext=0x7E0/0x7E8 -> int=0x7E1/0x7E9 mode=2 can=1000000@16000000Hz task_prio=1`

### 4. 当前阻塞点

- `hardware level/board_baseline/src/main.c` 的 `board_diag_runtime_init()` 已经通过。
- 当前阻塞点不在 nRF/MCP2515 初始化，而在主机侧 `CANable` 权限和 `can0` 创建。
- 最新固件已经记录诊断变量：
  - `g_board_mcp2515_init_status`
  - `g_board_mcp2515_canstat`
  - `g_board_mcp2515_canctrl`
  - `g_board_mcp2515_read_status`
- 当前通过 `nrfjprog --memrd` 读到：
  - `g_board_mcp2515_init_status = 0`
  - `g_board_mcp2515_canstat = 0x00`
  - `g_board_mcp2515_canctrl = 0x07`
  - `g_board_mcp2515_read_status = 0x00`
- `0` 对应 `MCP2515_STATUS_OK`，说明 `nRF -> MCP2515` 的 SPI 初始化路径已经跑通。
- 当前还没有完成 `CANable -> MCP2515 -> gateway -> adjacent ECU -> response` 的 request 测试，原因是当前会话没有权限打开 `/dev/ttyACM2` 并创建 `can0`。
- 后续主机侧 `can0` 已能创建并发送 `7E0#0210030000000000`，但 `candump` 只看到本地发送帧，没有看到 ECU response。
- 已在 `mcp2515_can_port.c` 增加运行期诊断变量，用于读取：
  - poll 次数
  - RX 成功次数
  - no-frame 次数
  - port error 次数
  - 最近一次 `CANINTF`
  - 最近一次 `EFLG`
  - 最近一次 `TEC/REC`
- 当前基线诊断显示 `UDS task` 正在轮询 MCP2515，最近状态为 `MCP2515_STATUS_NO_FRAME`，`CANINTF=0x00`、`EFLG=0x00`、`TEC=0`、`REC=0`。
- 已增加一次性启动测试帧：
  - `BOARD_CAN_STARTUP_TEST_FRAME_ENABLED = 1`
  - 复位后延迟 1 秒发送 `7E8#0250030000000000`
  - 用于确认 `MCP2515 -> CANable` 发送方向是否能被 `candump` 看到
- 启动测试帧已经成功排队，`g_board_startup_test_tx_last_status = 0`。
- 当前 `MCP2515` 诊断显示 `CANINTF=0xA0`、`EFLG=0x15`、`TEC=0x80`、`REC=0x00`，说明发送侧进入错误状态，核心问题更接近 CAN 物理层、ACK 或 bit timing，而不是 UDS dispatcher。
- 已分别测试 `8 MHz + 1 Mbps` 和常见 `16 MHz + 1 Mbps` CNF 配置，错误状态未改善。
- 调试过程中发现 `configUSE_HP_FRAMEWORK=1` 时，FreeRTOS context switch 进入 `hp_guard_applicator()` 后发生 HardFault。
- 为了先完成 `CAN/UDS` 通讯链路 bring-up，临时将 `hardware level/board_baseline/include/config/FreeRTOSConfig.h` 中的 `configUSE_HP_FRAMEWORK` 设为 `0`。
- 这不是删除 Kintsugi 组件，而是暂时关闭 context-switch hook；链路稳定后需要单独修复 `hp_guard_applicator()` 在当前 FreeRTOS/nRF 组合下的 MPU/RAM execution 问题，再重新打开。
- 关闭 hook 后固件不再 HardFault，任务进入 idle/轮询路径；启动测试帧仍然成功排队，但 `MCP2515` 保持 `CANINTF=0xA0`、`EFLG=0x15`、`TEC=0x80`、`REC=0x00`，继续指向 CAN ACK/物理层/bit timing 问题。
- 之后将固件切到 `500 kbps` bring-up 配置：
  - `BOARD_CAN_BITRATE_BPS = 500000`
  - `BOARD_MCP2515_CNF1 = 0x00`
  - `BOARD_MCP2515_CNF2 = 0xF0`
  - `BOARD_MCP2515_CNF3 = 0x86`
- `500 kbps` 下启动测试帧仍然排队成功，但 `CANINTF=0xA0`、`EFLG=0x15`、`TEC=0x80`、`REC=0x00` 未改善。
- 结论进一步收敛为：`nRF -> MCP2515` SPI 与固件路径可用，当前问题更可能在 CAN 收发器物理层、CANable ACK、H/L 极性、共地、模块工作电平或 CANable 固件/模式。
- 已增加 `MCP2515` 内部 loopback 自检：
  - loopback 初始化状态为 `0`
  - loopback TX 状态为 `0`
  - loopback RX 状态为 `0`
  - 收到的 CAN ID 为 `0x321`
  - 收到的数据为 `02 50 03 A5 5A 00 00 00`
- 该结果证明 `nRF -> SPI -> MCP2515 controller` 路径正常，问题位于 MCP2515 控制器之后，即外部 CAN transceiver、CANH/CANL/GND、ACK、CANable 模式或物理连接。
- 根据模块实物信息，确认 CAN transceiver 为 `TJA1051T/3`，晶振为 `8 MHz`。
- 根据用户提供的可能总线速率，将固件切到 `8 MHz + 250 kbps`：
  - `BOARD_CAN_BITRATE_BPS = 250000`
  - `BOARD_MCP2515_CNF1 = 0x00`
  - `BOARD_MCP2515_CNF2 = 0xAC`
  - `BOARD_MCP2515_CNF3 = 0x03`
- `250 kbps` 下内部 loopback 仍然通过，说明 MCP2515 控制器侧配置和 SPI 路径仍然正常；外部启动测试帧仍显示无 ACK，下一步要求 CANable 使用 `slcand -s5` 同速率测试。

## 后续建议

- 如果之后要继续保持“上游 Kintsugi 代码不改”的策略，建议新增的 UDS guard 逻辑优先放在：
  - `hardware level/app`
  - `board_baseline`
  - `FreeRTOS hook`

- 只有在必须改变 `hp_guard/hp_manager` 行为时，再对 `kintsugi/src/*.c` 做最小 patch，并单独记录 patch 文件。

- 下一步优先创建 `can0` 并发送第一帧 UDS request：
  - `CANable` 设备当前为 `/dev/ttyACM2`
  - 当前会话打开 `/dev/ttyACM2` 时返回 `Permission denied`
  - 需要使用 `sudo` 或把当前用户加入 `dialout` 后重新登录
