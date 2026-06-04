# UDS 服务安全语义适配出处记录

日期：2026-06-04

## 适配范围

本次只补全硬件 C 固件中的 UDS 服务语义，不引入第三方 UDS 源码：

- `0x10 DiagnosticSessionControl`
- `0x27 SecurityAccess`
- `0x2E WriteDataByIdentifier`

代码位置：

- `hardware level/app/include/uds_protocol.h`
- `hardware level/app/include/uds_dispatcher.h`
- `hardware level/app/src/uds_dispatcher.c`
- `software level/tools/uds_security_baseline_test.py`

## 参考来源

### 1. driftregion/iso14229

来源：

```text
https://driftregion.github.io/iso14229/services.html
https://github.com/driftregion/iso14229
```

采用点：

- `0x10` 是 session 切换服务，常见 session 包括 default `0x01` 和 extended `0x03`。
- `0x10` 正响应可携带 P2 / P2* timing 信息。
- `0x27` 分为 request seed 和 validate key 两个事件/阶段。
- `0x2E` 的典型 NRC 包括：
  - `0x13` incorrect message length or invalid format
  - `0x22` conditions not correct
  - `0x31` request out of range
  - `0x33` security access denied

适配方式：

- 没有复制该项目源码。
- 保留本项目自己的轻量 dispatcher。
- 将 `0x10` positive response 从只返回 session type 扩展为：

```text
50 <session> <P2_hi> <P2_lo> <P2*_hi> <P2*_lo>
```

当前值：

```text
P2 = 50 ms = 0x0032
P2* = 5000 ms = 0x1388
```

### 2. openxc/uds-c

来源：

```text
https://github.com/openxc/uds-c
```

采用点：

- UDS 协议层与 CAN 发送/接收层解耦。
- 底层 CAN 通过项目自己的 adapter 注入，而不是把 UDS service handler 和 CAN driver 绑死。

适配方式：

- 本项目继续保留：
  - `uds_protocol.c`：UDS payload 编解码
  - `uds_link.c`：single-frame ISO-TP / CAN frame 包装
  - `uds_gateway.c`：gateway policy
  - `uds_dispatcher.c`：服务状态机
  - `mcp2515_can_port.c`：MCP2515 CAN I/O

### 3. ex7l0it/uds-server-simulator-esp32

来源：

```text
https://github.com/ex7l0it/uds-server-simulator-esp32
```

采用点：

- ECU 配置里把 DID 按 security requirement 分类。
- `0x2E WriteDataByIdentifier` 不是全局允许，而是根据 DID 配置决定是否需要 security access。

适配方式：

- 本项目在 `uds_config_entry_t` 中加入：
  - `required_security_level`
  - `min_write_length`
  - `max_write_length`
- 当前 DID `0x1234` 配置为：

```text
requires_extended_session = true
requires_security_unlock = true
required_security_level = 0x01
min_write_length = 1
max_write_length = 4
```

### 4. nickdaria/udslib

来源：

```text
https://github.com/nickdaria/udslib
```

采用点：

- UDS session、lookup table、security access 应作为协议语义层，不应依赖某个传输协议。

适配方式：

- 本项目未引入该框架。
- 保留当前 `uds_dispatcher_t` 内部状态：
  - session state
  - security state
  - config table
  - replay guard

## 本次新增/调整的安全语义

### `0x10 DiagnosticSessionControl`

补全：

- 支持 default session `0x01`
- 支持 extended diagnostic session `0x03`
- 正响应返回 session timing
- session 变化时清除 unlock 状态和 pending seed

### `0x27 SecurityAccess`

补全：

- 按 UDS subfunction 奇偶规则区分：
  - odd：request seed
  - even：send key
- 当前只支持 security level `0x01`
- key 仍为论文实验用 demo 算法：

```text
key = seed ^ 0xA55A
```

新增 NRC：

- `0x35` invalid key
- `0x36` exceed number of attempts
- `0x37` required time delay not expired

说明：

- 这仍不是生产级加密协议。
- 当前目标是为 hotpatch 实验提供可控的 baseline security state machine。

### `0x2E WriteDataByIdentifier`

补全：

- DID 不存在或不可写：`0x31`
- session 不满足：`0x22`
- security level 不满足：`0x33`
- 写入长度不满足 DID 策略：`0x13`
- 合法写入后记录 replay guard 信息

## License/引用说明

本次没有复制以上开源项目的源码，只参考公开文档、README 和服务设计方式，重新实现到本项目轻量 C dispatcher 中。论文中可以把这些项目列为 engineering references，而不是 vendored dependency。
