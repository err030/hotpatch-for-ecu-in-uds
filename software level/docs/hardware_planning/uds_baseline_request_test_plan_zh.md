# UDS Baseline 请求测试计划

日期：2026-06-02

## 当前目标

先不接入 Kintsugi hotpatch，验证 `CANable -> gateway -> adjacent ECU -> UDS dispatcher -> response` 的 baseline 行为。

当前硬件配置：

- `MCP2515` 晶振：`8 MHz`
- CAN bitrate：`250 kbps`
- CANable slcan 参数：`-s5`
- tester request CAN ID：`0x7E0`
- tester response CAN ID：`0x7E8`
- gateway internal request CAN ID：`0x7E1`
- gateway internal response CAN ID：`0x7E9`

## 基础启动

```bash
sudo pkill slcand
sudo ip link delete can0
sudo slcand -o -f -s5 /dev/serial/by-id/usb-Openlight_Labs_CANable2_b158aa7_github.com_normaldotcom_canable2.git_20A036913945-if00 can0
sudo ip link set up can0
candump -L can0
```

`ip link delete can0` 如果提示设备不存在，可以忽略。

## `vcan0` 和 CANable2.0 / `can0` 的边界

- `vcan0` 只用于主机上的软件回归测试：`tests.test_socketcan` 和
  `tests.test_pythoncan` 会把 mock ECU / gateway 挂到 Linux virtual CAN。
- CANable2.0 发真实 CAN frame 时不走 `vcan0`，而是走真实 SocketCAN 设备，
  本计划默认接口名为 `can0`。
- 如果 CANable2.0 使用 `slcan` 固件，按上面的 `slcand -s5 ... can0` 拉起；
  `-s5` 对应当前板端配置的 `250 kbps`。
- 如果 CANable2.0 使用 candleLight / `gs_usb` 固件，通常会直接枚举成
  SocketCAN 设备，再用 `sudo ip link set can0 type can bitrate 250000` 和
  `sudo ip link set up can0` 拉起。

按 nRF reset 后，固件会主动发启动测试帧：

```text
7E8#0250030000000000
```

## 普通请求

### 1. 进入 extended session

请求：

```bash
cansend can0 7E0#0210030000000000
```

预期响应：

```text
7E8#06500300321388
```

含义：

- `0x10 0x03`：请求进入 extended diagnostic session
- `0x50 0x03`：正响应
- `0x0032`：P2 server max，50 ms
- `0x1388`：P2* server max，5000 ms

### 2. 请求 seed

请求：

```bash
cansend can0 7E0#0227010000000000
```

预期响应：

```text
7E8#04670112XX000000
```

其中 `XX` 是递增 seed 低字节。第一轮通常是 `0x01`，即 seed `0x1201`。

### 3. 发送正确 key

key 计算当前是 demo 逻辑：

```text
key = seed ^ 0xA55A
```

如果 seed 是 `0x1201`，key 是 `0xB75B`。

请求：

```bash
cansend can0 7E0#042702B75B000000
```

预期响应：

```text
7E8#0267020000000000
```

### 4. 授权 DID Write

当前可写 DID 是 `0x1234`。

请求：

```bash
cansend can0 7E0#062E1234AABB0000
```

预期响应：

```text
7E8#036E123400000000
```

### 5. 读回 DID

写入 `0x1234` 后，可以用 `0x22 ReadDataByIdentifier` 读回当前值：

```bash
cansend can0 7E0#0322123400000000
```

如果上一步写入 `AABB`，预期响应：

```text
7E8#05621234AABB0000
```

当前还提供一个只读状态 DID `0x1001`：

```bash
cansend can0 7E0#0322100100000000
```

预期响应：

```text
7E8#0562100142100000
```

## 恶意请求和拦截

### 1. 默认 session 下直接 DID Write

请求：

```bash
cansend can0 7E0#062E1234AABB0000
```

预期响应：

```text
7E8#037F2E2200000000
```

含义：

- `0x7F`：negative response
- `0x2E`：原始服务
- `0x22`：conditions not correct

### 2. extended session 但未解锁直接 DID Write

先进入 extended session：

```bash
cansend can0 7E0#0210030000000000
```

再直接写 DID：

```bash
cansend can0 7E0#062E1234AABB0000
```

预期响应：

```text
7E8#037F2E3300000000
```

含义：

- `0x33`：security access denied

### 3. 错误 key

请求 seed：

```bash
cansend can0 7E0#0227010000000000
```

发送错误 key：

```bash
cansend can0 7E0#0427020000000000
```

预期响应：

```text
7E8#037F273500000000
```

连续错误达到阈值后会进入短暂 lockout。

含义：

- `0x35`：invalid key
- 达到错误阈值时返回 `0x36`：exceed number of attempts
- lockout 未结束时返回 `0x37`：required time delay not expired

### 4. replay write

当前 `strict` policy 下，replay 不允许绕过 unlock。

先完成一次合法 unlock 和 DID write，再改变 session 或清除 unlock 后，重复同一个 write。预期仍应返回：

```text
7E8#037F2E2200000000
```

如果 replay 发生在仍处于 extended session 但 security unlock 已清除的状态，预期是：

```text
7E8#037F2E3300000000
```

如果 replay 发生在已经回到 default session 的状态，预期是：

```text
7E8#037F2E2200000000
```

## 自动化 baseline 安全测试

新增脚本：

```text
software level/tools/uds_security_baseline_test.py
```

使用前先确认 `can0` 已经按 `250 kbps` 拉起：

```bash
sudo pkill slcand
sudo ip link delete can0
sudo slcand -o -f -s5 /dev/serial/by-id/usb-Openlight_Labs_CANable2_b158aa7_github.com_normaldotcom_canable2.git_20A036913945-if00 can0
sudo ip link set up can0
```

运行测试：

```bash
python3 "software level/tools/uds_security_baseline_test.py" --interface can0
```

脚本会自动执行：

- reset 到 default session
- default session 下直接 `0x2E` 写入，期望 `0x7F 0x2E 0x22`
- extended session 下未解锁 `0x2E` 写入，期望 `0x7F 0x2E 0x33`
- 读取只读 DID `0x1001`，期望 `0x62 0x10 0x01 0x42 0x10`
- 对只读 DID `0x1001` 执行 `0x2E`，期望 `0x7F 0x2E 0x31`
- 请求 seed 后发送错误 key，期望 `0x7F 0x27 0x35`
- 第二次错误 key 触发 attempt limit，期望 `0x7F 0x27 0x36`
- lockout 期间请求 seed，期望 `0x7F 0x27 0x37`
- 请求 seed 后计算 demo key，期望 `0x67 0x02`
- 解锁后合法 DID write，期望 `0x6E 0x12 0x34`
- 读回刚写入的 DID `0x1234`，期望 `0x62 0x12 0x34 ...`
- session reset 后重放同一个 DID write，期望再次被拒绝

测试结果会打印到终端，并写入：

```text
software level/charts/hardware_baseline_security_latest.csv
```

2026-06-11 实测结果：CANable2.0 / `can0` 到 nRF52840 baseline 全部通过，
`19/19` 个 security baseline 检查为 `PASS`。

这个 CSV 可作为“不加入 hotpatch 时 baseline 拦截结果”的实验记录。

## CVE-derived UDS 攻击测试

选择依据见：

```text
software level/docs/hardware_planning/cve_attack_selection_for_uds_hotpatch_zh.md
```

新增脚本：

```text
software level/tools/cve_derived_uds_attack_test.py
```

运行：

```bash
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0
```

当前测试不是声称本 ECU 真实存在对应 CVE，而是把 Kintsugi real-world CVE 实验中的输入校验 bug class 映射到本项目 UDS-over-CAN 攻击面：

- `CVE-2020-17443-derived`：短报文长度检查，发送缺少 subfunction 的 `0x10`
- `CVE-2018-16603-derived`：短底层 packet 导致越界访问，发送 PCI length 大于实际 CAN DLC 的 malformed single frame
- `CVE-2018-16524-derived`：选项长度越界检查，映射为授权后 `0x2E DID Write` 的零长度 data

结果会写入：

```text
software level/charts/cve_derived_uds_attack_latest.csv
```

2026-06-11 实测结果：`6/6` 个 CVE-derived UDS attack 检查为 `PASS`。

## Gateway 模式

当前板级配置是：

```text
UDS_GATEWAY_MODE_MISCONFIGURED
```

它允许：

- `0x10` DiagnosticSessionControl
- `0x22` ReadDataByIdentifier
- `0x27` SecurityAccess
- `0x2E` WriteDataByIdentifier

后续为了展示 gateway 拦截，可以切到：

```text
UDS_GATEWAY_MODE_RESTRICTED
```

此时 `0x22` 仍允许通过，`0x2E` 应在 gateway 层被阻断，不进入 adjacent ECU。

## 加密/认证协议说明

当前 `0x27` 是 demo seed/key：

```text
key = seed ^ 0xA55A
```

这不是安全加密协议，只适合作为论文实验里的可控 baseline。后续应补成：

- per-session nonce
- ECU secret 派生 key
- freshness counter 或 monotonic challenge
- replay window
- lockout 和失败次数持久化策略

在 hotpatch 实验里，建议先保留 demo 算法，明确写成 vulnerable/simple baseline；hotpatch 的重点先放在修复 DID write/replay/gateway policy。
