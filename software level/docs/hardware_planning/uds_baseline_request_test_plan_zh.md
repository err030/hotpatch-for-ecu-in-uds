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

key 计算当前是实验用弱变换：

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
- 请求 seed 后计算实验弱变换 key，期望 `0x67 0x02`
- 解锁后合法 DID write，期望 `0x6E 0x12 0x34`
- 读回刚写入的 DID `0x1234`，期望 `0x62 0x12 0x34 ...`
- session reset 后重放同一个 DID write，期望再次被拒绝

测试结果会打印到终端，并写入：

```text
software level/charts/hardware_baseline_security_latest.csv
```

2026-06-11 实测结果：早期 misconfigured gateway + strict ECU baseline 全部通过，
`19/19` 个 security baseline 检查为 `PASS`。

2026-06-14 实测结果：CANable2.0 / `can0` 到 nRF52840 secure profile 全部通过，
`19/19` 个 security baseline 检查为 `PASS`。该 profile 让 `0x2E` 穿过 gateway
到达 strict ECU，非法写由 ECU 返回 NRC，合法授权写仍允许。结果写入：

```text
software level/charts/hardware_secure_security_latest.csv
```

2026-06-14 实测结果：CANable2.0 / `can0` 到 nRF52840 vulnerable profile 全部通过，
`19/19` 个检查符合 vulnerable profile 预期。其中 extended session 下未解锁
`0x2E 0x1234` 返回 `0x6E 0x1234`，说明高风险请求已到达 ECU 且被 vulnerable
policy 接受。结果写入：

```text
software level/charts/hardware_vulnerable_security_latest.csv
```

这个 CSV 可作为“不加入 hotpatch 时 baseline 拦截结果”的实验记录。

## SecurityAccess-derived 0x2E 攻击测试

主攻击脚本：

```text
software level/tools/uds_2e_security_access_attack_test.py
```

该脚本执行完整的 `0x10 -> 0x27 -> 0x2E -> 0x22` 流程，用来验证：

- 请求能穿过 gateway 到达 ECU；
- 弱 seed/key 变换被算出后，`0x27` 解锁成功；
- `0x2E WriteDataByIdentifier` 写入成功；
- `0x22 ReadDataByIdentifier` 能读回写入值。

运行：

```bash
python3 "software level/tools/uds_2e_security_access_attack_test.py" --interface can0 --csv "software level/charts/uds_2e_security_access_attack_secure_latest.csv"
```

2026-06-14 实测结果：secure profile 下 `5/5` 个步骤为 `PASS`，`0x2E 0x1234 CAFE`
写入成功并通过 `0x22` 读回。这个结果说明：仅靠 gateway/service routing 不会阻断
协议有效的 `0x27 -> 0x2E` 序列；hotpatch 应修复 ECU-local SecurityAccess / DID
write policy。

hotpatched profile 验证命令：

```bash
python3 "software level/tools/uds_2e_security_access_attack_test.py" --interface can0 --expect hotpatched-block --csv "software level/charts/uds_2e_security_access_attack_hotpatched_latest.csv"
```

2026-06-14 实测结果：hotpatched profile 下 `5/5` 个步骤为 `PASS`。其中
`0x27` 仍返回 `0x67 0x02`，但后续 `0x2E 0x1234 CAFE` 返回 `0x7F 0x2E 0x31`，
`0x22 0x1234` 读回空值。这证明拦截点在 ECU-local DID quarantine，而不是 gateway。

kintsugi-runtime profile 验证命令：

```bash
python3 "software level/tools/uds_2e_security_access_attack_test.py" --interface can0 --expect success --csv "software level/charts/uds_2e_security_access_attack_kintsugi_before_latest.csv"
nrfjprog -f nrf52 --reset
python3 "software level/tools/uds_2e_security_access_attack_test.py" --interface can0 --trigger-kintsugi-hotpatch --expect hotpatched-block --csv "software level/charts/uds_2e_security_access_attack_kintsugi_after_latest.csv"
python3 "software level/tools/uds_security_baseline_test.py" --interface can0 --profile hotpatched --csv "software level/charts/hardware_kintsugi_runtime_after_security_latest.csv"
```

2026-06-15 实测结果：Kintsugi trigger 前攻击 `5/5 PASS` 且写入成功；发送
`0x2E F190 01` 后 trigger 返回 `0x6E F190`，随后同一攻击链 `6/6 PASS`，其中
授权后的 `0x2E` 被 `0x7F 0x2E 0x31` 拦截。Kintsugi 触发后的完整 security baseline
为 `19/19 PASS`。

参考说明见：

```text
software level/docs/hardware_planning/uds_2e_security_access_attack_reference_zh.md
```

## Legacy CVE-derived parser negative 测试

选择依据见：

```text
software level/docs/hardware_planning/cve_attack_selection_for_uds_hotpatch_zh.md
```

保留脚本：

```text
software level/tools/cve_derived_uds_attack_test.py
```

运行：

```bash
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0
```

当前测试不是主攻击证据，也不声称本 ECU 真实存在对应 CVE；它只保留为 parser /
message-length negative testing：

- `CVE-2020-17443-derived`：短报文长度检查，发送缺少 subfunction 的 `0x10`
- `CVE-2018-16603-derived`：短底层 packet 导致越界访问，发送 PCI length 大于实际 CAN DLC 的 malformed single frame
- `CVE-2018-16524-derived`：选项长度越界检查，映射为授权后 `0x2E DID Write` 的零长度 data

结果会写入：

```text
software level/charts/cve_derived_uds_attack_latest.csv
```

2026-06-11 实测结果：早期 baseline 下 `6/6` 个 CVE-derived UDS attack 检查为
`PASS`。

2026-06-14 实测结果：secure profile 下 `6/6` 个 CVE-derived UDS attack 检查为
`PASS`，其中 `0x2E` 派生攻击穿过 gateway 后由 strict ECU 返回 `0x7F 0x2E 0x13`。
结果写入：

```text
software level/charts/cve_derived_uds_attack_secure_latest.csv
```

2026-06-14 实测结果：vulnerable profile 下 `6/6` 个 CVE-derived parser negative 检查为
`PASS`，结果写入：

```text
software level/charts/cve_derived_uds_attack_vulnerable_latest.csv
```

## Gateway/Profile 模式

当前板级默认 profile 是 `secure`。它故意让高风险诊断请求能穿过 gateway，
再由 ECU 侧 strict security policy 拒绝非法写入：

```text
BOARD_BASELINE_PROFILE_SECURE -> UDS_GATEWAY_MODE_MISCONFIGURED + strict ECU
```

它允许通过 gateway：

- `0x10` DiagnosticSessionControl
- `0x22` ReadDataByIdentifier
- `0x27` SecurityAccess
- `0x2E` WriteDataByIdentifier

因此 secure profile 下，非法 `0x2E` 预期会到达 adjacent ECU，然后由 strict ECU
返回对应 NRC；合法授权后的 `0x2E` 仍应允许。这条路径用于证明 ECU 侧 security
state machine 有效，也为后续 hotpatch 从 vulnerable ECU 切到 strict ECU 提供对照。

攻击演示 profile 需要显式切到：

```text
BOARD_BASELINE_PROFILE_VULNERABLE -> UDS_GATEWAY_MODE_MISCONFIGURED + vulnerable ECU
```

它让 `0x2E` 穿过 gateway 并到达 vulnerable ECU。该 profile 用于展示为什么只靠
gateway 后面的部署位置不够，以及为什么需要 ECU-local hotpatch 把 vulnerable
policy 切到 strict policy。

如果要展示 gateway perimeter 防护，可以显式切到：

```text
BOARD_BASELINE_PROFILE_GATEWAY_SECURE -> UDS_GATEWAY_MODE_RESTRICTED + strict ECU
```

这个 profile 会在 gateway 层直接 drop 外部 `0x2E`，它是 defense-in-depth 对照，
不是 hotpatch 主线。

hotpatch 拦截 profile 是：

```text
BOARD_BASELINE_PROFILE_HOTPATCHED -> UDS_GATEWAY_MODE_MISCONFIGURED + strict ECU + DID quarantine
```

它仍允许 `0x27` 和 `0x2E` 穿过 gateway 并到达 ECU。区别是 ECU-local hotpatch
把高风险 `DID 0x1234` 写权限临时隔离：攻击者即使通过弱 seed/key 算法完成
`0x27` 解锁，后续 `0x2E 0x1234 ...` 也会得到 `0x7F 0x2E 0x31`。

运行时 Kintsugi 接入 profile 是：

```text
BOARD_BASELINE_PROFILE_KINTSUGI_RUNTIME -> UDS_GATEWAY_MODE_MISCONFIGURED + strict ECU + Kintsugi bridge
```

它启动时不预应用 hotpatch，因此弱 `0x27 -> 0x2E` 攻击仍能成功。发送
`0x2E F190 01` 后，board bridge 通过 Kintsugi manager/applicator patch 一个
`.ramfunc` gate，gate 生效后再启用 ECU-local DID quarantine。

构建/烧录命令：

```bash
make -C "hardware level/board_baseline" secure
make -C "hardware level/board_baseline" flash-secure
make -C "hardware level/board_baseline" vulnerable
make -C "hardware level/board_baseline" flash-vulnerable
make -C "hardware level/board_baseline" gateway-secure
make -C "hardware level/board_baseline" flash-gateway-secure
make -C "hardware level/board_baseline" hotpatched
make -C "hardware level/board_baseline" flash-hotpatched
make -C "hardware level/board_baseline" kintsugi-runtime
make -C "hardware level/board_baseline" flash-kintsugi-runtime
```

自动化测试按 profile 设置预期：

```bash
python3 "software level/tools/uds_security_baseline_test.py" --interface can0 --profile secure
python3 "software level/tools/uds_security_baseline_test.py" --interface can0 --profile vulnerable
python3 "software level/tools/uds_security_baseline_test.py" --interface can0 --profile gateway-secure
python3 "software level/tools/uds_security_baseline_test.py" --interface can0 --profile hotpatched
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0 --profile secure
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0 --profile vulnerable
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0 --profile gateway-secure
python3 "software level/tools/cve_derived_uds_attack_test.py" --interface can0 --profile hotpatched
```

论文图表用的软件级 mutation campaign：

```bash
python3 "software level/charts/export_uds_attack_mutation.py"
```

该命令固定随机种子生成 `1000` 个 gateway-routed `0x10 -> 0x27 -> 0x2E`
变异尝试，并导出：

```text
software level/charts/uds_2e_mutation_attack_summary.csv
software level/charts/uds_2e_mutation_attack_detail.csv
software level/charts/UDS_2E_MUTATION_ATTACK_SUMMARY.md
software level/charts/uds_2e_mutation_attack_rates.svg
```

如果只需要临时覆盖 gateway mode，也可以直接改：

```text
BOARD_UDS_GATEWAY_MODE
```

## 加密/认证协议说明

当前 `0x27` 是实验弱 seed/key：

```text
key = seed ^ 0xA55A
```

这不是安全加密协议，只适合作为论文实验里的可控 baseline。后续应补成：

- per-session nonce
- ECU secret 派生 key
- freshness counter 或 monotonic challenge
- replay window
- lockout 和失败次数持久化策略

在 hotpatch 实验里，应明确写成 weak SecurityAccess baseline；hotpatch 的重点放在
替换弱 seed/key、收紧 DID write policy、清理 replay/unlock 状态。
