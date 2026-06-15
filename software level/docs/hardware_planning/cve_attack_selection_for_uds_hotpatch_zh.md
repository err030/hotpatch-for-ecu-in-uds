# UDS ECU 项目的 CVE 攻击候选选择记录

日期：2026-06-04

## 结论

2026-06-14 更新：本文件只保留为 legacy malformed-request negative testing 的来源记录。
主线 `0x2E` 攻击证据已改为 `0x27 SecurityAccess -> 0x2E WriteDataByIdentifier`
流程，见：

```text
software level/docs/hardware_planning/uds_2e_security_access_attack_reference_zh.md
```

论文中不应把本文件里的 CVE-derived cases 写成本 ECU 的真实漏洞；它们只用于
parser/length/security-state regression checks。

当前硬件固件事实：

- 使用 `FreeRTOS-Kernel V11.1.0+`
- 没有接入 `FreeRTOS+TCP`
- 没有接入 `picoTCP`
- 没有接入 Zephyr networking / USB MSC / shell / syscall
- 没有接入 mbedTLS 证书解析路径
- UDS over CAN 是本项目自己的 C 实现

因此当前用途是：

1. 保留 Kintsugi artifact 中“真实 CVE hotpatch”的证据链。
2. 在本项目中只保留 `CVE-derived legacy regression checks`，即把真实 CVE 的 bug class
   映射到 UDS/CAN parser、DID length、security state 的负向测试。
3. 论文中不要把这些 checks 写成主攻击，也不要写成“本 ECU 真实受该 CVE 影响”。
   主攻击应写 `SecurityAccess-derived 0x2E write attack`。

## Kintsugi artifact 中明确记录的 10 个 CVE

证据位置：

```text
/home/beibei/Downloads/kintsugi_artifact_zenodo/README.md
/home/beibei/Downloads/kintsugi_artifact_zenodo/experiments/realworld_cves/README.md
```

Kintsugi README 明确说明其 E5 real-world CVE 实验覆盖 10 个 CVE，并且 `experiments/realworld_cves/README.md` 给出了每个 CVE 的 expected UART output。

| CVE | Kintsugi 实验平台 | Kintsugi hotpatch | 本项目直接适用性 | 适合 UDS 映射 |
|---|---|---|---|---|
| `CVE-2020-10021` | Zephyr | `hotpatches/zephyr/cve_2020_10021.c` | 不直接适用，当前不用 Zephyr USB MSC | 低 |
| `CVE-2020-10023` | Zephyr | `hotpatches/zephyr/cve_2020_10023.c` | 不直接适用，当前不用 Zephyr shell | 中，字符串/空格裁剪类 parser bug 可映射 |
| `CVE-2020-10024` | Zephyr | `hotpatches/zephyr/cve_2020_10024.c` | 不直接适用，当前不用 Zephyr syscall/userspace | 低 |
| `CVE-2020-10062` | Zephyr MQTT | `hotpatches/zephyr/cve_2020_10062.c` | 不直接适用，当前不用 MQTT | 高，variable-length decode / length bound 可映射到 ISO-TP/UDS parser |
| `CVE-2020-10063` | Zephyr CoAP | `hotpatches/zephyr/cve_2020_10063.c` | 不直接适用，当前不用 CoAP | 高，option length/delta integer overflow 可映射到 DID/length parser |
| `CVE-2017-2784` | FreeRTOS + mbedTLS | `hotpatches/freertos/cve_2017_2784.c` | 不直接适用，当前不用 mbedTLS cert parse | 中，SecurityAccess key validation 可借鉴“拒绝不支持曲线/算法” |
| `CVE-2018-16524` | FreeRTOS+TCP | `hotpatches/freertos/cve_2018_16524.c` | 不直接适用，当前不用 FreeRTOS+TCP | 高，TCP options length OOB 可映射到 UDS payload length validation |
| `CVE-2018-16603` | FreeRTOS+TCP | `hotpatches/freertos/cve_2018_16603.c` | 不直接适用，当前不用 FreeRTOS+TCP | 高，短包导致 OOB 访问可映射到 malformed CAN/UDS single frame |
| `CVE-2020-17443` | picoTCP ICMPv6 | `hotpatches/freertos/cve_2020_17443.c` | 不直接适用，当前不用 picoTCP | 高，短报文长度检查可映射到 UDS request minimum length |
| `CVE-2020-17445` | picoTCP IPv6 destopt | `hotpatches/freertos/cve_2020_17445.c` | 不直接适用，当前不用 picoTCP | 高，option length 越界可映射到 DID data length / config table parser |

## Kintsugi hotpatches 目录中存在但 README 未列入 10 个实验的 CVE

证据位置：

```text
/home/beibei/Downloads/kintsugi_artifact_zenodo/hotpatches/freertos/cve_2018_16528.c
/home/beibei/Downloads/kintsugi_artifact_zenodo/hotpatches/freertos/cve_2021_31572.c
/home/beibei/Downloads/kintsugi_artifact_zenodo/hotpatches/zephyr/cve_2020_10028.c
```

这些文件存在，但 `experiments/realworld_cves/README.md` 没有把它们列入 10 个 expected-output 实验。因此论文里写：

```text
Kintsugi artifact contains hotpatch source files for these CVEs.
```

## Legacy CVE-derived regression checks

### 1：`CVE-2018-16603` derived malformed UDS single-frame length

理由：

- Kintsugi 明确做过该 CVE 的实验。
- NVD 描述其核心问题是 `xProcessReceivedTCPPacket` 中短 TCP packet 导致 source/destination port 越界访问。
- 本项目有真实 CAN/ISO-TP single-frame parser：`uds_can_unpack_single_frame_payload()`。
- 可以用 CANable 发送 malformed single frame，验证 ECU 是否错误读取 payload。

本项目映射：

```text
FreeRTOS+TCP short TCP packet -> UDS single-frame PCI length > actual DLC
```

攻击输入示例：

```text
CAN ID 0x7E0, data[0] claims payload length 7, but actual DLC shorter than 8
```

预期：

- patched/baseline strict parser 不应进入 UDS dispatcher
- 不应产生 positive response
- 后续可以作为 Kintsugi guard 的目标：在 gateway/adapter 层提前 drop malformed frame

### 2：`CVE-2018-16524` derived option-length/OOB UDS DID write

理由：

- Kintsugi 明确做过该 CVE 的实验。
- Kintsugi hotpatch 对 `prvCheckOptions` 增加了 `pucLast > buffer + length` 的边界检查。
- 本项目 `0x2E WriteDataByIdentifier` 已经有 DID data length 策略，可以设计“不合法长度”攻击。

本项目映射：

```text
TCP option length over packet boundary -> DID write data length violates config table policy
```

攻击输入示例：

```text
0x2E 0x12 0x34 with zero-length data
0x2E 0x12 0x34 with data length > max_write_length
```

预期：

- 返回 `7F 2E 13`
- 后续 hotpatch 可把 max/min length 或 DID policy 动态收紧

### 3：`CVE-2020-10063` derived integer-overflow parser test

理由：

- Kintsugi 明确做过该 CVE 的实验。
- Kintsugi hotpatch 对 CoAP option delta/length 加法后回绕进行检查。
- 本项目可以把它映射到 UDS parser 中所有 `length + offset` 运算的边界检查。

当前限制：

- 当前 UDS over CAN 只支持 single-frame，payload 最大 7 bytes，不容易真实触发 16-bit overflow。
- 更适合放在 software-level fuzz 或未来 ISO-TP multi-frame 实现里。

本项目映射：

```text
CoAP option length/delta overflow -> ISO-TP multi-frame total length / DID record length overflow
```

### 4：`CVE-2021-31572` FreeRTOS stream buffer integer overflow

注意：

- 本项目确实编译了 `stream_buffer.c`。
- 但当前 `external/rtos/FreeRTOS-Kernel/include/task.h` 显示版本为 `V11.1.0+`，不是 NVD 中 `FreeRTOS before 10.4.3`。
- `hotpatches/freertos/cve_2021_31572.c` 在 Kintsugi artifact 中存在，但不在 realworld CVE README 的 10 个 expected-output 实验列表里。

适合用法：

- 作为“额外可选 CVE hotpatch source exists”的后续工作。
- 不建议作为当前 UDS attack 主线。

## 本项目第一阶段建议实现

优先实现以下三个测试族：

1. `CVE-2018-16603-derived`: malformed CAN/UDS single-frame length。
2. `CVE-2018-16524-derived`: DID write length out-of-policy。
3. `CVE-2020-10063-derived`: parser arithmetic/fuzz case，先放 software-level，等 ISO-TP multi-frame 后移到 hardware-level。


## 外部核对来源

- NVD `CVE-2018-16524`: FreeRTOS+TCP `prvCheckOptions` parsing can disclose information.
- NVD `CVE-2018-16603`: FreeRTOS+TCP `xProcessReceivedTCPPacket` can access TCP port fields out of bounds.
- NVD `CVE-2020-17443`: picoTCP ICMPv6 echo reply path lacks short-packet length check.
- NVD `CVE-2020-17445`: picoTCP IPv6 destination options length check issue causes out-of-bounds read / DoS.
- NVD `CVE-2021-31572`: Amazon FreeRTOS before `10.4.3` has integer overflow in `stream_buffer.c`.
