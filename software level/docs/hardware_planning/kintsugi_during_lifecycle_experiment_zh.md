# Kintsugi UDS During Lifecycle Experiment

## 目的

原始 Kintsugi artifact 的 security experiment 分为 before / during / after，
重点证明 Kintsugi 在 hotpatch 前、中、后可以保护 hotpatch 相关内存不被篡改。

本项目的车辆适配实验不复刻原始 memory-tampering workload，而是把 during
定义为 UDS 诊断链路可观察的 hotpatch lifecycle：

```text
before hotpatch
receive pending
schedule pending
after apply
```

这样可以证明：

- Kintsugi runtime hotpatch 被接入到真实 UDS/CAN 控制路径；
- hotpatch 在 receive / schedule pending 阶段不会误激活 ECU 安全策略；
- 只有 apply 后，ECU-local UDS DID quarantine 才生效；
- 正常诊断请求在各阶段仍可通过。

## UDS 控制 DID

控制 DID：

```text
0xF190
```

控制命令：

| Command | UDS payload | 语义 |
|---:|---|---|
| `0x01` | `2E F190 01` | 兼容旧路径：receive + schedule + apply |
| `0x02` | `2E F190 02` | 只 receive hotpatch 到 Kintsugi slot |
| `0x03` | `2E F190 03` | 只 schedule 已 receive 的 hotpatch |
| `0x04` | `2E F190 04` | apply 已 schedule 的 hotpatch |

成功响应均为：

```text
6E F190
```

失败响应为：

```text
7F 2E <NRC>
```

## 预期行为

| Phase | Kintsugi 状态 | UDS `0x27 -> 0x2E` 攻击 | 普通诊断 `0x22 1001` |
|---|---|---|---|
| before hotpatch | no patch loaded | success | pass |
| receive pending | patch stored in slot | success | pass |
| schedule pending | applicator prepared | success | pass |
| after apply | ECU policy active | blocked with `7F 2E 31` | pass |

这里的 during 不是“Kintsugi 检测攻击”，而是“hotpatch 生命周期中间态验证”。
攻击是否应被修复由外部安全决策触发；Kintsugi 负责安全地接收、调度和应用
已经准备好的 patch。

## 采集脚本

脚本：

```bash
python3 "software level/tools/uds_kintsugi_during_lifecycle_test.py" \
  --interface can0 \
  --csv "software level/charts/uds_kintsugi_during_lifecycle_latest.csv" \
  --summary-csv "software level/charts/uds_kintsugi_during_lifecycle_summary_latest.csv" \
  --pdf "software level/thesis_figures/pdf/fig_kintsugi_during_lifecycle_latest.pdf"
```

输出：

- `software level/charts/uds_kintsugi_during_lifecycle_latest.csv`
- `software level/charts/uds_kintsugi_during_lifecycle_summary_latest.csv`
- `software level/thesis_figures/pdf/fig_kintsugi_during_lifecycle_latest.pdf`

## 论文表述建议

可以写成：

> To align the vehicle experiment with the original Kintsugi before/during/after
> security evaluation, the UDS integration exposes a staged hotpatch lifecycle
> through a diagnostic control DID. The receive and schedule stages make the
> patch resident and pending without changing ECU behavior, while the apply
> stage activates the ECU-local DID quarantine. This shows that the UDS security
> mitigation is a runtime hotpatch effect rather than a rebooted or statically
> selected firmware profile.

