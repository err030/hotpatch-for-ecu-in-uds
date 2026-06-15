# UDS SecurityAccess -> 0x2E 攻击实验依据

## 结论

当前主线 `0x2E` 攻击不再使用自造 CVE 映射，也不依赖 “gateway 直接拦截”。
实验建模为：

```text
tester -> gateway -> ECU
0x10 extended session
0x27 request seed
弱 seed/key transform 计算 key
0x27 send key
0x2E WriteDataByIdentifier
0x22 ReadDataByIdentifier 读回验证
```

这条路径的安全含义是：gateway 允许标准诊断路径通过，攻击请求实际到达 ECU；
如果 ECU 的 SecurityAccess seed/key 算法弱、可逆、可枚举或已被提取，攻击者就能
获得正当的 `0x67 0x02` 解锁响应，然后执行 `0x2E` 写配置。

## 当前实测

脚本：

```text
software level/tools/uds_2e_security_access_attack_test.py
```

实测 artifact：

```text
software level/charts/uds_2e_security_access_attack_secure_latest.csv
software level/charts/uds_2e_security_access_attack_hotpatched_latest.csv
software level/charts/uds_2e_security_access_attack_kintsugi_before_latest.csv
software level/charts/uds_2e_security_access_attack_kintsugi_after_latest.csv
```

2026-06-14 在 `CANable2.0 / can0 -> nRF52840 + MCP2515` 上实测通过：

- `0x10 0x03` 进入 extended session
- `0x27 0x01` 获取 seed
- 使用当前实验弱变换 `key = seed ^ 0xA55A` 发送 `0x27 0x02`
- `0x2E 0x1234 CAFE` 写入成功
- `0x22 0x1234` 读回 `CAFE`

2026-06-14 同一硬件链路上，`hotpatched` profile 实测拦截成功：

- `0x10 0x03` 进入 extended session
- `0x27 0x01` 获取 seed
- 使用当前实验弱变换 `key = seed ^ 0xA55A` 发送 `0x27 0x02`
- ECU 返回 `0x67 0x02`，说明 gateway 没拦截且 SecurityAccess 解锁仍成功
- `0x2E 0x1234 CAFE` 返回 `0x7F 0x2E 0x31`
- `0x22 0x1234` 返回空 DID 值 `0x62 0x12 0x34`，说明写入没有发生

该 hotpatch 不是 gateway block，而是 ECU-local DID quarantine：在弱 `0x27`
风险未彻底替换前，临时撤销高风险配置 DID 的写权限。

2026-06-15 在 `kintsugi-runtime` profile 下完成运行时接入验证：

- 触发前，完整 `0x10 -> 0x27 -> 0x2E -> 0x22` 攻击链仍成功，写入 `CAFE`
- 发送实验控制 DID `0x2E F190 01` 后，board Kintsugi bridge 调用
  `hp_manager_receive_hotpatch -> hp_manager_schedule_hotpatch ->
  hp_manager_apply_scheduled_hotpatch`
- Kintsugi applicator 将 `.ramfunc` gate patch 为 active，随后 ECU-local policy
  启用 DID quarantine
- 触发后，同一攻击链中 `0x27` 仍成功，但 `0x2E 0x1234 CAFE` 返回 `0x7F 0x2E 0x31`
  且 `0x22 0x1234` 读回空值

## Mutation / fuzzing 统计实验

为了避免论文只展示一个手工成功样例，当前增加了确定性 mutation campaign：

```text
software level/charts/export_uds_attack_mutation.py
```

该脚本固定随机种子，生成 `1000` 个围绕 `0x10 -> 0x27 -> 0x2E` 的变异样例，
变异维度包括：

- gateway policy：`misconfigured / open / restricted`
- diagnostic session 顺序：正常 extended、跳过 session、解锁后回 default session
- SecurityAccess：正确 seed/key、错误 key、跳过 key
- DID：目标配置 DID `0x1234`、只读 DID、未知 DID
- `0x2E` payload 长度：合法长度、零长度、超长

2026-06-15 生成的软件级统计：

| Profile | Cases | Valid attack-shaped cases | Attack successes | Success rate | Blocked/failed rate | Hotpatch-blocked valid cases |
|---|---:|---:|---:|---:|---:|---:|
| `before_hotpatch` | 1000 | 787 | 787 | 78.70% | 21.30% | 0 |
| `after_hotpatch` | 1000 | 787 | 0 | 0.00% | 100.00% | 787 |

2026-06-15 追加普通诊断请求对照组，验证 hotpatch 不是把正常 UDS 路径一并破坏：

| Profile | Workload | Cases | Successful cases | Success rate |
|---|---|---:|---:|---:|
| `before_hotpatch` | benign diagnostic | 1000 | 1000 | 100.00% |
| `before_hotpatch` | attack mutation | 1000 | 787 | 78.70% |
| `after_hotpatch` | benign diagnostic | 1000 | 1000 | 100.00% |
| `after_hotpatch` | attack mutation | 1000 | 0 | 0.00% |

其中 benign diagnostic workload 包含 `0x10` session control、`0x22` DID read 和
`0x27` SecurityAccess unlock，不包含高风险 `0x2E` 配置写入。这个对照组用于证明
hotpatch 的效果是 selective mitigation：正常诊断仍可用，攻击性 `0x27 -> 0x2E`
写链被降低到 `0/1000` 成功。

论文图表 artifact：

```text
software level/charts/uds_2e_mutation_attack_summary.csv
software level/charts/uds_2e_mutation_attack_detail.csv
software level/charts/UDS_2E_MUTATION_ATTACK_SUMMARY.md
software level/charts/uds_2e_mutation_attack_rates.svg
software level/charts/uds_control_group_summary.csv
software level/charts/uds_benign_diagnostic_control_detail.csv
software level/charts/UDS_CONTROL_GROUP_SUMMARY.md
software level/thesis_figures/pdf/fig11_control_group_success_rates.pdf
```

解释边界：`before_hotpatch` 不是 100%，因为分母包含变异后的合理诊断尝试，而不是只
计算单条手工挑选的成功链。`after_hotpatch` 在本 corpus 中观测到 100% 拦截，但论文
中应写成“tested mutation corpus 中全部拦截”，不能写成证明所有可能攻击都被拦截。

## 可核验来源

- Thompson, M., "UDS Security Access for Constrained ECUs," SAE Technical Paper
  2022-01-0132, 2022, doi:10.4271/2022-01-0132。
  - 本地 artifact：`hardware level/reference/2022-01-0132.pdf`
  - 该论文讨论 constrained ECU 必须使用 UDS service `0x27`、缺少 HSM/TRNG/后端 IT
    时的 seed/key 设计约束，并把“攻击者持有大量历史 UDS-Seed/UDS-Key”列入威胁模型。
  - 本项目不复刻其完整设计方案，而是把它作为 `0x27` 威胁模型依据：当 seed/key
    变换弱或被提取时，后续 `0x2E` 写 DID 会成为 ECU-local hotpatch 目标。
- `udsoncan` 文档列出了 UDS 标准服务，包括 `SecurityAccess (0x27)`、
  `WriteDataByIdentifier (0x2E)` 和 `ReadDataByIdentifier (0x22)`，并说明
  `SecurityAccess` 的 seed/key 解锁流程。
  - https://udsoncan.readthedocs.io/en/latest/udsoncan/services.html
- `Caring Caribou` 是开源 CAN/UDS 安全探索工具；其 UDS 模块包含诊断服务发现、
  seed collection、seed randomness fuzzing 和 DID dump 等能力，说明该类
  SecurityAccess/DID 操作是公开工具链中常见的汽车安全测试面。
  - https://github.com/CaringCaribou/caringcaribou
- Linux ISO-TP 文档和 python-can/SocketCAN 文档用于说明当前 `can0`/SocketCAN
  传输路径，不用于证明攻击本身。
  - https://docs.kernel.org/networking/iso15765-2.html

## 关于 Martin Thompson 2022 的使用边界

已通过本地 PDF artifact 核验该来源。论文可以用于支持：

- constrained ECU 上继续使用 UDS `0x27` 的现实约束；
- seed/key challenge-response 的术语和 threat model；
- 没有 HSM/TRNG/backend IT 时，SecurityAccess 设计会留下残余风险。

论文不应被写成“本文复现了 Thompson 的完整算法”。当前实验只实现一个可控弱
baseline，用于证明 hotpatch 需要在 ECU-local SecurityAccess / DID policy 层拦截
协议有效的 `0x27 -> 0x2E` 链。

## 与 hotpatch 的关系

这条攻击不是“gateway 没配好所以直接放行 0x2E”这么简单。它表示：

- 诊断路径本身是合法且会被路由的。
- `0x27` 解锁流程被弱 seed/key 破坏后，`0x2E` 看起来像合法授权写入。
- gateway 很难仅凭 service ID 阻断这类协议有效请求，否则会破坏维修/标定流程。
- hotpatch 的目标应放在 ECU-local policy：替换弱 SecurityAccess 算法、增加
  freshness/nonce、收紧 DID 写权限、清理 replay/unlock 状态，或临时禁用高风险 DID。

当前硬件 hotpatch payload 采用最后一种最小闭环：保留 `0x27` 握手以证明请求到达
ECU，但对 `UDS_VALID_WRITE_DID = 0x1234` 启用 quarantine，使攻击链在授权后
`0x2E` 阶段被 ECU 返回 `requestOutOfRange (0x31)`。

Kintsugi 接入边界：当前没有打开 FreeRTOS context-switch hook
`configUSE_HP_FRAMEWORK=1`，因为此前该 hook 在 nRF/FreeRTOS 组合下曾触发 HardFault。
本轮接入使用 Kintsugi 原生 slot/code/applicator 数据结构和 manager API，但由 board
bridge 显式调用 apply safe point，避免阻塞式 `hp_manager()` 等待 context-switch
applicator。
