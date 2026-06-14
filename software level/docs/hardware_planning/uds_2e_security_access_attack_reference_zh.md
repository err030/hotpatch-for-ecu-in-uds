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
