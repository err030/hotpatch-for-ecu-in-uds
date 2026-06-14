# PPT 汇报提纲

这个提纲面向“目前工作汇报”，按 `10` 页组织，适合讲 `8-12` 分钟。
主线建议是：`问题背景 -> 系统设计 -> 关键实现 -> 实验结果 -> 后续工作`。

---

## 第 1 页：标题页

建议标题：

`面向 UDS 场景的 ECU Hotpatch 软件仿真与评估`

建议副标题：

- 当前阶段工作汇报
- software-first simulation
- UDS / gateway / hotpatch / fleet evaluation

建议放的内容：

- 项目名称
- 你的姓名
- 日期
- 一句话目标：
  `在纯软件环境中验证 gateway-routed UDS 漏洞利用、运行时热补丁行为，以及 fleet-level 防护收益。`

---

## 第 2 页：研究问题与动机

这一页回答“为什么要做这个题目”。

建议展示内容：

- 场景：`gateway-adjacent diagnostic ECU`
- 风险：UDS 服务链 `0x10 -> 0x27 -> 0x2E` 一旦状态机或授权逻辑有缺陷，可能导致未授权写
- 问题：传统 `OTA-only` 修复存在保护生效慢、暴露窗口长的问题
- 核心问题：
  1. 能否先在软件中稳定复现 UDS 攻击链和漏洞语义？
  2. 能否用 hotpatch 在 OTA 前先提供保护？
  3. 这种提前保护在 fleet 层面是否有意义？

建议配图：

- 直接用 [charts/THESIS_CHARTS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/THESIS_CHARTS_zh.md:8) 里的 `Gateway-routed UDS 攻击路径`

页内总结句：

`本工作的目标不是先上硬件，而是先把攻击链、补丁行为和评估指标在软件中跑通并量化。`

---

## 第 3 页：当前系统总体架构

这一页回答“我现在到底做出来了什么系统”。

建议展示内容：

- `tester -> gateway -> target ECU` 的 routed diagnostics 路径
- 软件模块：
  - UDS 协议编解码
  - ISO-TP 分帧/重组
  - 虚拟 CAN 总线
  - Gateway 策略模拟
  - ECU 状态机
  - Hotpatch manager
  - Fleet / timing / differential evaluation
- 三层 backend：
  - `in-memory`
  - `python-can virtual`
  - `python-can socketcan`

建议引用：

- [README.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/README.md:7)
- [PROJECT_STATUS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/PROJECT_STATUS_zh.md:18)

可以放一行结论：

`当前版本已经从协议语义、攻击场景、热补丁生命周期扩展到软件级评估闭环。`

---

## 第 4 页：UDS 状态机与漏洞建模

这一页是第一个“关键实现页”。

建议展示内容：

- ECU 支持的核心服务：
  - `0x10` session control
  - `0x27` security access
  - `0x2E` write data by identifier
- 关键状态：
  - `default session`
  - `extended session`
  - `seed issued`
  - `unlocked`
  - `locked out`
- 当前建模的漏洞类型：
  - 未授权直接写
  - failed key 后旧 unlock 未清理
  - session 切换后旧 unlock 仍保留
  - replay old write

建议配图：

- [charts/THESIS_CHARTS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/THESIS_CHARTS_zh.md:21) 里的 `UDS 状态机与漏洞位置`

建议代码切片：

- [src/hotpatch_uds/ecu.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/ecu.py:132)
- [src/hotpatch_uds/ecu.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/ecu.py:175)

适合截图的讲解点：

- `_handle_session_control()` 中 session 切换时是否清理 unlock
- `_handle_security_access()` 中 failed key 和 lockout 的处理
- `_handle_write_data_by_identifier()` 中写请求是否强制依赖 unlock

页内总结句：

`核心漏洞不是协议不存在，而是状态迁移和授权清理细节出错。`

---

## 第 5 页：Gateway 与攻击路径实现

这一页回答“为什么 gateway 后面仍然可能被打”。

建议展示内容：

- Gateway 三种模式：
  - `open`
  - `restricted`
  - `misconfigured`
- 重点说明：
  - gateway 只是做转发与过滤
  - 一旦策略放宽或配置错误，攻击流量仍可到达目标 ECU

建议代码切片：

- [src/hotpatch_uds/gateway.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/gateway.py:80)

建议强调的代码点：

- `forward_all_pending()` 体现请求和响应的双向转发
- `_allow_request_frame()` 体现基于 service id 的策略过滤

可配一张图：

- [charts/THESIS_CHARTS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/THESIS_CHARTS_zh.md:40) 里的 `0x10 -> 0x27 -> 0x2E 服务链`

页内总结句：

`gateway 能改变攻击面，但不能自动修复 ECU 内部的授权逻辑漏洞。`

---

## 第 6 页：Hotpatch 机制设计与运行时流程

这一页回答“补丁是怎么被加载、验证、激活的”。

建议展示内容：

- Hotpatch 生命周期：
  - `stage`
  - `validate_and_store`
  - `schedule`
  - `guard_and_apply`
  - `rollback`
- 设计元素：
  - quarantine
  - slot
  - validation
  - safe point activation
  - rollback

建议代码切片：

- [src/hotpatch_uds/hotpatch.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/hotpatch.py:100)
- [src/hotpatch_uds/hotpatch.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/hotpatch.py:151)

适合口头说明的重点：

- `stage()` 先进入 quarantine，不直接覆盖运行代码
- `validate_and_store()` 做大小和 slot 检查
- `guard_and_apply()` 只在 safe point 应用，降低运行时风险
- `rollback()` 支持失败后退回脆弱版本

页内总结句：

`当前 hotpatch 不是“立即替换”，而是一个带验证、调度和回滚的软件级生命周期模型。`

---

## 第 7 页：攻击与补丁行为演示结果

这一页建议做成“补丁前后对比页”，非常适合汇报。

建议展示内容：

左侧放“漏洞版本”：

- `write_without_unlock: POSITIVE sid=0x6E`

右侧放“补丁后”：

- `write_without_unlock: NEGATIVE sid=0x7F orig=0x2E nrc=0x33`

再补一组 runtime patch 演示：

- `write_before_patch: POSITIVE`
- `patch_state: patch_loading`
- `patch_state: patched steps_to_protection=2`
- `write_after_patch: NEGATIVE`

建议结果来源：

- [src/hotpatch_uds/scenarios.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/scenarios.py:364)
- [src/hotpatch_uds/scenarios.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/scenarios.py:469)

建议直接展示的运行结果摘要：

- 漏洞 ECU：未授权写成功
- 补丁 ECU：未授权写被拒绝
- Patchable ECU：运行时激活补丁后，同一写请求从成功变为拒绝

页内总结句：

`补丁效果不是静态声明，而是通过同一攻击路径下的行为变化直接验证的。`

---

## 第 8 页：一致性验证与测试覆盖

这一页回答“结果是不是可信”。

建议展示内容：

- 差分测试目标：
  比较 `direct backend` 和 `gateway-routed backend` 在相同 case 下是否保持一致语义
- 当前默认差分 case 共 `7` 个：
  - unauthorized_write
  - authorized_write
  - sequence_error
  - seed_request_without_extended_session
  - write_out_of_range_did
  - write_after_session_reset
  - double_seed_then_valid_key
- 差分结果：`7/7 matched = True`

建议代码切片：

- [src/hotpatch_uds/differential.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/differential.py:160)
- [src/hotpatch_uds/differential.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/differential.py:261)

建议结果表来源：

- [charts/DIFFERENTIAL_RESULTS_default.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/DIFFERENTIAL_RESULTS_default.md:9)

可补一句测试状态：

- 本地结果摘要显示：`50` 项通过，`3` 项跳过

页内总结句：

`当前实现不仅能跑 demo，而且 direct path 和 gateway-routed path 的 UDS 语义是一致的。`

---

## 第 9 页：核心评估结果总结

这一页是结果总表，建议做成三块：`fleet`、`timing`、`security benefit`。

建议展示内容：

### 1. Fleet-level 收益

- `OTA-only cumulative exposure window = 6605 min`
- `Hotpatch-first cumulative exposure window = 2787 min`
- `Relative reduction = 0.578`
- `time to first protection: 30 min -> 2 min`
- `time to 80% protection: 525 min -> 27 min`

### 2. 实时性与资源代价

- `reserved memory = 672 bytes`
- `peak quarantine = 64 bytes`
- `peak active code = 64 bytes`
- `validation = 0.4 ms`
- `scheduling = 0.23 ms`
- `guard = 0.05 ms`
- `application = 0.83 ms`
- `attack chain latency: 3.35 ms -> 3.5 ms`

### 3. 攻击阻挡效果

- `31` 次观测窗口攻击尝试
- `hotpatch block rate = 0.9355`
- `OTA-only block rate = 0.0323`

建议结果来源：

- [charts/HOTPATCH_EVALUATION_default.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/HOTPATCH_EVALUATION_default.md:1)
- [charts/FINAL_RESULTS_default.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/FINAL_RESULTS_default.md:1)
- [charts/THESIS_CHARTS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/THESIS_CHARTS_zh.md:72)

建议代码切片：

- [src/hotpatch_uds/evaluation.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/evaluation.py:79)
- [src/hotpatch_uds/fleet.py](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/src/hotpatch_uds/fleet.py:186)

页内总结句：

`当前结果支持 thesis 的核心判断：hotpatch-first 能显著缩短 OTA 前暴露窗口，且软件级代价较小。`

---

## 第 10 页：当前结论与后续工作安排

这一页作为最后一页。

建议分成两部分。

### 当前结论

- 已完成一个可运行的 `software-first` UDS/hotpatch 仿真环境
- 已复现多类 UDS 状态机与授权缺陷
- 已实现 Kintsugi 风格 hotpatch 生命周期模型
- 已完成差分测试、timing 评估和 fleet-level 策略比较
- 当前结果表明：`hotpatch-first` 相比 `OTA-only` 更早提供保护，并显著降低累计暴露时间

### 之后工作的安排

建议按优先级讲：

1. 补齐外部协议栈验证
   - 在本机继续跑通 `python-can + can-isotp + udsoncan`
   - 完整验证 `python-can virtual` 和 `python-can socketcan`
2. 推进 `vcan0 / SocketCAN` 路径
   - 把软件语义继续映射到 OS 级 CAN 通信层
3. 扩展差分测试对象
   - 后续接入 `iso14229`、`uds-c` 做跨实现差分比较
4. 推进到硬件与 RTOS 阶段
   - 用真实测量值替换当前 timing model
   - 验证 guard / patch activation 在更真实执行环境中的可行性
5. 完善 thesis 产出
   - 固化图表
   - 整理实验假设、限制和结论

建议引用：

- [PROJECT_STATUS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/PROJECT_STATUS_zh.md:126)
- [charts/FINAL_RESULTS_default.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/charts/FINAL_RESULTS_default.md:21)

最后一页收束句：

`下一阶段的重点不是继续堆功能，而是把当前软件级证据推进到更真实的协议栈、vcan0 环境和硬件/RTOS 实验。`

---

## 汇报时长建议

- 第 1 页：0.5 分钟
- 第 2-3 页：2 分钟
- 第 4-7 页：4 分钟
- 第 8-9 页：2.5 分钟
- 第 10 页：1 分钟

---

## 如果你想把 PPT 做得更像“阶段汇报”

可以把第 9 页之前再插入一页“当前完成情况”：

- 已完成：
  UDS 环境、ECU 状态机、gateway、hotpatch、fleet、timing、differential、fuzzing、tests
- 部分完成：
  第三方协议栈与 `vcan0` 统一验证
- 未开始或下一阶段：
  真实硬件、RTOS、外部实现差分

这一页可参考：

- [PROJECT_STATUS_zh.md](/home/beibei/Desktop/hotpatch-for-ecu-in-uds/PROJECT_STATUS_zh.md:15)
