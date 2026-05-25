<!--
中文说明：
- 这个文件用于对照 TODO.md 记录当前 software-first thesis 仿真的实现进度。
- 它的作用是说明哪些部分已经完成，哪些部分只是打了基础，哪些部分还没有开始。
- 这份文件偏向项目管理和 thesis 研究推进，不直接替代 README。
-->

# Project Status

## 当前判断标准

这里的状态按三类记录：

- `已完成`：仓库里已经有对应实现和测试，可以直接运行或验证。
- `部分完成`：已经有基础实现，但还没有达到 TODO 里想要的完整深度。
- `未开始`：当前仓库里还没有对应实现。

## 与 TODO.md 的对应进度

### 1. 完整的 UDS-over-CAN 软件实验环境

状态：`已完成`

当前已有：
- UDS request/response
- 简化 ISO-TP
- tester client
- target ECU mock
- gateway 模拟节点
- `tester -> gateway -> target ECU` 路径
- 原生 `SocketCAN / vcan0` backend
- `vcan0` 上的后台 ECU / gateway runtime
- `python-can virtual` backend
- `python-can socketcan` backend
- `python-can + can-isotp + udsoncan` 可选接入路径

### 2. 有状态的 ECU

状态：`已完成`

当前已有：
- current diagnostic session
- security access state
- failed attempts counter
- lockout timer
- configuration storage
- local periodic task tick

### 3. 一组攻击场景

状态：`已完成`

当前已有四类场景：
- 未经 `0x27` 成功授权直接执行 `0x2E`
- `0x27` 失败后旧 unlock 状态未清理
- session 切换后旧 unlock 状态仍保留
- 重放旧写请求

### 4. gateway 侧策略模拟

状态：`已完成`

当前已有三种模式：
- `open`
- `restricted`
- `misconfigured`

当前可研究：
- gateway 配置如何改变攻击面
- 为什么在 gateway 后面并不自动等于安全
- 为什么 routed diagnostics 仍然危险

### 5. hotpatch 行为模拟

状态：`已完成`

当前已有：
- `vulnerable`
- `patched`
- `patch_loading`
- `patch_activating`
- `patch_failed`
- patch rollback 行为、测试和演示脚本
- Kintsugi 风格 `quarantine / slot / validation / scheduling / guard-applicator`
- hotpatch 资源统计
- hotpatch 生命周期测试

### 6. UDS 状态机建模

状态：`已完成`

当前已有状态：
- default session
- extended session
- seed issued
- unlocked
- locked out

当前已有导出：
- 状态机图
- 攻击链图
- 漏洞位置图
- fleet 比较图

### 7. Fuzzing / negative testing

状态：`已完成`

当前已有：
- request sequence negative test
- repeated wrong key lockout test
- malformed payload length test
- malformed write payload test
- unexpected ISO-TP sequence number test
- 系统化 parser fuzzing corpus
- 系统化 state sequence corpus
- 系统化 ISO-TP frame anomaly corpus

说明：
- 当前已经完成 thesis 需要的系统化 fuzzing / negative testing
- 如果后续需要更强版本，可以再接 coverage-guided fuzzing 工具

### 8. 差分测试

状态：`已完成`

当前已有：
- `direct backend`
- `gateway-routed backend`
  两种实现路径的一致性差分测试
- 可选 `python-can virtual` backend 差分入口
- 可选 `python-can socketcan` backend 差分入口
- 差分测试框架和 case corpus
- 差分测试摘要 CSV
- 差分测试细节 CSV
- 差分测试 Markdown 导出

当前还缺：
- `iso14229`
- `uds-c`
  这些外部实现接入后的跨框架差分比较

### 9. fleet-level 抽象模拟

状态：`已完成`

当前已有：
- 默认 `100` 台车建模能力
- availability window
- OTA-only vs hotpatch-first
- exposure window
- response unavailable vehicle minutes
- total unavailable vehicle minutes

### 10. patch 对实时性的影响

状态：`已完成`

当前已有：
- 周期任务执行时间模型
- UDS handler 时间模型
- patch check overhead
- patch activation delay
- patch rollback delay
- vulnerable vs patched timing 比较表
- Kintsugi 风格 manager / guard / applicator 软件级时间统计
- software-level 资源 / 实时性 / 抵挡率综合评估

## 本轮新增的关键内容

- 修复了包名、README、测试和源码目录不一致的问题
- 新增了 `gateway.py`
- 把总线扩成支持 arbitration-id 过滤
- 把 transport 扩成支持 routed diagnostics
- 把 ECU 扩成更明确的状态机
- 新增了多种漏洞 ECU 变体
- 新增了 gateway 和负面测试
- 新增了 fleet-level OTA/hotpatch 抽象模拟
- 新增了 timing model
- 新增了 Mermaid 图表与 CSV 导出
- 新增了 framework probe、差分测试框架和系统化 fuzzing corpus
- 新增了三层 backend 矩阵
- 新增了 `python-can + can-isotp + udsoncan` 可选 runtime
- 新增了 Kintsugi 风格 hotpatch manager 模型
- 新增了 exposure window / resource / realtime / attack blocking rate 评估

## 建议的下一步优先级

1. 在本机安装 `python-can / can-isotp / udsoncan` 并实际跑通 `tests/test_pythoncan.py`
2. 在 `vcan0` 上跑通 `python-can socketcan` 路径
3. 把外部实现继续扩到 `iso14229 / uds-c` 差分比较
4. 最后再把 software-level 结论推进到真实硬件和 RTOS 上
