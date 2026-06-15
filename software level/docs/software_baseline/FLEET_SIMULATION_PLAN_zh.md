<!--
- 这个文件用于说明 thesis 中 fleet-level 抽象模拟应该怎么做。
- 它的作用是把当前已经完成的 UDS/hotpatch 软件原型，扩展到车队 OTA-only vs hotpatch-first的策略比较。
- 这份文件偏向实现设计与研究方法。
-->

# Fleet Simulation Plan

## 一、这个 fleet 抽象模拟到底要做什么

这里要做的是一个**策略级别的抽象模拟**，并回答这几个问题：

- 只用 `OTA-only` 时，车队多久才能被保护？
- 先做 `hotpatch-first` 再做完整 OTA 时，车队多久才能被保护？
- 两种策略下，累计暴露时间差多少？
- 两种策略下，累计不可用车辆时间差多少？

这个模拟服务于 thesis 的 motivation 和 evaluation。

## 二、为什么适合做抽象模拟

thesis 重点是：

- `gateway-adjacent diagnostic ECU` 上的局部 UDS 漏洞
- `real-time hotpatch` 能否更早提供保护
- 在 fleet 层面，这种更早保护是否有意义

所以 fleet 部分只需要做到：

- 把单车的 patch/OTA 时间抽象出来
- 把车队的 availability 和并发更新限制抽象出来
- 比较两种更新策略的结果

## 三、最适合的实现方式

### 推荐方案

第一版最适合用：

- **离散事件模拟**

原因：

- 系统天然是事件驱动的
- 有开始时间、结束时间、等待窗口、并发资源、完成事件
- 指标也天然是时间相关指标

### 第一版不建议直接用很重的 fleet framework

例如：

- 不建议一开始就接 `FleetPy`
- 不建议一开始就接真实路网
- 不建议一开始就模拟乘客匹配、路径规划、交通拥堵

这些内容和你的 thesis 主问题耦合不强，会把范围做大。

## 四、推荐的开源参考

### 1. SimPy

这是最适合你第一版 fleet 抽象模拟的参考。

理由：

- 它就是做离散事件模拟的
- 可以很自然地表示：
  - 车辆可用窗口
  - 更新资源容量
  - patch/OTA 的开始和结束
  - 等待队列
- 代码会比较短，适合 bachelor thesis

官方文档：
- [SimPy documentation](https://simpy.readthedocs.io/en/stable/)

官方源码主仓库：
- [team-simpy/simpy (GitLab)](https://gitlab.com/team-simpy/simpy)

说明：
- SimPy 的主项目在 GitLab，不是 GitHub
- 但它是最适合你这个 fleet 抽象模拟的参考

### 2. Mesa

如果你想把每辆车建成一个 agent，也可以参考 Mesa。

GitHub：
- [projectmesa/mesa](https://github.com/projectmesa/mesa)

适合用途：
- 多 agent 建模
- 可视化
- 更强调 agent behavior

不适合你的地方：
- 对你当前这个 thesis，Mesa 比较重
- 第一版其实没有必要上 agent-based framework

### 3. FleetPy

如果你想参考“真实车队仿真框架长什么样”，可以看 FleetPy。

GitHub：
- [TUM-VT/FleetPy](https://github.com/TUM-VT/FleetPy)

适合用途：
- 看自动驾驶/按需出行车队仿真的结构
- 看 vehicle / operator / task / result logging 的组织方式

不适合你的地方：
- 它太重
- 它的重点是车队运营与路由，不是 OTA / hotpatch
- 你不应该直接把 thesis 建在它上面

### 4. 与你当前 UDS 原型继续相关的协议项目

这些不直接做 fleet 模拟，但后面可以和当前项目继续对接：

- [pylessard/python-udsoncan](https://github.com/pylessard/python-udsoncan)
- [pylessard/python-can-isotp](https://github.com/pylessard/python-can-isotp)
- [hardbyte/python-can](https://github.com/hardbyte/python-can)
- [driftregion/iso14229](https://github.com/driftregion/iso14229)
- [openxc/uds-c](https://github.com/openxc/uds-c)

它们的作用主要是：

- 给你更真实的 UDS/ISO-TP/CAN 层参考
- 不负责 fleet 策略模拟

## 五、我建议你怎么实现

### 第一版只做两个策略

#### 策略 A：OTA-only

流程：

1. 漏洞公开
2. 车辆等待可用窗口
3. 车辆进入 OTA 队列
4. 执行完整 OTA
5. 车辆被保护

#### 策略 B：hotpatch-first

流程：

1. 漏洞公开
2. 车辆等待短可用窗口
3. 车辆先执行 hotpatch
4. 车辆先被保护
5. 之后在更宽松窗口里完成完整 OTA

### 每辆车至少要有这些属性

- `vehicle_id`
- `priority`
- `available_windows`
- `hotpatch_capable`
- `ota_duration`
- `hotpatch_duration`
- `state`

其中 `state` 可以是：

- `vulnerable`
- `waiting_hotpatch`
- `hotpatching`
- `hotpatched`
- `waiting_ota`
- `ota_updating`
- `ota_updated`

### 整个 fleet 模型至少要有这些全局参数

- `fleet_size`
- `ota_slots`
- `hotpatch_slots`
- `campaign_start_time`
- `simulation_end_time`
- `availability_window_model`

### 事件类型建议

- `vulnerability_disclosed`
- `vehicle_window_open`
- `hotpatch_start`
- `hotpatch_finish`
- `ota_start`
- `ota_finish`

## 六、最小实现的数据流

### 输入

fleet 抽象模拟的输入，建议来自两个地方：

#### 1. 你当前 UDS/hotpatch 原型

提供：

- patch 前后是否成功阻断攻击
- patch 激活需要多少步骤
- patch 逻辑是否成功

后面如果接硬件，再替换成更真实的时间测量。

#### 2. 你自己定义的 fleet 参数

例如：

- `fleet_size = 100`
- `ota_slots = 5`
- `hotpatch_slots = 20`
- `ota_duration = 30 min`
- `hotpatch_duration = 2 min`
- 每辆车每天只有几个短窗口可更新

### 输出

第一版只输出这几个指标就够：

- `time_to_first_protection`
- `time_to_80_percent_protection`
- `cumulative_exposure_window`
- `cumulative_unavailable_vehicle_minutes`

## 七、你可以直接写进 thesis 的建模假设

为了控制范围，fleet 抽象模拟可以先采用这些假设：

- 所有车辆针对同一个漏洞
- 每辆车只关注一个目标 ECU
- hotpatch 是局部修复，执行时间明显短于完整 OTA
- OTA 需要更长的不可用时间
- 车队更新能力受并发 slot 限制
- 车辆不是任意时刻都可更新

这些假设是合理的，而且能直接支持 thesis 主问题。

## 八、为什么这部分有研究价值

因为它把 thesis 的两层结果连起来了：

### 单车层面

- patch 前攻击成功
- patch 后攻击被阻断

### 车队层面

- hotpatch-first 更早提供保护
- exposure window 更短
- unavailable vehicle minutes 可能更低

这会让你的 thesis 从“单个 ECU prototype”变成“局部安全修复 + fleet-level operational meaning”。

## 九、建议的仓库实现顺序

### 第一步

先在当前仓库里新建：

- `src/hotpatch_uds/fleet.py`

放：

- `FleetVehicle`
- `FleetConfig`
- `FleetMetrics`
- `simulate_ota_only()`
- `simulate_hotpatch_first()`

### 第二步

新建：

- `tests/test_fleet.py`

先验证：

- hotpatch-first 的 `time_to_first_protection` 小于 OTA-only
- hotpatch-first 的 `cumulative_exposure_window` 小于 OTA-only

### 第三步

再决定是否：

- 接 `SimPy`
- 或先用你自己写的小型事件队列

## 十、我给你的直接建议

### 最稳的路线

如果你现在就要开始做，我建议：

1. 第一版不用 FleetPy，不用 Mesa
2. 第一版直接做一个小型离散事件模拟器
3. 结构先做简单
4. 指标先跑通
5. 之后如果你觉得需要，再替换成 SimPy

### 原因

因为你的 thesis 重点仍然在：

- UDS
- gateway-adjacent diagnostic ECU
- hotpatch
- OTA-only vs hotpatch-first

fleet 模拟只是把这些结果提升到车队层面，不应该反过来主导整个项目。

## 十一、结论

结论很明确：

- 你的 fleet 抽象模拟最适合做成**离散事件模拟**
- 最合适的开源参考是 **SimPy**
- 如果你要看更完整的车队框架，可以参考 **FleetPy**
- 如果你要看 agent-based 风格，可以参考 **Mesa**
- 但你的第一版实现最好继续留在当前仓库里自己写，这样最贴合 thesis，也最容易控制范围
