# hotpatch-for-ecu-in-uds

这是一个面向 bachelor thesis 的 `software-first` 仿真仓库。当前目标是先把 UDS attack flow、mock ECU、简化 ISO-TP 和 runtime patch 行为在软件里跑通，并无硬件部分，全由python模拟。

## 当前完成了什么

当前版本已经具备下面这些部分：

- 标准风格的 UDS request/response 编码与解析
- 带 session / unlock / failed attempts / lockout / periodic tick 的 mock ECU 状态机
- `0x10 -> 0x27 -> 0x2E` 服务链
- `tester -> gateway -> target ECU` 的 routed diagnostics 路径
- `open / restricted / misconfigured` 三种 gateway 策略基础模型
- vulnerable / patched / patchable 以及多种授权缺陷 ECU 行为
- 简化版 ISO-TP 分帧与重组
- 内存中的虚拟 CAN 总线和 arbitration-id 过滤
- 同步的 client/server request-response 过程
- 三层 backend 矩阵：`in-memory` / `python-can virtual` / `python-can socketcan`
- 可选的 `python-can + can-isotp + udsoncan` 第三方协议栈接入
- 可选的 Linux `SocketCAN / vcan0` backend
- 可选的后台 ECU server / gateway runtime，能把当前 mock ECU 挂到 `vcan0`
- Kintsugi 风格的 hotpatch manager / slot / quarantine / guard-applicator 软件模型
- runtime patch 前后行为对比
- fleet-level `OTA-only` vs `hotpatch-first` 抽象策略比较
- timing model：UDS handler、周期任务抖动和 patch activation delay
- 差分测试：direct backend 与 gateway-routed backend 的一致性比较
- software-level 评估：exposure window、资源利用率、实时性、攻击阻挡率
- 系统化 fuzzing：parser、state sequence、ISO-TP 异常序号 corpus
- 多组攻击场景与负面测试
- 自动化测试

## 当前目录结构

```text
src/hotpatch_uds/
  backends.py     # 三层 backend 定义与可用性摘要
  protocol.py     # UDS 报文对象与编解码
  ecu.py          # mock ECU 状态机
  isotp.py        # 简化 ISO-TP
  bus.py          # 内存 CAN 总线
  gateway.py      # gateway 路由与策略模拟
  transport.py    # UDS payload 在 ISO-TP/CAN 上的同步往返
  pythoncan.py    # python-can + can-isotp + udsoncan runtime
  socketcan.py    # Linux SocketCAN / vcan runtime
  client.py       # tester / attacker 侧最小 client
  hotpatch.py     # Kintsugi 风格 hotpatch manager/slot/guard 模型
  server.py       # mock ECU server 包装与 patch 切换
  scenarios.py    # thesis 场景脚本
  fleet.py        # fleet-level OTA/hotpatch 抽象模拟
  timing.py       # timing model 与 patch 开销比较
  frameworks.py   # CAN/ISO-TP/UDS Python 框架探测
  differential.py # 差分测试框架
  evaluation.py   # software-level 风险/资源/实时性评估
  fuzzing.py      # 系统化 fuzzing corpus
  main.py         # 命令行演示入口

tests/
  test_hotpatch.py
  test_evaluation.py
  test_pythoncan.py
  test_protocol.py
  test_isotp.py
  test_simulation.py
  test_gateway.py
  test_negative.py
  test_fleet.py
  test_fuzzish.py
  test_timing.py
  test_frameworks.py
  test_socketcan.py
  test_differential.py
  test_systematic_fuzzing.py
```

## 运行方式

### 直接跑演示

```bash
python3 -m src.hotpatch_uds.main
```

### 跑测试

```bash
python3 -m unittest discover -s tests -v
```

### 三层 backend

当前仓库把通信层整理成三层：

1. `in-memory`
   当前默认 backend。继续使用本地 `InMemoryCanBus + IsoTpSender/Reassembler + UdsClient`。
2. `python-can virtual`
   保留现有 ECU / gateway / hotpatch 逻辑，只把底层切到 `python-can + can-isotp + udsoncan`，但不依赖 OS 级 CAN 设备。
3. `python-can socketcan`
   同样的上层结构，底层再切到 Linux `socketcan + vcan0`。

这三层的目标是：

- 先保证 thesis 模型和测试在 `in-memory` 稳定
- 再用 `python-can virtual` 验证第三方协议栈集成
- 最后把相同结构推进到 `vcan0`

### 跑 `python-can virtual` 集成测试

先安装可选依赖：

```bash
python3 -m pip install python-can can-isotp udsoncan
```

然后执行：

```bash
python3 -m unittest tests.test_pythoncan -v
```

### 跑 `vcan0` 集成测试

先在 Ubuntu 上准备 `vcan0`：

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

然后执行：

```bash
python3 -m unittest tests.test_socketcan tests.test_pythoncan -v
```

如果想在自己的脚本里直接把当前 mock ECU 挂到第三方协议栈，可以使用：

```python
from src.hotpatch_uds.ecu import PatchedECU
from src.hotpatch_uds.scenarios import build_python_can_socketcan_gateway_routed_client_and_server
from src.hotpatch_uds.server import MockEcuServer

live = build_python_can_socketcan_gateway_routed_client_and_server(
    MockEcuServer(PatchedECU()),
    interface="vcan0",
)
try:
    result = live.client.change_to_extended_session()
    print(result.response)
finally:
    live.close()
```

如果只想跑当前仓库自己的 raw SocketCAN backend，可以使用：

```python
from src.hotpatch_uds.ecu import PatchedECU
from src.hotpatch_uds.scenarios import build_socketcan_gateway_routed_client_and_server
from src.hotpatch_uds.server import MockEcuServer

live = build_socketcan_gateway_routed_client_and_server(
    MockEcuServer(PatchedECU()),
    interface="vcan0",
)
try:
    result = live.client.change_to_extended_session()
    print(result.response)
finally:
    live.close()
```

### 生成 software-level 评估结果

```bash
python3 charts/export_hotpatch_evaluation.py
```

它会生成：

- `charts/hotpatch_evaluation_default.csv`
- `charts/HOTPATCH_EVALUATION_default.md`
- `charts/hotpatch_evaluation_default.svg`

## 当前设计边界

这版仍以 `software-first simulation` 为主，但现在已经可以：

- 在 `in-memory` backend 上稳定复现实验语义
- 在可选的 `python-can + can-isotp + udsoncan` backend 上复用同一套 ECU / gateway
- 在 `socketcan + vcan0` 上推进到 OS 级 CAN 层

当前还没有接入：

- 真实 CANable / MCP2515 / nRF52840
- 外部框架级差分测试
- 真实硬件上的 Kintsugi 式 guard / MPU / context-switch integration
- 真正的 RTOS task context / IRQ preemption 级 hotpatch 应用

这版的完成内容为：

1. 先把 gateway-routed UDS 行为和攻击链解释清楚
2. 先把 OTA-only 与 hotpatch-first 的 fleet-level 差异固定下来
3. 再把 transport、client 和 gateway 渐进式接到更真实的实现
4. 再用 Kintsugi 风格的软件模型评估 hotpatch 是否理论上缩短 OTA 前 exposure window

## 参考来源

当前实现主要参考这些开源项目和公开文档的建模思路：

- `python-udsoncan`  
  https://github.com/pylessard/python-udsoncan
- `udsoncan documentation`  
  https://udsoncan.readthedocs.io/en/latest/
- `python-can-isotp`  
  https://github.com/pylessard/python-can-isotp
- `can-isotp documentation`  
  https://can-isotp.readthedocs.io/
- `python-can`  
  https://github.com/hardbyte/python-can
- `python-can virtual bus documentation`  
  https://python-can.readthedocs.io/en/stable/interfaces/virtual.html
- `Linux kernel ISO-TP documentation`  
  https://docs.kernel.org/networking/iso15765-2.html

这些来源用于帮助定义行为、层次和接口风格；当前仓库代码为 thesis 需求重新实现，没有直接复制其代码。
