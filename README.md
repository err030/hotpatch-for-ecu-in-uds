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
- runtime patch 前后行为对比
- fleet-level `OTA-only` vs `hotpatch-first` 抽象策略比较
- timing model：UDS handler、周期任务抖动和 patch activation delay
- 差分测试：direct backend 与 gateway-routed backend 的一致性比较
- 系统化 fuzzing：parser、state sequence、ISO-TP 异常序号 corpus
- 多组攻击场景与负面测试
- 自动化测试

## 当前目录结构

```text
src/hotpatch_uds/
  protocol.py     # UDS 报文对象与编解码
  ecu.py          # mock ECU 状态机
  isotp.py        # 简化 ISO-TP
  bus.py          # 内存 CAN 总线
  gateway.py      # gateway 路由与策略模拟
  transport.py    # UDS payload 在 ISO-TP/CAN 上的同步往返
  client.py       # tester / attacker 侧最小 client
  server.py       # mock ECU server 包装与 patch 切换
  scenarios.py    # thesis 场景脚本
  fleet.py        # fleet-level OTA/hotpatch 抽象模拟
  timing.py       # timing model 与 patch 开销比较
  frameworks.py   # CAN/ISO-TP/UDS Python 框架探测
  differential.py # 差分测试框架
  fuzzing.py      # 系统化 fuzzing corpus
  main.py         # 命令行演示入口

tests/
  test_protocol.py
  test_isotp.py
  test_simulation.py
  test_gateway.py
  test_negative.py
  test_fleet.py
  test_fuzzish.py
  test_timing.py
  test_frameworks.py
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

## 当前设计边界

这版 still 是 `software-only simulation`，还没有接入：

- `python-can`
- `can-isotp`
- `udsoncan`
- 真实 SocketCAN / vcan
- 真实 CANable / MCP2515 / nRF52840
- 真实 `vcan + SocketCAN`
- `python-can / can-isotp / udsoncan`
- 差分测试
- 外部框架级差分测试
- 真实 `vcan0` 接入

这版的完成内容为：

1. 先把 gateway-routed UDS 行为和攻击链解释清楚
2. 先把 OTA-only 与 hotpatch-first 的 fleet-level 差异固定下来
3. 再把 transport、client 和 gateway 接到更真实的实现

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
