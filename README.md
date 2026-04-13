# hotpatch-for-ecu-in-uds

这是一个面向 bachelor thesis 的 `software-first` 仿真仓库。当前目标是先把 UDS attack flow、mock ECU、简化 ISO-TP 和 runtime patch 行为在软件里跑通，并无硬件部分，全由python模拟。

## 当前完成了什么

当前版本已经具备下面这些部分：

- 标准风格的 UDS request/response 编码与解析
- 最小可用的 mock ECU 状态机
- `0x10 -> 0x27 -> 0x2E` 服务链
- vulnerable / patched / patchable 三种 ECU 行为
- 简化版 ISO-TP 分帧与重组
- 内存中的虚拟 CAN 总线
- 同步的 client/server request-response 过程
- runtime patch 前后行为对比
- 自动化测试

## 当前目录结构

```text
src/hotpatch_uds_sim/
  protocol.py     # UDS 报文对象与编解码
  ecu.py          # mock ECU 状态机
  isotp.py        # 简化 ISO-TP
  bus.py          # 内存 CAN 总线
  transport.py    # UDS payload 在 ISO-TP/CAN 上的同步往返
  client.py       # tester / attacker 侧最小 client
  server.py       # mock ECU server 包装与 patch 切换
  scenarios.py    # thesis 场景脚本
  main.py         # 命令行演示入口

tests/
  test_protocol.py
  test_isotp.py
  test_simulation.py
```

## 运行方式

### 直接跑演示

```bash
python3 -m src.hotpatch_uds_sim.main
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

这版的完成内容为：

1. 先把 UDS 行为和攻击链解释清楚
2. 先把 vulnerable / patched 差异固定下来
3. 再把 transport 和 client 替换成更真实的实现

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
