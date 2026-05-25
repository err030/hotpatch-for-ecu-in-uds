<!--
中文说明：
- 这个文件用于检查当前 thesis 项目相关的 CAN / ISO-TP / UDS 框架。
- 它的作用是说明：当前项目已经自己实现了什么，外部开源框架各自负责什么，当前环境里哪些已经安装，后续应该按什么顺序接入。
- 这份文件偏向工程接入与 research 支撑，不直接替代论文正文。
-->

# Framework Audit

## 当前环境检查

当前 Python 环境检查结果：

- `python-can`：未安装
- `can-isotp`：未安装
- `udsoncan`：未安装

这意味着：

- 当前仓库仍然完全依赖本地 `in-memory` 仿真
- 现在可以先继续完善接口、测试和差分框架
- 后续一旦安装这些依赖，就可以逐步接真实 `virtual` 或 `SocketCAN` 后端

## 当前项目自己已经实现的内容

当前仓库已经自己实现了这些层：

- `protocol.py`
  - UDS request / response 编码和解码
- `isotp.py`
  - 简化 ISO-TP
- `bus.py`
  - 内存 CAN 总线
- `transport.py`
  - tester 与 ECU 的同步 request-response 交互
- `gateway.py`
  - gateway routing policy
- `ecu.py`
  - 有状态 ECU + 多种漏洞变体

所以当前仓库不是“什么都没有”，而是已经有一个完整的 software-only pipeline。

## 外部开源框架各自负责什么

### python-can

作用：

- 提供 CAN bus 抽象
- 支持 `virtual`、`socketcan` 等 backend
- 后续可以替换当前的 `InMemoryCanBus`

官方仓库：
- [hardbyte/python-can](https://github.com/hardbyte/python-can)

官方文档：
- [python-can virtual interface docs](https://python-can.readthedocs.io/en/v4.2.2/interfaces/virtual.html)

### can-isotp

作用：

- 提供 ISO-TP transport
- 支持 user-space 实现
- 也支持 Linux ISO-TP socket 的简化封装
- 后续可以替换当前的 `isotp.py` 和部分 `transport.py`

官方仓库：
- [pylessard/python-can-isotp](https://github.com/pylessard/python-can-isotp)

官方文档：
- [can-isotp docs](https://can-isotp.readthedocs.io/)

### udsoncan

作用：

- 提供同步 UDS client
- 负责构建 request、发送请求、解析 response
- 后续可以替换当前的 `client.py` 一部分职责

官方仓库：
- [pylessard/python-udsoncan](https://github.com/pylessard/python-udsoncan)

官方文档：
- [udsoncan client docs](https://udsoncan.readthedocs.io/en/latest/udsoncan/client.html)

### SocketCAN / Linux ISO-TP

作用：

- 提供 Linux 内核级 CAN 与 ISO-TP socket
- 后续做真实 `vcan0` 或真实 CAN 接入时会用到

官方文档：
- [Linux SocketCAN docs](https://docs.kernel.org/networking/can.html)
- [Linux ISO-TP docs](https://docs.kernel.org/networking/iso15765-2.html)

### iso14229

作用：

- 面向 embedded systems 的 UDS server/client
- 后续很适合做“外部实现参考”或差分测试对象

官方仓库：
- [driftregion/iso14229](https://github.com/driftregion/iso14229)

官方文档：
- [iso14229 docs](https://driftregion.github.io/iso14229/)

### uds-c

作用：

- 平台无关的 C 版 UDS 库
- 更适合做 reference behavior 对比

官方仓库：
- [openxc/uds-c](https://github.com/openxc/uds-c)

## 目前最合理的接入顺序

建议顺序：

1. `python-can`
2. `can-isotp`
3. `udsoncan`
4. `SocketCAN / vcan`
5. `iso14229 / uds-c` 差分测试

原因：

- `python-can` 是最底层的 bus abstraction
- `can-isotp` 建在 CAN transport 之上
- `udsoncan` 再建在 ISO-TP connection 之上
- `iso14229 / uds-c` 更适合后面做跨实现行为对比

## 当前已经为后续接入做好的准备

当前仓库已经补了这些准备层：

- `frameworks.py`
  - 检查依赖是否安装
- `differential.py`
  - 先比较 direct backend 和 gateway-routed backend
- `fuzzing.py`
  - 生成系统化 fuzzing / negative corpus

这意味着后续真正装上框架后，不需要推翻当前项目结构。
