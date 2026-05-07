<!--
中文说明：
- 这个文件用于说明当前项目如何准备接入真实 `vcan / SocketCAN`，但目前还不真正连接。
- 它的作用是先把接入路径、代码对应层和后续变更范围讲清楚。
- 这份文件是工程准备说明，不是最终实验记录。
-->

# VCAN Preparation

## 当前状态

当前仓库已经新增一个不依赖第三方框架的 `SocketCAN / vcan0` backend：

- `src/hotpatch_uds/socketcan.py`
- `build_socketcan_direct_client_and_server(...)`
- `build_socketcan_gateway_routed_client_and_server(...)`

它直接使用 Python 标准库 `socket.AF_CAN`，因此当前就可以把现有 mock ECU /
gateway 挂到 Linux `vcan0`。

当前仓库仍然还没有真正使用：

- `python-can / can-isotp / udsoncan` 的已安装环境

当前仍然使用：

- `InMemoryCanBus` 作为默认 backend
- 本地 `IsoTpSender / IsoTpReassembler`
- 本地 `UdsClient`

同时已经新增了第三层可选接入路径：

- `build_python_can_virtual_direct_client_and_server(...)`
- `build_python_can_virtual_gateway_routed_client_and_server(...)`
- `build_python_can_socketcan_direct_client_and_server(...)`
- `build_python_can_socketcan_gateway_routed_client_and_server(...)`

## 接入后的层次映射

当前层次：

- `bus.py`
- `isotp.py`
- `transport.py`
- `client.py`

当前新增的中间层映射成：

- `socketcan.py` -> Linux `AF_CAN / CAN_RAW`
- `isotp.py` -> 当前本地 ISO-TP 分帧/重组
- `client.py` -> 当前本地 `UdsClient`

现在的第三方协议栈映射成：

- `pythoncan.py` -> `python-can`
- `pythoncan.py` -> `can-isotp`
- `pythoncan.py` -> `udsoncan` connection
- `transport.py` -> 当前统一 request/response 抽象

## 接入后的逻辑结构

当前可运行结构已经可以是：

```text
UdsClient
    ->
SocketCanIsoTpConnection
    ->
Linux AF_CAN raw socket
    ->
vcan0
```

后续目标结构再进一步变成：

```text
UdsClient / future udsoncan.Client
    ->
IsoTP connection
    ->
python-can / SocketCAN
    ->
vcan0
```

这和当前 `software-only` 结构是一一对应的，所以迁移难度是可控的。

## 当前代码里已经可复用的部分

后续接 `vcan` 以后，这些仍然可以继续保留：

- `ecu.py`
- `gateway.py`
- `scenarios.py`
- `fleet.py`
- `timing.py`
- 大部分测试逻辑

后续最可能被替换或包一层 adapter 的是：

- `bus.py`
- `isotp.py`
- `transport.py`
- `client.py`

## 建议的下一步

如果你要在 Ubuntu 虚拟机里实际跑起来，当前最直接的命令是：

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
python3 -m pip install python-can can-isotp udsoncan
python3 -m unittest tests.test_socketcan tests.test_pythoncan -v
```

当你准备继续把外部框架接进来时，最稳的顺序是：

1. 安装 `python-can`
2. 安装 `can-isotp`
3. 安装 `udsoncan`
4. 先跑 `python-can virtual`
5. 再切 `socketcan + vcan0`

## 为什么现在还不急着真接

因为 thesis 当前更重要的是：

- 把攻击链、状态机、patch 行为、fleet 比较和 timing model 先做扎实
- 然后再把 transport 层逐步替换成 `python-can / can-isotp / udsoncan`

这样范围更可控，论文结构也更稳。
