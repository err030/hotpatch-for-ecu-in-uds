<!--
中文说明：
- 这个文件用于说明当前项目的 `vcan / SocketCAN` 软件验证路径。
- 它同时说明 `vcan0` 和真实 CANable2.0 / `can0` 硬件路径的边界。
- 这份文件是工程状态说明，不是最终硬件实验记录。
-->

# VCAN Preparation

## 当前状态

当前仓库已经有一个不依赖第三方框架的 `SocketCAN / vcan0` backend：

- `src/hotpatch_uds/socketcan.py`
- `build_socketcan_direct_client_and_server(...)`
- `build_socketcan_gateway_routed_client_and_server(...)`

它直接使用 Python 标准库 `socket.AF_CAN`，因此当前就可以把现有 mock ECU /
gateway 挂到 Linux `vcan0`。

当前仓库也已经验证了第三方协议栈路径：

- `python-can virtual`
- `python-can socketcan + vcan0`
- `can-isotp`
- `udsoncan`

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

第三方协议栈结构已经可以是：

```text
UdsClient / udsoncan.Client
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

## 已验证的软件回归命令

在 Ubuntu 主机上准备 `vcan0` 后，可以跑：

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
python3 -m pip install python-can can-isotp udsoncan
python3 -m unittest tests.test_socketcan tests.test_pythoncan -v
```

当前完整软件回归也已经覆盖 `vcan0`：

```bash
python3 -m unittest discover -s tests -v
```

## 和 CANable2.0 的关系

`vcan0` 是 Linux virtual CAN，只用于主机内的 mock ECU / gateway 回归测试。
CANable2.0 发真实 CAN frame 时不需要 `vcan0`，而是需要把 CANable 拉成
真实 SocketCAN 接口，例如 `can0`。

如果 CANable2.0 是 `slcan` 固件，使用：

```bash
sudo slcand -o -f -s5 /dev/serial/by-id/<CANable2.0-device> can0
sudo ip link set up can0
```

如果 CANable2.0 是 candleLight / `gs_usb` 固件，通常使用：

```bash
sudo ip link set can0 type can bitrate 250000
sudo ip link set up can0
```

## 下一步

软件栈已经验证到 `vcan0`。后续重点应转到：

- CANable2.0 / `can0` 到 nRF52840 baseline 的真实请求记录
- C dispatcher 的 host 单元测试和 Python corpus 对齐
- Kintsugi guard / applicator / MPU 的硬件闭环
