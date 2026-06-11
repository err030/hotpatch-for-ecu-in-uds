# Hotpatch Evaluation

## Exposure Window

- OTA-only cumulative exposure window: `6605` min
- Hotpatch-first cumulative exposure window: `2787` min
- Relative reduction: `0.578`

## Resource Utilization

- Reserved memory footprint: `672` bytes
- Peak quarantine usage: `64` bytes
- Peak active code usage: `64` bytes

## Real-Time Overhead

- Validation overhead: `0.4` ms
- Scheduling overhead: `0.23` ms
- Guard overhead: `0.05` ms
- Application overhead: `0.83` ms
- Vulnerable attack chain latency: `3.35` ms
- Patched attack chain latency: `3.5` ms

## Attack Resistance

- Total attack attempts in observation window: `31`
- Hotpatch block rate: `0.9355`
- OTA-only block rate in same window: `0.0323`


## 中文

当前能确认的数据：

OTA-only cumulative exposure window: 6605 min
Hotpatch-first cumulative exposure window: 2787 min
Relative reduction: 0.578
Reserved memory footprint: 672 bytes
Peak quarantine usage: 64 bytes
Peak active code usage: 64 bytes
Validation overhead: 0.4 ms
Scheduling overhead: 0.23 ms
Guard overhead: 0.05 ms
Application overhead: 0.83 ms
Vulnerable attack chain latency: 3.35 ms
Patched attack chain latency: 3.5 ms
Hotpatch block rate: 0.9355
OTA-only block rate: 0.0323
测试状态现在是：

tests.test_pythoncan：virtual 3 项通过，socketcan/vcan0 3 项通过
tests.test_socketcan：raw SocketCAN/vcan0 3 项通过
全量软件回归：60 项通过，0 项跳过
