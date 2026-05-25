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

tests.test_pythoncan：本地跑通，virtual 3 项通过；socketcan 3 项在当前 Codex 会话里因 raw CAN 权限限制而 skip
tests.test_socketcan：你已经在 Ubuntu VM 里跑通
带本地依赖前缀的全量测试：50 项通过，3 项跳过
