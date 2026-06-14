# Hotpatch Evaluation

## Exposure Window

- OTA-only cumulative exposure window: `6605` min
- Hotpatch-first cumulative exposure window: `2787` min
- Relative reduction: `0.578`

## Resource Utilization

- Reserved memory footprint: `672` bytes
- Peak quarantine usage: `80` bytes
- Peak active code usage: `80` bytes

## Real-Time Overhead

- Validation overhead: `0.45` ms
- Scheduling overhead: `0.26` ms
- Guard overhead: `0.06` ms
- Application overhead: `0.91` ms
- Vulnerable attack chain latency: `3.35` ms
- Patched attack chain latency: `3.5` ms

## Attack Resistance

- Total attack attempts in observation window: `31`
- Hotpatch block rate: `0.9355`
- OTA-only block rate in same window: `0.0323`