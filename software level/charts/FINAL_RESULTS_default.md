# Final Results

## Protocol Stack Validation

- `in-memory`: passed
  - validated by the default local unit-test suite
- `python-can virtual + can-isotp + udsoncan`: passed
  - validated by `tests.test_pythoncan`
- `raw SocketCAN backend on vcan0`: passed
  - validated on the Ubuntu VM with `tests.test_socketcan`
- `python-can socketcan + can-isotp + udsoncan on vcan0`: passed
  - validated on the Ubuntu VM with `tests.test_pythoncan`

## Hotpatch Evaluation

- OTA-only cumulative exposure window: `6605` min
- Hotpatch-first cumulative exposure window: `2787` min
- Relative reduction: `0.578`
- Reserved memory footprint: `672` bytes
- Peak quarantine usage: `64` bytes
- Peak active code usage: `64` bytes
- Validation overhead: `0.4` ms
- Scheduling overhead: `0.23` ms
- Guard overhead: `0.05` ms
- Application overhead: `0.83` ms
- Vulnerable attack chain latency: `3.35` ms
- Patched attack chain latency: `3.5` ms
- Total attack attempts in observation window: `31`
- Hotpatch block rate: `0.9355`
- OTA-only block rate in same window: `0.0323`

## Interpretation

- The software-level model now spans semantic UDS behavior, CAN/ISO-TP/UDS stack integration, and OS-level `vcan0` communication.
- The current data supports the thesis claim that a Kintsugi-style hotpatch can reduce the OTA pre-update exposure window at modest software-level cost.
- The next evidence step is to execute the formal `python-can socketcan` tests and then carry the same metrics into the hardware/RTOS phase.
