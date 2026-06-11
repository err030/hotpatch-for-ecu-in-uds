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

## Hardware Baseline Validation

- `nRF52840 + FreeRTOS + MCP2515` baseline: flashed, verified and reset through J-Link
- `CANable2.0 slcan + can0` security baseline: passed
  - validated by `software level/tools/uds_security_baseline_test.py`
  - result: `19/19` checks passed
  - artifact: `software level/charts/hardware_baseline_security_latest.csv`
- CVE-derived UDS attack checks over `can0`: passed
  - validated by `software level/tools/cve_derived_uds_attack_test.py`
  - result: `6/6` checks passed
  - artifact: `software level/charts/cve_derived_uds_attack_latest.csv`

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
- The hardware baseline now validates the same UDS/security rules over CANable2.0 / `can0` against the nRF52840 board.
- The current data supports the thesis claim that a Kintsugi-style hotpatch can reduce the OTA pre-update exposure window at modest software-level cost.
- The next evidence step is to carry the validated baseline into secure/demo board profiles, C-side host tests, full ISO-TP decisions, and the hardware/RTOS hotpatch phase.
