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
- `secure` board profile over `can0`: passed
  - profile: permissive/misconfigured gateway + strict ECU
  - validated by `software level/tools/uds_security_baseline_test.py --profile secure`
  - result: `19/19` checks passed
  - artifact: `software level/charts/hardware_secure_security_latest.csv`
- Legacy malformed-request checks over `secure` board profile: passed
  - validated by `software level/tools/cve_derived_uds_attack_test.py --profile secure`
  - result: `6/6` checks passed
  - artifact: `software level/charts/cve_derived_uds_attack_secure_latest.csv`
- UDS SecurityAccess-derived `0x2E` write attack over `secure` board profile: passed
  - validated by `software level/tools/uds_2e_security_access_attack_test.py`
  - result: `5/5` checks passed
  - key exposure: weak seed/key transform unlocks `0x27`, then `0x2E 0x1234 CAFE` succeeds and reads back via `0x22`
  - artifact: `software level/charts/uds_2e_security_access_attack_secure_latest.csv`
- UDS SecurityAccess-derived `0x2E` write attack over `hotpatched` board profile: blocked
  - profile: permissive/misconfigured gateway + strict ECU + ECU-local DID quarantine hotpatch
  - validated by `software level/tools/uds_2e_security_access_attack_test.py --expect hotpatched-block`
  - result: `5/5` checks passed
  - key exposure result: weak seed/key still unlocks `0x27`, but `0x2E 0x1234 CAFE` returns `7F2E31` and readback stays empty
  - artifact: `software level/charts/uds_2e_security_access_attack_hotpatched_latest.csv`
- Kintsugi-triggered runtime hotpatch over `kintsugi-runtime` board profile: passed
  - before trigger: `0x27 -> 0x2E` attack succeeds and reads back `CAFE`
  - trigger: `0x2E F190 01` returns `6EF190` after Kintsugi manager/applicator applies the gate patch
  - after trigger: weak seed/key still unlocks `0x27`, but `0x2E 0x1234 CAFE` returns `7F2E31`
  - artifacts: `software level/charts/uds_2e_security_access_attack_kintsugi_before_latest.csv`, `software level/charts/uds_2e_security_access_attack_kintsugi_after_latest.csv`
- `kintsugi-runtime` board profile after trigger over `can0`: passed
  - validated by `software level/tools/uds_security_baseline_test.py --profile hotpatched`
  - result: `19/19` checks passed
  - artifact: `software level/charts/hardware_kintsugi_runtime_after_security_latest.csv`
- `hotpatched` board profile over `can0`: passed
  - validated by `software level/tools/uds_security_baseline_test.py --profile hotpatched`
  - result: `19/19` checks passed
  - artifact: `software level/charts/hardware_hotpatched_security_latest.csv`
- Legacy malformed-request checks over `hotpatched` board profile: passed
  - validated by `software level/tools/cve_derived_uds_attack_test.py --profile hotpatched`
  - result: `6/6` checks passed
  - artifact: `software level/charts/cve_derived_uds_attack_hotpatched_latest.csv`
- `vulnerable` board profile over `can0`: passed
  - profile: permissive/misconfigured gateway + vulnerable ECU
  - validated by `software level/tools/uds_security_baseline_test.py --profile vulnerable`
  - result: `19/19` checks passed
  - key exposure: extended-session `0x2E` without unlock returns `6E1234`
  - artifact: `software level/charts/hardware_vulnerable_security_latest.csv`
- Legacy malformed-request checks over `vulnerable` board profile: passed
  - validated by `software level/tools/cve_derived_uds_attack_test.py --profile vulnerable`
  - result: `6/6` checks passed
  - artifact: `software level/charts/cve_derived_uds_attack_vulnerable_latest.csv`

## Hotpatch Evaluation

- UDS `0x27 -> 0x2E` mutation campaign: passed
  - corpus: deterministic `1000` mutated attempts around gateway-routed SecurityAccess-derived DID write
  - before hotpatch: `787/1000` attack successes, `78.70%` success rate
  - after hotpatch: `0/1000` attack successes, `100.00%` observed block/fail rate
  - valid attack-shaped cases: `787`, all `787` rejected by the hotpatched DID quarantine
  - artifacts: `software level/charts/uds_2e_mutation_attack_summary.csv`, `software level/charts/uds_2e_mutation_attack_detail.csv`, `software level/charts/uds_2e_mutation_attack_rates.svg`
- OTA-only cumulative exposure window: `6605` min
- Hotpatch-first cumulative exposure window: `2787` min
- Relative reduction: `0.578`
- Reserved memory footprint: `672` bytes
- Peak quarantine usage: `80` bytes
- Peak active code usage: `80` bytes
- Validation overhead: `0.45` ms
- Scheduling overhead: `0.26` ms
- Guard overhead: `0.06` ms
- Application overhead: `0.91` ms
- Vulnerable attack chain latency: `3.35` ms
- Patched attack chain latency: `3.5` ms
- Total attack attempts in observation window: `31`
- Hotpatch block rate: `0.9355`
- OTA-only block rate in same window: `0.0323`

## Interpretation

- The software-level model now spans semantic UDS behavior, CAN/ISO-TP/UDS stack integration, and OS-level `vcan0` communication.
- The hardware baseline now validates both vulnerable and secure UDS/security profiles over CANable2.0 / `can0` against the nRF52840 board.
- The vulnerable profile now shows the ECU-local vulnerability needed for the hotpatch story: routed `0x2E` reaches the ECU and succeeds without unlock in extended session.
- The SecurityAccess-derived `0x2E` attack shows the stronger hotpatch target: a routed, protocol-valid `0x27 -> 0x2E` sequence is not stopped by gateway policy and succeeds when the seed/key transform is weak.
- The hotpatched and Kintsugi-runtime profiles block that same sequence at ECU-local DID policy: `0x27` still succeeds, but authorized `0x2E` to high-risk DID `0x1234` is quarantined with `7F2E31`.
- The mutation campaign turns the single-chain result into a thesis chart: pre-hotpatch attack success is high but not perfect because the denominator includes plausible mutated attempts; post-hotpatch success is `0/1000` for the tested corpus.
- The current data supports the thesis claim that a Kintsugi-style hotpatch can reduce the OTA pre-update exposure window at modest software-level cost.
- Remaining risk should be stated explicitly: the `100.00%` post-hotpatch block/fail rate is an observed result over this deterministic corpus and the current hardware checks, not a formal proof over every UDS input sequence.
