<!--
中文说明：
- 这个文件用于记录当前默认差分测试的导出结果。
- 结果比较的是 direct backend 和 gateway-routed backend 在相同 UDS 语义 case 下的行为是否一致。
-->

# Differential Results

## Summary

| Case | Backends | Matched | Steps |
|---|---|---:|---:|
| unauthorized_write | direct_patched_backend|gateway_routed_patched_backend | True | 2 |
| authorized_write | direct_patched_backend|gateway_routed_patched_backend | True | 4 |
| sequence_error | direct_patched_backend|gateway_routed_patched_backend | True | 2 |
| seed_request_without_extended_session | direct_patched_backend|gateway_routed_patched_backend | True | 1 |
| write_out_of_range_did | direct_patched_backend|gateway_routed_patched_backend | True | 4 |
| write_after_session_reset | direct_patched_backend|gateway_routed_patched_backend | True | 6 |
| double_seed_then_valid_key | direct_patched_backend|gateway_routed_patched_backend | True | 4 |

## Detailed Results

### unauthorized_write

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | False | 0x7F | 0x2E | 0x33 | 2e33 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | False | 0x7F | 0x2E | 0x33 | 2e33 |

### authorized_write

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| direct_patched_backend | 2 | True | 0x67 | - | - | 02 |
| direct_patched_backend | 3 | True | 0x6E | - | - | 1234 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| gateway_routed_patched_backend | 2 | True | 0x67 | - | - | 02 |
| gateway_routed_patched_backend | 3 | True | 0x6E | - | - | 1234 |

### sequence_error

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | False | 0x7F | 0x27 | 0x24 | 2724 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | False | 0x7F | 0x27 | 0x24 | 2724 |

### seed_request_without_extended_session

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | False | 0x7F | 0x27 | 0x22 | 2722 |
| gateway_routed_patched_backend | 0 | False | 0x7F | 0x27 | 0x22 | 2722 |

### write_out_of_range_did

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| direct_patched_backend | 2 | True | 0x67 | - | - | 02 |
| direct_patched_backend | 3 | False | 0x7F | 0x2E | 0x31 | 2e31 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| gateway_routed_patched_backend | 2 | True | 0x67 | - | - | 02 |
| gateway_routed_patched_backend | 3 | False | 0x7F | 0x2E | 0x31 | 2e31 |

### write_after_session_reset

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| direct_patched_backend | 2 | True | 0x67 | - | - | 02 |
| direct_patched_backend | 3 | True | 0x50 | - | - | 01 |
| direct_patched_backend | 4 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 5 | False | 0x7F | 0x2E | 0x33 | 2e33 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| gateway_routed_patched_backend | 2 | True | 0x67 | - | - | 02 |
| gateway_routed_patched_backend | 3 | True | 0x50 | - | - | 01 |
| gateway_routed_patched_backend | 4 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 5 | False | 0x7F | 0x2E | 0x33 | 2e33 |

### double_seed_then_valid_key

- matched: `True`
- backends: `direct_patched_backend, gateway_routed_patched_backend`

| Backend | Step | Positive | SID | Original SID | NRC | Data |
|---|---:|---:|---|---|---|---|
| direct_patched_backend | 0 | True | 0x50 | - | - | 03 |
| direct_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| direct_patched_backend | 2 | True | 0x67 | - | - | 011202 |
| direct_patched_backend | 3 | True | 0x67 | - | - | 02 |
| gateway_routed_patched_backend | 0 | True | 0x50 | - | - | 03 |
| gateway_routed_patched_backend | 1 | True | 0x67 | - | - | 011201 |
| gateway_routed_patched_backend | 2 | True | 0x67 | - | - | 011202 |
| gateway_routed_patched_backend | 3 | True | 0x67 | - | - | 02 |
