"""
- 这个测试文件验证 timing model 的基本合理性。
"""

import unittest

from src.hotpatch_uds.protocol import SID_WRITE_DATA_BY_IDENTIFIER
from src.hotpatch_uds.timing import (
    TimingModelConfig,
    estimate_attack_chain_timing,
    estimate_periodic_task_jitter_ms,
    service_handler_latency_ms,
)


class TimingModelTests(unittest.TestCase):
    def test_patched_write_handler_is_slower_than_vulnerable(self) -> None:
        cfg = TimingModelConfig()
        vulnerable_latency = service_handler_latency_ms(
            SID_WRITE_DATA_BY_IDENTIFIER,
            patched=False,
            config=cfg,
        )
        patched_latency = service_handler_latency_ms(
            SID_WRITE_DATA_BY_IDENTIFIER,
            patched=True,
            config=cfg,
        )

        self.assertGreater(patched_latency, vulnerable_latency)

    def test_patched_attack_chain_has_higher_latency(self) -> None:
        vulnerable = estimate_attack_chain_timing(patched=False)
        patched = estimate_attack_chain_timing(patched=True)

        self.assertGreater(
            patched.total_attack_chain_latency_ms,
            vulnerable.total_attack_chain_latency_ms,
        )

    def test_periodic_task_jitter_is_non_negative(self) -> None:
        jitter = estimate_periodic_task_jitter_ms(
            write_handler_latency_ms=1.05,
            periodic_task_execution_ms=2.5,
            periodic_task_period_ms=10.0,
        )

        self.assertGreaterEqual(jitter, 0.0)


if __name__ == "__main__":
    unittest.main()
