"""
- 这个测试文件验证软件级 hotpatch 评估输出。
"""

import unittest

from src.hotpatch_uds.evaluation import (
    evaluate_default_hotpatch_value,
    hotpatch_evaluation_csv,
    hotpatch_evaluation_markdown,
)


class HotpatchEvaluationTests(unittest.TestCase):
    def test_default_evaluation_shows_exposure_reduction(self) -> None:
        summary = evaluate_default_hotpatch_value()

        self.assertGreater(summary.exposure_window_reduction_ratio, 0.0)
        self.assertGreater(
            summary.attack_resistance.hotpatch_block_rate,
            summary.attack_resistance.ota_only_block_rate,
        )

    def test_export_formats_include_key_metrics(self) -> None:
        summary = evaluate_default_hotpatch_value()
        csv_text = hotpatch_evaluation_csv(summary)
        markdown = hotpatch_evaluation_markdown(summary)

        self.assertIn("reserved_memory_bytes", csv_text)
        self.assertIn("exposure_window_reduction_ratio", csv_text)
        self.assertIn("# Hotpatch Evaluation", markdown)
        self.assertIn("## Attack Resistance", markdown)


if __name__ == "__main__":
    unittest.main()
