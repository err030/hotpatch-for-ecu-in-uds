"""中文说明：
- 这个测试文件验证框架探测逻辑。
"""

import unittest

from src.hotpatch_uds.frameworks import (
    format_framework_status_lines,
    framework_readiness_summary,
    probe_python_frameworks,
)


class FrameworkProbeTests(unittest.TestCase):
    def test_probe_returns_expected_frameworks(self) -> None:
        statuses = probe_python_frameworks()

        self.assertEqual(len(statuses), 3)
        self.assertEqual(statuses[0].display_name, "python-can")
        self.assertEqual(statuses[1].display_name, "can-isotp")
        self.assertEqual(statuses[2].display_name, "udsoncan")

    def test_status_lines_are_human_readable(self) -> None:
        lines = format_framework_status_lines()

        self.assertEqual(len(lines), 3)
        self.assertTrue(any("python-can" in line for line in lines))

    def test_readiness_summary_mentions_missing_frameworks(self) -> None:
        summary = framework_readiness_summary()

        self.assertIn("frameworks still missing", summary)


if __name__ == "__main__":
    unittest.main()
