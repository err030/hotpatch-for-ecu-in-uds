"""
- 这个测试文件验证框架探测逻辑。
"""

import unittest

from src.hotpatch_uds.frameworks import (
    format_framework_status_lines,
    format_socketcan_status_lines,
    framework_readiness_summary,
    missing_framework_names,
    probe_python_frameworks,
    probe_socketcan_status,
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
        if missing_framework_names():
            self.assertIn("frameworks still missing", summary)
        else:
            self.assertIn("are available for vcan preparation", summary)

    def test_socketcan_probe_reports_boolean_capabilities(self) -> None:
        status = probe_socketcan_status()

        self.assertIsInstance(status.python_socketcan_supported, bool)
        self.assertIsInstance(status.interface_exists, bool)
        self.assertEqual(status.interface_name, "vcan0")

    def test_socketcan_status_lines_are_human_readable(self) -> None:
        lines = format_socketcan_status_lines()

        self.assertEqual(len(lines), 2)
        self.assertTrue(any("socketcan-python" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
