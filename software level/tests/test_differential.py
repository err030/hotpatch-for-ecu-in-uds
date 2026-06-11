"""中文说明：
- 这个测试文件验证 direct backend 和 gateway-routed backend 的差分一致性。
"""

import unittest

from src.hotpatch_uds.differential import (
    compare_case_across_backends,
    differential_detail_csv,
    differential_markdown_report,
    differential_summary_csv,
    default_local_backends,
    default_differential_cases,
    run_default_differential_suite,
)


class DifferentialTests(unittest.TestCase):
    def test_default_differential_suite_matches(self) -> None:
        comparisons = run_default_differential_suite()

        self.assertTrue(comparisons)
        self.assertTrue(all(comparison.matched for comparison in comparisons))

    def test_authorized_write_matches_across_backends(self) -> None:
        authorized_case = next(
            case for case in default_differential_cases() if case.name == "authorized_write"
        )
        comparison = compare_case_across_backends(
            authorized_case,
            backends=default_local_backends(),
        )

        self.assertTrue(comparison.matched)
        self.assertEqual(len(comparison.observations), 2)

    def test_extended_default_suite_size(self) -> None:
        cases = default_differential_cases()

        self.assertGreaterEqual(len(cases), 8)

    def test_differential_export_formats_include_known_case(self) -> None:
        comparisons = run_default_differential_suite()

        summary_csv = differential_summary_csv(comparisons)
        detail_csv = differential_detail_csv(comparisons)
        report_md = differential_markdown_report(comparisons)

        self.assertIn("authorized_write", summary_csv)
        self.assertIn("sequence_error", detail_csv)
        self.assertIn("# Differential Results", report_md)


if __name__ == "__main__":
    unittest.main()
