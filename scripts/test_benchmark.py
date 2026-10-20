"""Reporting regressions: partial or failed benchmark runs are never baselines."""

import unittest

from benchmark import parse_samples, successful


class ReportTests(unittest.TestCase):
    def report(self, count=3):
        return {"exit_code": 0, "failed_events": [], "output": [],
                "samples": [{"name": "BenchmarkLookup/fast/c32-4", "metrics": {"complete": 1}}
                            for _ in range(count)]}

    def test_complete_run(self):
        self.assertTrue(successful(self.report(), 3))

    def test_missing_samples(self):
        self.assertFalse(successful(self.report(2), 3))

    def test_no_benchmarks(self):
        self.assertFalse(successful(self.report(0), 3))

    def test_failed_process(self):
        report = self.report()
        report["exit_code"] = 1
        self.assertFalse(successful(report, 3))

    def test_failed_event(self):
        report = self.report()
        report["failed_events"].append({"Action": "fail"})
        self.assertFalse(successful(report, 3))

    def test_failed_output_with_zero_exit(self):
        report = self.report()
        report["output"].append("--- FAIL: BenchmarkLookup/fast/c256\n")
        self.assertFalse(successful(report, 3))

    def test_incomplete_results(self):
        report = self.report()
        report["samples"][0]["metrics"]["complete"] = 0
        self.assertFalse(successful(report, 3))

    def test_split_output_events(self):
        samples = parse_samples(["BenchmarkLookup/fast/c32-4\t", "1\t123 ns/op\t",
                                 "1.000 complete\t456 B/op\n", "PASS\n"])
        self.assertEqual(samples, [{"name": "BenchmarkLookup/fast/c32-4", "iterations": 1,
                                   "metrics": {"ns/op": 123, "complete": 1, "B/op": 456}}])


if __name__ == "__main__":
    unittest.main()
