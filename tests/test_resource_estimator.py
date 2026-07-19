"""Tests for analysis.resource.resource_estimator."""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.resource import analyze_source, analyze_to_dict, ResourceReport


def rpt(code: str) -> ResourceReport:
    return analyze_source(textwrap.dedent(code))


def flag_kinds(code: str) -> set[str]:
    return {f.kind for f in rpt(code).flags}


class TestLoopSignals(unittest.TestCase):

    def test_loop_nesting_depth(self):
        r = rpt("""
            for i in range(10):
                while i > 0:
                    for j in range(3):
                        pass
        """)
        self.assertEqual(r.loop_nesting_depth, 3)

    def test_while_true_flag(self):
        r = rpt("""
            while True:
                break
        """)
        self.assertIn("while_true", {f.kind for f in r.flags})

    def test_potentially_unbounded_while(self):
        r = rpt("""
            x = 0
            while check(x):
                x += 1
        """)
        self.assertIn("potentially_unbounded_loop", {f.kind for f in r.flags})


class TestRecursionSignals(unittest.TestCase):

    def test_recursion_presence(self):
        r = rpt("""
            def f(n):
                return f(n - 1)
        """)
        self.assertTrue(r.recursion_present)

    def test_recursive_without_base_flag(self):
        r = rpt("""
            def f(n):
                return f(n - 1)
        """)
        self.assertIn("recursive_no_base", {f.kind for f in r.flags})

    def test_recursive_with_obvious_base_not_flagged(self):
        r = rpt("""
            def fact(n):
                if n <= 1:
                    return 1
                return n * fact(n - 1)
        """)
        self.assertTrue(r.recursion_present)
        self.assertNotIn("recursive_no_base", {f.kind for f in r.flags})


class TestAllocationSignals(unittest.TestCase):

    def test_large_range_flag(self):
        r = rpt("for i in range(100000000):\n    pass")
        self.assertIn("large_range", {f.kind for f in r.flags})

    def test_suspicious_replication_flag(self):
        r = rpt("x = [0] * 100000000")
        self.assertIn("suspicious_allocation", {f.kind for f in r.flags})

    def test_suspicious_numpy_allocation_flag(self):
        r = rpt("""
            import numpy
            a = numpy.zeros((100000, 100000))
        """)
        self.assertIn("suspicious_allocation", {f.kind for f in r.flags})


class TestComplexityAndRisk(unittest.TestCase):

    def test_complexity_heuristic_nested_loops(self):
        r = rpt("""
            for i in items:
                for j in items:
                    pass
        """)
        self.assertEqual(r.complexity_heuristic, "O(n^2)")

    def test_complexity_recursion_without_base(self):
        r = rpt("""
            def f(n):
                return f(n + 1)
        """)
        self.assertEqual(r.complexity_heuristic, "Potentially unbounded / exponential")

    def test_low_risk(self):
        r = rpt("x = 1\nprint(x)")
        self.assertEqual(r.risk_score.value, "LOW")

    def test_medium_risk(self):
        r = rpt("for i in range(100000000):\n    pass")
        self.assertEqual(r.risk_score.value, "MEDIUM")

    def test_high_risk(self):
        r = rpt("""
            def f(n):
                return f(n + 1)

            while True:
                x = [0] * 100000000
        """)
        self.assertEqual(r.risk_score.value, "HIGH")


class TestSerialization(unittest.TestCase):

    def test_to_dict_shape(self):
        d = analyze_to_dict("while True:\n    break")
        self.assertIn("risk_score", d)
        self.assertIn("metrics", d)
        self.assertIn("flags", d)
        self.assertIn("summary", d)


if __name__ == "__main__":
    unittest.main()
