"""Tests for analysis.decision.engine."""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.capability import analyze_to_dict as capability_to_dict
from analysis.decision import ExternalAccessPolicy, SafetyDecisionEngine
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.taint import analyze_to_dict as taint_to_dict


def analyze_inputs(code: str) -> tuple[dict, dict, dict]:
    src = textwrap.dedent(code)
    return (
        taint_to_dict(src),
        capability_to_dict(src, name="<test>"),
        resource_to_dict(src, name="<test>"),
    )


class TestCoreRules(unittest.TestCase):

    def test_safe_clean_program(self):
        taint, cap, resource = analyze_inputs("x = 1\nprint(x)")
        decision = SafetyDecisionEngine().evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "SAFE")
        self.assertEqual(decision.reasons, [])

    def test_unsafe_on_tainted_sink_flow(self):
        taint, cap, resource = analyze_inputs("""
            import os
            os.system(input())
        """)
        decision = SafetyDecisionEngine().evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertTrue(any(r.startswith("taint_findings_present:") for r in decision.reasons))

    def test_unsafe_on_dynamic_execution_primitive(self):
        taint, cap, resource = analyze_inputs("eval('1+1')")
        decision = SafetyDecisionEngine().evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("dynamic_execution_primitive_detected", decision.reasons)

    def test_conditionally_safe_on_soft_unbounded_resource(self):
        taint, cap, resource = analyze_inputs("""
            x = 0
            while check(x):
                x += 1
        """)
        decision = SafetyDecisionEngine().evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "CONDITIONALLY_SAFE")
        self.assertIn("unbounded_resource_behavior_requires_review", decision.reasons)


class TestPluggablePolicy(unittest.TestCase):

    def test_policy_requires_network_check(self):
        taint, cap, resource = analyze_inputs("""
            import requests
            requests.get('https://example.com')
        """)
        decision = SafetyDecisionEngine(policies=[ExternalAccessPolicy()]).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "CONDITIONALLY_SAFE")
        self.assertIn("policy_check_required:NET", decision.reasons)

    def test_policy_allowlist_can_make_network_safe(self):
        taint, cap, resource = analyze_inputs("""
            import requests
            requests.get('https://example.com')
        """)
        decision = SafetyDecisionEngine(
            policies=[ExternalAccessPolicy(require_checks_for=("NET",), allow_classes={"NET"})]
        ).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "SAFE")

    def test_policy_denylist_can_force_unsafe(self):
        taint, cap, resource = analyze_inputs("""
            open('file.txt', 'w').write('x')
        """)
        decision = SafetyDecisionEngine(
            policies=[ExternalAccessPolicy(require_checks_for=("FS",), deny_classes={"FS"})]
        ).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_denied:FS", decision.reasons)


if __name__ == "__main__":
    unittest.main()
