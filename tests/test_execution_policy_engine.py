"""Tests for analysis.decision.execution_policy."""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.capability import analyze_to_dict as capability_to_dict
from analysis.decision import ExecutionPolicy, ExecutionPolicyEngine
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.taint import analyze_to_dict as taint_to_dict
from analysis.manifest import generate_manifest_from_source
from analysis.safety_ir import build_safety_ir_from_source


def analyze_inputs(code: str) -> tuple[dict, dict, dict]:
    src = textwrap.dedent(code)
    return (
        taint_to_dict(src),
        capability_to_dict(src, name="<test>"),
        resource_to_dict(src, name="<test>"),
    )


class TestExecutionPolicySerialization(unittest.TestCase):

    def test_json_roundtrip(self):
        p = ExecutionPolicy(
            allowed_imports=["os", "requests"],
            forbidden_capabilities=["DYN", "subprocess.Popen"],
            max_resource_risk="MEDIUM",
            max_loop_depth=2,
            allow_filesystem_access=False,
            allow_subprocess_execution=False,
        )
        parsed = ExecutionPolicy.from_json(p.to_json())
        self.assertEqual(parsed.to_dict(), p.to_dict())


class TestExecutionPolicyRules(unittest.TestCase):

    def test_allowed_imports_enforced(self):
        taint, cap, resource = analyze_inputs("""
            import requests
            requests.get('https://example.com')
        """)
        policy = ExecutionPolicy(allowed_imports=["os"])
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_import_not_allowed:requests", decision.reasons)

    def test_forbidden_capability_enforced(self):
        taint, cap, resource = analyze_inputs("eval('1+1')")
        policy = ExecutionPolicy(forbidden_capabilities=["DYN"])
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertIn("policy_forbidden_capability:DYN", decision.reasons)

    def test_max_resource_risk_enforced(self):
        taint, cap, resource = analyze_inputs("for i in range(100000000):\n    pass")
        policy = ExecutionPolicy(max_resource_risk="LOW")
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_resource_risk_exceeded:MEDIUM>LOW", decision.reasons)

    def test_max_loop_depth_enforced(self):
        taint, cap, resource = analyze_inputs("""
            for i in range(10):
                for j in range(10):
                    pass
        """)
        policy = ExecutionPolicy(max_loop_depth=1)
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_loop_depth_exceeded:2>1", decision.reasons)

    def test_filesystem_access_toggle_enforced(self):
        taint, cap, resource = analyze_inputs("open('file.txt').read()")
        policy = ExecutionPolicy(allow_filesystem_access=False)
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_fs_access_not_allowed", decision.reasons)

    def test_subprocess_toggle_enforced(self):
        taint, cap, resource = analyze_inputs("""
            import subprocess
            subprocess.run(['ls'])
        """)
        policy = ExecutionPolicy(allow_subprocess_execution=False)
        decision = ExecutionPolicyEngine(policy=policy).evaluate(
            taint_results=taint,
            capability_results=cap,
            resource_results=resource,
        )
        self.assertEqual(decision.verdict, "UNSAFE")
        self.assertIn("policy_subprocess_execution_not_allowed", decision.reasons)


class TestIntegrationWithSafetySystem(unittest.TestCase):

    def test_manifest_accepts_execution_policy_dict(self):
        manifest = generate_manifest_from_source(
            "import requests\nrequests.get('https://example.com')",
            source_name="<test>",
            timestamp="2026-05-18T00:00:00Z",
            analysis_version="2026.05",
            execution_policy={
                "allowed_imports": ["os"],
                "forbidden_capabilities": [],
                "max_resource_risk": "HIGH",
                "max_loop_depth": None,
                "allow_filesystem_access": True,
                "allow_subprocess_execution": True,
            },
        )
        self.assertEqual(manifest["overall_verdict"], "UNSAFE")
        self.assertIn("policy_import_not_allowed:requests", manifest["rejection_reasons"])
        self.assertIsInstance(manifest["execution_policy"], dict)

    def test_safety_ir_accepts_execution_policy_object(self):
        policy = ExecutionPolicy(allow_subprocess_execution=False)
        ir = build_safety_ir_from_source(
            "import subprocess\nsubprocess.run(['ls'])",
            source_name="<test>",
            timestamp="2026-05-18T00:00:00Z",
            analysis_version="2026.05",
            execution_policy=policy,
        )
        d = ir.to_dict()
        self.assertEqual(d["verdict_hint"], "UNSAFE")
        self.assertIn("policy_subprocess_execution_not_allowed", d["metadata"]["decision_reasons"])
        self.assertEqual(d["metadata"]["execution_policy"]["allow_subprocess_execution"], False)


if __name__ == "__main__":
    unittest.main()
