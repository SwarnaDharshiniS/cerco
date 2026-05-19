"""Tests for analysis.manifest.safety_manifest_generator."""

import json
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.capability import analyze_to_dict as cap_to_dict
from analysis.manifest import generate_manifest, generate_manifest_from_source, manifest_to_json
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.taint import analyze_to_dict as taint_to_dict
from cfg.cfg_builder import build_cfg


def manifest_from(code: str, *, timestamp: str | None = "2026-05-18T00:00:00Z") -> dict:
    source = textwrap.dedent(code)
    return generate_manifest_from_source(source, source_name="<test>", timestamp=timestamp, analysis_version="2026.05")


class TestManifestShape(unittest.TestCase):

    def test_required_top_level_fields(self):
        m = manifest_from("x = 1")
        required = {
            "overall_verdict",
            "capability_summary",
            "taint_flow_summary",
            "resource_risk_summary",
            "rejection_reasons",
            "decision_trace",
            "confidence_metadata",
            "timestamp",
            "analysis_version",
            "manifest_digest",
        }
        self.assertTrue(required.issubset(m.keys()))

    def test_machine_readable_json(self):
        m = manifest_from("x = 1")
        raw = manifest_to_json(m)
        obj = json.loads(raw)
        self.assertEqual(obj["overall_verdict"], m["overall_verdict"])


class TestVerdicting(unittest.TestCase):

    def test_safe_clean_code(self):
        m = manifest_from("x = 1\nprint(x)")
        self.assertEqual(m["overall_verdict"], "SAFE")
        self.assertEqual(m["rejection_reasons"], [])

    def test_unsafe_on_taint_flow(self):
        m = manifest_from("""
            import os
            os.system(input())
        """)
        self.assertEqual(m["overall_verdict"], "UNSAFE")
        self.assertIn("taint_findings_present:1", m["rejection_reasons"])

    def test_unsafe_on_high_capability(self):
        m = manifest_from("eval('1+1')")
        self.assertEqual(m["overall_verdict"], "UNSAFE")
        self.assertIn("dynamic_execution_primitive_detected", m["rejection_reasons"])

    def test_safe_on_medium_resource_risk_when_bounded(self):
        m = manifest_from("for i in range(100000000):\n    pass")
        self.assertEqual(m["overall_verdict"], "SAFE")

    def test_conditionally_safe_on_policy_required_network_access(self):
        m = manifest_from("""
            import requests
            requests.get('https://example.com')
        """)
        self.assertEqual(m["overall_verdict"], "CONDITIONALLY_SAFE")
        self.assertIn("policy_check_required:NET", m["rejection_reasons"])

    def test_conditionally_safe_on_soft_unbounded_resource_behavior(self):
        m = manifest_from("""
            x = 0
            while check(x):
                x += 1
        """)
        self.assertEqual(m["overall_verdict"], "CONDITIONALLY_SAFE")
        self.assertIn("unbounded_resource_behavior_requires_review", m["rejection_reasons"])


class TestDeterminism(unittest.TestCase):

    def test_default_timestamp_is_deterministic_epoch(self):
        m = generate_manifest_from_source("x = 1", source_name="<test>", analysis_version="1")
        self.assertEqual(m["timestamp"], "1970-01-01T00:00:00Z")

    def test_same_input_same_manifest(self):
        code = "x = 1\nfor i in range(3):\n    pass"
        m1 = manifest_from(code)
        m2 = manifest_from(code)
        self.assertEqual(m1, m2)

    def test_manifest_digest_changes_when_inputs_change(self):
        source_a = "x = 1"
        source_b = "import os\nos.system(input())"

        m1 = manifest_from(source_a)
        m2 = manifest_from(source_b)

        self.assertNotEqual(m1["manifest_digest"], m2["manifest_digest"])

    def test_manifest_json_stable_key_order(self):
        m = manifest_from("x = 1")
        j1 = manifest_to_json(m)
        j2 = manifest_to_json(dict(reversed(list(m.items()))))
        self.assertEqual(j1, j2)


class TestDirectInputMode(unittest.TestCase):

    def test_generate_manifest_from_result_dicts(self):
        source = """
            import os
            for i in range(5):
                print(i)
        """
        src = textwrap.dedent(source)
        taint = taint_to_dict(src)
        cap = cap_to_dict(src, name="<test>")
        res = resource_to_dict(src, name="<test>")
        cfg = build_cfg(source=src, name="<test>").to_dict()

        manifest = generate_manifest(
            taint_results=taint,
            capability_results=cap,
            resource_results=res,
            cfg_metadata=cfg,
            timestamp="2026-05-18T00:00:00Z",
            analysis_version="2026.05",
        )

        self.assertIn("cfg_metadata", manifest)
        self.assertIn("summary", manifest["cfg_metadata"])
        self.assertEqual(manifest["analysis_version"], "2026.05")


if __name__ == "__main__":
    unittest.main()
