"""Tests for analysis.manifest.manifest_verifier."""

import hashlib
import json
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.manifest import ManifestVerificationEngine, generate_manifest_from_source
from analysis.safety_ir import build_safety_ir_from_source


def canonical_json(data) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(data) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def manifest_from(code: str) -> dict:
    return generate_manifest_from_source(
        textwrap.dedent(code),
        source_name="<test>",
        timestamp="2026-05-18T00:00:00Z",
        analysis_version="2026.05",
    )


class TestManifestVerifier(unittest.TestCase):

    def test_valid_manifest_is_trusted(self):
        m = manifest_from("x = 1\nprint(x)")
        report = ManifestVerificationEngine().verify(manifest=m)
        self.assertTrue(report.trusted)
        self.assertTrue(report.integrity_ok)
        self.assertTrue(report.claims_ok)

    def test_tampered_manifest_digest_rejected(self):
        m = manifest_from("x = 1")
        m["resource_risk_summary"]["risk_score"] = "HIGH"
        report = ManifestVerificationEngine().verify(manifest=m)
        self.assertFalse(report.trusted)
        self.assertIn("manifest_digest_mismatch", report.errors)

    def test_checksum_validation(self):
        m = manifest_from("x = 1")
        expected = sha256(m)
        engine = ManifestVerificationEngine()
        ok = engine.verify(manifest=m, expected_checksum=expected, checksum_algorithm="sha256")
        bad = engine.verify(manifest=m, expected_checksum="0" * 64, checksum_algorithm="sha256")
        self.assertTrue(ok.checksums_ok)
        self.assertFalse(bad.checksums_ok)

    def test_verdict_claim_mismatch_rejected(self):
        m = manifest_from("""
            import os
            os.system(input())
        """)
        # tamper verdict claim and keep old digest shape intentionally re-signed
        m["overall_verdict"] = "SAFE"
        m["manifest_digest"] = sha256({k: v for k, v in m.items() if k != "manifest_digest"})
        report = ManifestVerificationEngine().verify(manifest=m)
        self.assertFalse(report.trusted)
        self.assertTrue(any(e.startswith("verdict_claim_mismatch:") for e in report.errors))

    def test_ir_consistency_validation(self):
        source = """
            import os
            os.system(input())
        """
        m = manifest_from(source)
        ir = build_safety_ir_from_source(
            textwrap.dedent(source),
            source_name="<test>",
            timestamp="2026-05-18T00:00:00Z",
            analysis_version="2026.05",
        ).to_dict()

        ok = ManifestVerificationEngine().verify(manifest=m, ir=ir)
        self.assertTrue(ok.ir_consistency_ok)

        ir["verdict_hint"] = "SAFE"
        bad = ManifestVerificationEngine().verify(manifest=m, ir=ir)
        self.assertFalse(bad.ir_consistency_ok)
        self.assertIn("ir_verdict_hint_mismatch", bad.errors)


if __name__ == "__main__":
    unittest.main()
