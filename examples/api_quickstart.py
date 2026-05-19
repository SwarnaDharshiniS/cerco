"""Quick API walkthrough for cerco analyzers.

Run from repository root:
    python3 examples/api_quickstart.py
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.capability import analyze_to_dict as capability_to_dict
from analysis.decision import ExternalAccessPolicy, SafetyDecisionEngine
from analysis.manifest import ManifestVerificationEngine, generate_manifest_from_source
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.safety_ir import build_safety_ir_from_source
from analysis.taint import analyze_to_dict as taint_to_dict
from cfg import build_cfg


def main() -> None:
    source = textwrap.dedent(
        """
        import os

        def run(user_cmd: str) -> None:
            os.system(user_cmd)

        run(input("cmd: "))
        """
    )

    taint = taint_to_dict(source)
    capability = capability_to_dict(source, name="example.py")
    resource = resource_to_dict(source, name="example.py")

    decision = SafetyDecisionEngine(policies=[ExternalAccessPolicy()]).evaluate(
        taint_results=taint,
        capability_results=capability,
        resource_results=resource,
    )

    cfg = build_cfg(source=source)
    manifest = generate_manifest_from_source(
        source,
        source_name="example.py",
        timestamp="2026-05-19T00:00:00Z",
        analysis_version="2026.05",
    )
    verification = ManifestVerificationEngine().verify(manifest=manifest)

    ir = build_safety_ir_from_source(
        source,
        source_name="example.py",
        timestamp="2026-05-19T00:00:00Z",
        analysis_version="2026.05",
    )

    print("=== Decision ===")
    print(f"verdict: {decision.verdict}")
    print(f"reasons: {decision.reasons}")

    print("\n=== Taint ===")
    print(f"total findings: {taint['total']}")

    print("\n=== Capability ===")
    print(f"capabilities: {capability['summary']['capabilities']}")
    print(f"highest severity: {capability['summary']['highest_severity']}")

    print("\n=== Resource ===")
    print(f"risk score: {resource['risk_score']}")

    print("\n=== CFG ===")
    print(f"blocks: {cfg.to_dict()['summary']['total_blocks']}")
    print(f"edges: {cfg.to_dict()['summary']['total_edges']}")

    print("\n=== Manifest Verification ===")
    print(f"trusted: {verification.trusted}")
    print(f"integrity_ok: {verification.integrity_ok}")

    print("\n=== Safety IR ===")
    ir_dict = ir.to_dict()
    print(f"node_type: {ir_dict['node_type']}")
    print(f"function nodes: {len(ir_dict['nodes']['functions'])}")


if __name__ == "__main__":
    main()
