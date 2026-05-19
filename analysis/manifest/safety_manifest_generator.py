"""Safety manifest generation for certifying analysis outputs."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from analysis.capability import analyze_to_dict as capability_to_dict
from analysis.decision import (
    ExecutionPolicy,
    ExecutionPolicySafetyPolicy,
    ExternalAccessPolicy,
    SafetyDecisionEngine,
)
from analysis.resource import analyze_to_dict as resource_to_dict
from analysis.taint import analyze_to_dict as taint_to_dict
from cfg.cfg_builder import build_cfg

MANIFEST_SCHEMA_VERSION = "1.0"
DEFAULT_ANALYSIS_VERSION = "1.0.0"


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _stable_sorted_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(item.get(k) for k in keys)

    return sorted(items, key=sort_key)


def _normalized_capability_summary(capability_results: dict[str, Any]) -> dict[str, Any]:
    summary = capability_results.get("summary", {})
    by_cap = capability_results.get("by_capability", {})

    normalized_by_cap: dict[str, list[dict[str, Any]]] = {}
    for cap in sorted(by_cap.keys()):
        uses = by_cap.get(cap, [])
        normalized_by_cap[cap] = _stable_sorted_dicts(
            list(uses),
            keys=("severity", "kind", "symbol", "line", "col", "alias"),
        )

    return {
        "capabilities": sorted(summary.get("capabilities", [])),
        "highest_severity": summary.get("highest_severity"),
        "total_uses": int(summary.get("total_uses", 0)),
        "counts": {
            "FS": int(summary.get("FS", 0)),
            "NET": int(summary.get("NET", 0)),
            "PROC": int(summary.get("PROC", 0)),
            "DYN": int(summary.get("DYN", 0)),
        },
        "by_capability": normalized_by_cap,
    }


def _normalized_taint_summary(taint_results: dict[str, Any]) -> dict[str, Any]:
    findings = list(taint_results.get("findings", []))
    findings = _stable_sorted_dicts(findings, keys=("severity", "sink", "sink_kind", "message"))
    return {
        "total": int(taint_results.get("total", 0)),
        "critical": int(taint_results.get("critical", 0)),
        "high": int(taint_results.get("high", 0)),
        "medium": int(taint_results.get("medium", 0)),
        "findings": findings,
    }


def _normalized_resource_summary(resource_results: dict[str, Any]) -> dict[str, Any]:
    metrics = resource_results.get("metrics", {})
    flags = _stable_sorted_dicts(
        list(resource_results.get("flags", [])),
        keys=("kind", "line", "col", "evidence", "message"),
    )
    return {
        "risk_score": resource_results.get("risk_score", "LOW"),
        "metrics": {
            "loop_nesting_depth": int(metrics.get("loop_nesting_depth", 0)),
            "recursion_present": bool(metrics.get("recursion_present", False)),
            "potentially_unbounded_loops": bool(metrics.get("potentially_unbounded_loops", False)),
            "max_function_call_depth": int(metrics.get("max_function_call_depth", 0)),
            "complexity_heuristic": metrics.get("complexity_heuristic", "O(1)"),
        },
        "flags": flags,
        "summary": resource_results.get("summary", {}),
    }


def _normalized_cfg_summary(cfg_metadata: dict[str, Any]) -> dict[str, Any]:
    summary = cfg_metadata.get("summary", {})
    return {
        "name": cfg_metadata.get("name"),
        "summary": {
            "total_blocks": int(summary.get("total_blocks", 0)),
            "total_edges": int(summary.get("total_edges", 0)),
            "branches": int(summary.get("branches", 0)),
            "loops": int(summary.get("loops", 0)),
            "loop_back_edges": int(summary.get("loop_back_edges", 0)),
        },
    }


def _confidence_metadata(
    taint_summary: dict[str, Any],
    capability_summary: dict[str, Any],
    resource_summary: dict[str, Any],
    cfg_summary: dict[str, Any],
) -> dict[str, Any]:
    inputs = {
        "taint": taint_summary,
        "capability": capability_summary,
        "resource": resource_summary,
        "cfg": cfg_summary,
    }

    present = sum(1 for x in inputs.values() if isinstance(x, dict) and len(x) > 0)
    coverage = present / 4.0

    confidence_score = round(0.4 + 0.6 * coverage, 3)
    return {
        "score": confidence_score,
        "coverage": coverage,
        "deterministic": True,
        "canonicalization": "json-sort-keys+compact",
        "input_hashes": {k: _sha256(v) for k, v in inputs.items()},
    }


def generate_manifest(
    *,
    taint_results: dict[str, Any],
    capability_results: dict[str, Any],
    resource_results: dict[str, Any],
    cfg_metadata: dict[str, Any],
    execution_policy: ExecutionPolicy | dict[str, Any] | None = None,
    timestamp: str | None = None,
    analysis_version: str = DEFAULT_ANALYSIS_VERSION,
) -> dict[str, Any]:
    generated_at = timestamp or "1970-01-01T00:00:00Z"

    capability_summary = _normalized_capability_summary(capability_results)
    taint_summary = _normalized_taint_summary(taint_results)
    resource_summary = _normalized_resource_summary(resource_results)
    cfg_summary = _normalized_cfg_summary(cfg_metadata)

    policies = [ExternalAccessPolicy()]
    if execution_policy is not None:
        policy_obj = execution_policy if isinstance(execution_policy, ExecutionPolicy) else ExecutionPolicy.from_dict(execution_policy)
        policies.append(ExecutionPolicySafetyPolicy(policy_obj))

    decision = SafetyDecisionEngine(policies=policies).evaluate(
        taint_results=taint_results,
        capability_results=capability_results,
        resource_results=resource_results,
    )
    rejection_reasons = decision.reasons
    overall_verdict = decision.verdict

    manifest: dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "analysis_version": analysis_version,
        "timestamp": generated_at,
        "overall_verdict": overall_verdict,
        "capability_summary": capability_summary,
        "taint_flow_summary": taint_summary,
        "resource_risk_summary": resource_summary,
        "cfg_metadata": cfg_summary,
        "rejection_reasons": rejection_reasons,
        "decision_trace": decision.to_dict(),
        "execution_policy": (
            execution_policy.to_dict()
            if isinstance(execution_policy, ExecutionPolicy)
            else execution_policy
        ),
        "confidence_metadata": _confidence_metadata(
            taint_summary=taint_summary,
            capability_summary=capability_summary,
            resource_summary=resource_summary,
            cfg_summary=cfg_summary,
        ),
    }

    manifest["manifest_digest"] = _sha256({k: v for k, v in manifest.items() if k != "manifest_digest"})
    return manifest


def generate_manifest_from_source(
    source: str,
    *,
    source_name: str = "<string>",
    execution_policy: ExecutionPolicy | dict[str, Any] | None = None,
    timestamp: str | None = None,
    analysis_version: str = DEFAULT_ANALYSIS_VERSION,
) -> dict[str, Any]:
    taint_results = taint_to_dict(source)
    capability_results = capability_to_dict(source, name=source_name)
    resource_results = resource_to_dict(source, name=source_name)
    cfg_metadata = build_cfg(source=source, name=source_name).to_dict()

    return generate_manifest(
        taint_results=taint_results,
        capability_results=capability_results,
        resource_results=resource_results,
        cfg_metadata=cfg_metadata,
        execution_policy=execution_policy,
        timestamp=timestamp,
        analysis_version=analysis_version,
    )


def manifest_to_json(manifest: dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(manifest, sort_keys=True, indent=indent, ensure_ascii=False)
