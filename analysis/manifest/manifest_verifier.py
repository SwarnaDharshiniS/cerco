"""Manifest verification engine for certifying Python execution trust."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from analysis.decision import (
    ExecutionPolicy,
    ExecutionPolicySafetyPolicy,
    ExternalAccessPolicy,
    SafetyDecisionEngine,
)

from .safety_manifest_generator import MANIFEST_SCHEMA_VERSION


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash_payload(data: Any, algorithm: str = "sha256") -> str:
    algo = algorithm.lower().strip()
    try:
        h = hashlib.new(algo)
    except ValueError as exc:
        raise ValueError(f"unsupported hash algorithm: {algorithm}") from exc
    h.update(_canonical_json(data).encode("utf-8"))
    return h.hexdigest()


@dataclass
class ManifestVerificationReport:
    trusted: bool
    integrity_ok: bool
    checksums_ok: bool
    ir_consistency_ok: bool
    claims_ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trusted": self.trusted,
            "integrity_ok": self.integrity_ok,
            "checksums_ok": self.checksums_ok,
            "ir_consistency_ok": self.ir_consistency_ok,
            "claims_ok": self.claims_ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "details": self.details,
        }


class ManifestVerificationEngine:
    """Verifies manifest integrity and trust without rerunning full source analysis."""

    def verify(
        self,
        *,
        manifest: dict[str, Any],
        ir: dict[str, Any] | None = None,
        expected_checksum: str | None = None,
        checksum_algorithm: str = "sha256",
    ) -> ManifestVerificationReport:
        errors: list[str] = []
        warnings: list[str] = []
        details: dict[str, Any] = {}

        integrity_ok = self._verify_integrity(manifest, errors=errors, details=details)
        checksums_ok = self._verify_checksums(
            manifest,
            expected_checksum=expected_checksum,
            checksum_algorithm=checksum_algorithm,
            errors=errors,
            details=details,
        )
        claims_ok = self._verify_claims(manifest, errors=errors, warnings=warnings, details=details)
        ir_consistency_ok = self._verify_ir_consistency(manifest, ir=ir, errors=errors, details=details)

        trusted = integrity_ok and checksums_ok and claims_ok and ir_consistency_ok and not errors
        return ManifestVerificationReport(
            trusted=trusted,
            integrity_ok=integrity_ok,
            checksums_ok=checksums_ok,
            ir_consistency_ok=ir_consistency_ok,
            claims_ok=claims_ok,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    def verify_checksum(self, *, payload: Any, expected_checksum: str, algorithm: str = "sha256") -> bool:
        return _hash_payload(payload, algorithm) == expected_checksum

    def _verify_integrity(self, manifest: dict[str, Any], *, errors: list[str], details: dict[str, Any]) -> bool:
        required = {
            "manifest_schema_version",
            "analysis_version",
            "timestamp",
            "overall_verdict",
            "capability_summary",
            "taint_flow_summary",
            "resource_risk_summary",
            "cfg_metadata",
            "rejection_reasons",
            "decision_trace",
            "confidence_metadata",
            "manifest_digest",
        }
        missing = sorted(required - set(manifest.keys()))
        if missing:
            errors.append(f"missing_required_fields:{','.join(missing)}")
            return False

        if manifest.get("manifest_schema_version") != MANIFEST_SCHEMA_VERSION:
            errors.append(
                f"unsupported_manifest_schema:{manifest.get('manifest_schema_version')}"
            )
            return False

        expected_digest = _hash_payload({k: v for k, v in manifest.items() if k != "manifest_digest"}, "sha256")
        details["computed_manifest_digest"] = expected_digest
        if manifest.get("manifest_digest") != expected_digest:
            errors.append("manifest_digest_mismatch")
            return False

        return True

    def _verify_checksums(
        self,
        manifest: dict[str, Any],
        *,
        expected_checksum: str | None,
        checksum_algorithm: str,
        errors: list[str],
        details: dict[str, Any],
    ) -> bool:
        ok = True

        if expected_checksum is not None:
            computed = _hash_payload(manifest, checksum_algorithm)
            details["computed_external_checksum"] = computed
            if computed != expected_checksum:
                errors.append(f"external_checksum_mismatch:{checksum_algorithm}")
                ok = False

        conf = manifest.get("confidence_metadata", {})
        hashes = conf.get("input_hashes", {}) if isinstance(conf, dict) else {}
        if isinstance(hashes, dict) and hashes:
            recomputed = {
                "taint": _hash_payload(manifest.get("taint_flow_summary", {}), "sha256"),
                "capability": _hash_payload(manifest.get("capability_summary", {}), "sha256"),
                "resource": _hash_payload(manifest.get("resource_risk_summary", {}), "sha256"),
                "cfg": _hash_payload(manifest.get("cfg_metadata", {}), "sha256"),
            }
            details["recomputed_input_hashes"] = recomputed
            for key, value in recomputed.items():
                if hashes.get(key) != value:
                    errors.append(f"input_hash_mismatch:{key}")
                    ok = False

        return ok

    def _verify_claims(
        self,
        manifest: dict[str, Any],
        *,
        errors: list[str],
        warnings: list[str],
        details: dict[str, Any],
    ) -> bool:
        declared_verdict = manifest.get("overall_verdict")
        if declared_verdict not in {"SAFE", "UNSAFE", "CONDITIONALLY_SAFE"}:
            errors.append(f"invalid_overall_verdict:{declared_verdict}")
            return False

        taint_summary = manifest.get("taint_flow_summary", {})
        cap_summary = manifest.get("capability_summary", {})
        resource_summary = manifest.get("resource_risk_summary", {})

        taint_results = {
            "total": int(taint_summary.get("total", 0)),
            "findings": list(taint_summary.get("findings", [])),
        }
        capability_results = {
            "summary": {
                "capabilities": list(cap_summary.get("capabilities", [])),
                "total_uses": int(cap_summary.get("total_uses", 0)),
                "highest_severity": cap_summary.get("highest_severity"),
            },
            "by_capability": dict(cap_summary.get("by_capability", {})),
        }
        resource_results = {
            "risk_score": resource_summary.get("risk_score", "LOW"),
            "flags": list(resource_summary.get("flags", [])),
            "metrics": dict(resource_summary.get("metrics", {})),
        }

        policies = [ExternalAccessPolicy()]
        policy_data = manifest.get("execution_policy")
        if isinstance(policy_data, dict):
            try:
                policies.append(ExecutionPolicySafetyPolicy(ExecutionPolicy.from_dict(policy_data)))
            except Exception:
                warnings.append("invalid_execution_policy_payload")

        expected = SafetyDecisionEngine(policies=policies).evaluate(
            taint_results=taint_results,
            capability_results=capability_results,
            resource_results=resource_results,
        )
        details["expected_verdict_from_summaries"] = expected.verdict

        if expected.verdict != declared_verdict:
            errors.append(f"verdict_claim_mismatch:{declared_verdict}!={expected.verdict}")
            return False

        reasons = sorted(set(manifest.get("rejection_reasons", [])))
        if sorted(expected.reasons) != reasons:
            errors.append("rejection_reasons_mismatch")
            return False

        decision_trace = manifest.get("decision_trace", {})
        if isinstance(decision_trace, dict):
            if decision_trace.get("verdict") != declared_verdict:
                errors.append("decision_trace_verdict_mismatch")
                return False

        return True

    def _verify_ir_consistency(
        self,
        manifest: dict[str, Any],
        *,
        ir: dict[str, Any] | None,
        errors: list[str],
        details: dict[str, Any],
    ) -> bool:
        if ir is None:
            return True

        ok = True
        declared_verdict = manifest.get("overall_verdict")
        ir_verdict = ir.get("verdict_hint")
        details["ir_verdict_hint"] = ir_verdict
        if ir_verdict != declared_verdict:
            errors.append("ir_verdict_hint_mismatch")
            ok = False

        ir_meta = ir.get("metadata", {}) if isinstance(ir.get("metadata", {}), dict) else {}
        manifest_taint = int((manifest.get("taint_flow_summary") or {}).get("total", 0))
        if int(ir_meta.get("taint_total", manifest_taint)) != manifest_taint:
            errors.append("ir_taint_total_mismatch")
            ok = False

        manifest_cap_total = int((manifest.get("capability_summary") or {}).get("total_uses", 0))
        if int(ir_meta.get("capability_total", manifest_cap_total)) != manifest_cap_total:
            errors.append("ir_capability_total_mismatch")
            ok = False

        manifest_risk = str((manifest.get("resource_risk_summary") or {}).get("risk_score", "LOW"))
        if str(ir_meta.get("resource_risk", manifest_risk)) != manifest_risk:
            errors.append("ir_resource_risk_mismatch")
            ok = False

        return ok


def verify_manifest(
    manifest: dict[str, Any],
    *,
    ir: dict[str, Any] | None = None,
    expected_checksum: str | None = None,
    checksum_algorithm: str = "sha256",
) -> dict[str, Any]:
    return ManifestVerificationEngine().verify(
        manifest=manifest,
        ir=ir,
        expected_checksum=expected_checksum,
        checksum_algorithm=checksum_algorithm,
    ).to_dict()
