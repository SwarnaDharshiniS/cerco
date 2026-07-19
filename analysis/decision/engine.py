"""Rule-based safety decision engine for certifying compiler pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


SAFE = "SAFE"
UNSAFE = "UNSAFE"
CONDITIONALLY_SAFE = "CONDITIONALLY_SAFE"

_VERDICT_ORDER = {
    SAFE: 0,
    CONDITIONALLY_SAFE: 1,
    UNSAFE: 2,
}


def _max_verdict(left: str, right: str) -> str:
    return left if _VERDICT_ORDER[left] >= _VERDICT_ORDER[right] else right


@dataclass(frozen=True)
class SafetyContext:
    taint_results: dict[str, Any]
    capability_results: dict[str, Any]
    resource_results: dict[str, Any]


@dataclass(frozen=True)
class SafetyPolicyDecision:
    policy_name: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "verdict": self.verdict,
            "reasons": sorted(self.reasons),
            "metadata": self.metadata,
        }


class SafetyPolicy(Protocol):
    name: str

    def evaluate(self, context: SafetyContext) -> SafetyPolicyDecision | None:
        ...


@dataclass(frozen=True)
class SafetyDecision:
    verdict: str
    reasons: list[str]
    rule_hits: list[dict[str, Any]]
    policy_results: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": sorted(self.reasons),
            "rule_hits": self.rule_hits,
            "policy_results": self.policy_results,
        }


class ExternalAccessPolicy:
    """Policy hook for FS/NET capabilities that require explicit approval."""

    name = "external_access_policy"

    def __init__(
        self,
        *,
        require_checks_for: tuple[str, ...] = ("FS", "NET"),
        allow_classes: set[str] | None = None,
        deny_classes: set[str] | None = None,
    ) -> None:
        self._require_checks_for = require_checks_for
        self._allow_classes = allow_classes
        self._deny_classes = deny_classes or set()

    def evaluate(self, context: SafetyContext) -> SafetyPolicyDecision | None:
        summary = context.capability_results.get("summary", {})
        capabilities = set(summary.get("capabilities", []))

        reasons: list[str] = []
        verdict = SAFE

        for cap in sorted(capabilities):
            if cap not in self._require_checks_for:
                continue
            if cap in self._deny_classes:
                reasons.append(f"policy_denied:{cap}")
                verdict = _max_verdict(verdict, UNSAFE)
                continue

            allowed = self._allow_classes is not None and cap in self._allow_classes
            if not allowed:
                reasons.append(f"policy_check_required:{cap}")
                verdict = _max_verdict(verdict, CONDITIONALLY_SAFE)

        if not reasons:
            return None

        return SafetyPolicyDecision(
            policy_name=self.name,
            verdict=verdict,
            reasons=reasons,
            metadata={
                "require_checks_for": list(self._require_checks_for),
            },
        )


class SafetyDecisionEngine:
    """Combines taint, capability, and resource outputs into a final verdict."""

    def __init__(self, *, policies: list[SafetyPolicy] | None = None) -> None:
        self._policies = policies or []

    def evaluate(
        self,
        *,
        taint_results: dict[str, Any],
        capability_results: dict[str, Any],
        resource_results: dict[str, Any],
    ) -> SafetyDecision:
        context = SafetyContext(
            taint_results=taint_results,
            capability_results=capability_results,
            resource_results=resource_results,
        )

        verdict = SAFE
        reasons: list[str] = []
        rule_hits: list[dict[str, Any]] = []

        taint_total = int(taint_results.get("total", 0))
        if taint_total > 0:
            verdict = _max_verdict(verdict, UNSAFE)
            reasons.append(f"taint_findings_present:{taint_total}")
            rule_hits.append({"rule": "tainted_sink_flow", "verdict": UNSAFE, "count": taint_total})

        dyn_uses = list((capability_results.get("by_capability") or {}).get("DYN", []))
        if dyn_uses:
            verdict = _max_verdict(verdict, UNSAFE)
            reasons.append("dynamic_execution_primitive_detected")
            rule_hits.append({"rule": "dynamic_execution", "verdict": UNSAFE, "count": len(dyn_uses)})

        unbounded_kinds = {"while_true", "potentially_unbounded_loop", "recursive_no_base"}
        resource_flags = list(resource_results.get("flags", []))
        unbounded_flags = [f for f in resource_flags if f.get("kind") in unbounded_kinds]
        if unbounded_flags:
            risk = str(resource_results.get("risk_score", "LOW"))
            has_hard_unbounded = any(f.get("kind") in {"while_true", "recursive_no_base"} for f in unbounded_flags)
            if risk == "HIGH" or has_hard_unbounded:
                verdict = _max_verdict(verdict, UNSAFE)
                reasons.append("unbounded_resource_behavior_high_risk")
                rule_hits.append({"rule": "unbounded_resource", "verdict": UNSAFE, "count": len(unbounded_flags)})
            else:
                verdict = _max_verdict(verdict, CONDITIONALLY_SAFE)
                reasons.append("unbounded_resource_behavior_requires_review")
                rule_hits.append(
                    {"rule": "unbounded_resource", "verdict": CONDITIONALLY_SAFE, "count": len(unbounded_flags)}
                )

        policy_results: list[dict[str, Any]] = []
        for policy in self._policies:
            result = policy.evaluate(context)
            if result is None:
                continue
            policy_results.append(result.to_dict())
            verdict = _max_verdict(verdict, result.verdict)
            reasons.extend(result.reasons)

        return SafetyDecision(
            verdict=verdict,
            reasons=sorted(set(reasons)),
            rule_hits=sorted(rule_hits, key=lambda r: (r["rule"], r["verdict"], r.get("count", 0))),
            policy_results=sorted(policy_results, key=lambda p: p["policy_name"]),
        )
