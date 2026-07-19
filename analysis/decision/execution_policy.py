"""Configurable execution policy engine for untrusted Python analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .engine import SAFE, UNSAFE, SafetyDecision, SafetyDecisionEngine, SafetyContext, SafetyPolicy, SafetyPolicyDecision


_RISK_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
}


def _normalize_risk(value: str) -> str:
    upper = value.upper()
    if upper not in _RISK_ORDER:
        raise ValueError(f"invalid risk level: {value}")
    return upper


@dataclass(frozen=True)
class ExecutionPolicy:
    """Serializable policy constraints for untrusted execution analysis."""

    allowed_imports: list[str] | None = None
    forbidden_capabilities: list[str] = field(default_factory=list)
    max_resource_risk: str = "HIGH"
    max_loop_depth: int | None = None
    allow_filesystem_access: bool = True
    allow_subprocess_execution: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_resource_risk", _normalize_risk(self.max_resource_risk))
        if self.max_loop_depth is not None and self.max_loop_depth < 0:
            raise ValueError("max_loop_depth must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_imports": sorted(self.allowed_imports) if self.allowed_imports is not None else None,
            "forbidden_capabilities": sorted(self.forbidden_capabilities),
            "max_resource_risk": self.max_resource_risk,
            "max_loop_depth": self.max_loop_depth,
            "allow_filesystem_access": self.allow_filesystem_access,
            "allow_subprocess_execution": self.allow_subprocess_execution,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionPolicy":
        return cls(
            allowed_imports=data.get("allowed_imports"),
            forbidden_capabilities=list(data.get("forbidden_capabilities", [])),
            max_resource_risk=str(data.get("max_resource_risk", "HIGH")),
            max_loop_depth=data.get("max_loop_depth"),
            allow_filesystem_access=bool(data.get("allow_filesystem_access", True)),
            allow_subprocess_execution=bool(data.get("allow_subprocess_execution", True)),
        )

    @classmethod
    def from_json(cls, raw: str) -> "ExecutionPolicy":
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("execution policy JSON must decode to an object")
        return cls.from_dict(obj)


class ExecutionPolicySafetyPolicy(SafetyPolicy):
    """Evaluates ExecutionPolicy constraints inside the safety decision engine."""

    name = "execution_policy"

    def __init__(self, policy: ExecutionPolicy) -> None:
        self._policy = policy

    def evaluate(self, context: SafetyContext) -> SafetyPolicyDecision | None:
        reasons: list[str] = []

        summary = context.capability_results.get("summary", {})
        by_cap = context.capability_results.get("by_capability", {})
        present_caps = set(summary.get("capabilities", []))

        if not self._policy.allow_filesystem_access and "FS" in present_caps:
            reasons.append("policy_fs_access_not_allowed")

        if not self._policy.allow_subprocess_execution and "PROC" in present_caps:
            reasons.append("policy_subprocess_execution_not_allowed")

        for forbidden in sorted(set(self._policy.forbidden_capabilities)):
            if forbidden in present_caps:
                reasons.append(f"policy_forbidden_capability:{forbidden}")
                continue

            for entries in by_cap.values():
                if any(str(e.get("symbol")) == forbidden for e in entries):
                    reasons.append(f"policy_forbidden_capability:{forbidden}")
                    break

        imports_seen = self._observed_imports(by_cap)
        if self._policy.allowed_imports is not None:
            for imp in imports_seen:
                if not self._is_allowed_import(imp):
                    reasons.append(f"policy_import_not_allowed:{imp}")

        resource_risk = str(context.resource_results.get("risk_score", "LOW")).upper()
        if _RISK_ORDER.get(resource_risk, 0) > _RISK_ORDER[self._policy.max_resource_risk]:
            reasons.append(
                f"policy_resource_risk_exceeded:{resource_risk}>{self._policy.max_resource_risk}"
            )

        if self._policy.max_loop_depth is not None:
            loop_depth = int((context.resource_results.get("metrics") or {}).get("loop_nesting_depth", 0))
            if loop_depth > self._policy.max_loop_depth:
                reasons.append(f"policy_loop_depth_exceeded:{loop_depth}>{self._policy.max_loop_depth}")

        if not reasons:
            return None

        return SafetyPolicyDecision(
            policy_name=self.name,
            verdict=UNSAFE,
            reasons=sorted(set(reasons)),
            metadata={"policy": self._policy.to_dict()},
        )

    def _is_allowed_import(self, symbol: str) -> bool:
        allowed = self._policy.allowed_imports
        if allowed is None:
            return True

        for module in allowed:
            if symbol == module or symbol.startswith(module + "."):
                return True
        return False

    @staticmethod
    def _observed_imports(by_capability: dict[str, Any]) -> set[str]:
        out: set[str] = set()
        for entries in by_capability.values():
            for entry in entries:
                if entry.get("kind") != "import":
                    continue
                symbol = str(entry.get("symbol", "")).strip()
                if symbol:
                    out.add(symbol)
        return out


class ExecutionPolicyEngine:
    """Safety decision facade that always enforces an ExecutionPolicy."""

    def __init__(
        self,
        *,
        policy: ExecutionPolicy,
        base_policies: list[SafetyPolicy] | None = None,
    ) -> None:
        self._policy = policy
        self._base_policies = base_policies or []

    def evaluate(
        self,
        *,
        taint_results: dict[str, Any],
        capability_results: dict[str, Any],
        resource_results: dict[str, Any],
    ) -> SafetyDecision:
        policies = [ExecutionPolicySafetyPolicy(self._policy), *self._base_policies]
        return SafetyDecisionEngine(policies=policies).evaluate(
            taint_results=taint_results,
            capability_results=capability_results,
            resource_results=resource_results,
        )

    @property
    def policy(self) -> ExecutionPolicy:
        return self._policy
