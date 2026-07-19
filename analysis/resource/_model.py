"""
Resource estimation model for conservative static analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class ResourceFlag:
    kind: str
    message: str
    line: int | None = None
    col: int | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "line": self.line,
            "col": self.col,
            "evidence": self.evidence,
        }


@dataclass
class ResourceReport:
    source_name: str = "<string>"
    risk_score: RiskLevel = RiskLevel.LOW
    loop_nesting_depth: int = 0
    recursion_present: bool = False
    potentially_unbounded_loops: bool = False
    max_function_call_depth: int = 0
    complexity_heuristic: str = "O(1)"
    flags: list[ResourceFlag] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_name,
            "risk_score": self.risk_score.value,
            "metrics": {
                "loop_nesting_depth": self.loop_nesting_depth,
                "recursion_present": self.recursion_present,
                "potentially_unbounded_loops": self.potentially_unbounded_loops,
                "max_function_call_depth": self.max_function_call_depth,
                "complexity_heuristic": self.complexity_heuristic,
            },
            "flags": [f.to_dict() for f in self.flags],
            "summary": {
                "total_flags": len(self.flags),
                "while_true": sum(1 for f in self.flags if f.kind == "while_true"),
                "recursive_no_base": sum(1 for f in self.flags if f.kind == "recursive_no_base"),
                "large_range": sum(1 for f in self.flags if f.kind == "large_range"),
                "suspicious_allocation": sum(1 for f in self.flags if f.kind == "suspicious_allocation"),
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            "<ResourceReport "
            f"risk={self.risk_score.value} "
            f"loops={self.loop_nesting_depth} "
            f"recursion={self.recursion_present} "
            f"flags={len(self.flags)}>"
        )
