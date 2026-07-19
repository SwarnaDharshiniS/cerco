"""Safety IR data model for untrusted Python execution analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceRef:
    line: int | None = None
    col: int | None = None
    end_line: int | None = None
    end_col: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclass
class FunctionNode:
    node_id: str
    name: str
    is_async: bool
    source: SourceRef
    recursion_suspected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "FunctionNode",
            "node_id": self.node_id,
            "name": self.name,
            "is_async": self.is_async,
            "recursion_suspected": self.recursion_suspected,
            "source": self.source.to_dict(),
        }


@dataclass
class LoopNode:
    node_id: str
    loop_kind: str
    nesting_depth: int
    source: SourceRef
    potentially_unbounded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "LoopNode",
            "node_id": self.node_id,
            "loop_kind": self.loop_kind,
            "nesting_depth": self.nesting_depth,
            "potentially_unbounded": self.potentially_unbounded,
            "source": self.source.to_dict(),
        }


@dataclass
class CapabilityNode:
    node_id: str
    capability_class: str
    severity: str
    symbol: str
    use_kind: str
    reason: str
    source: SourceRef

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "CapabilityNode",
            "node_id": self.node_id,
            "capability_class": self.capability_class,
            "severity": self.severity,
            "symbol": self.symbol,
            "use_kind": self.use_kind,
            "reason": self.reason,
            "source": self.source.to_dict(),
        }


@dataclass
class CFGBlockNode:
    node_id: str
    block_kind: str
    label: str
    lines: dict[str, int | None]
    stmt_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "CFGBlockNode",
            "node_id": self.node_id,
            "block_kind": self.block_kind,
            "label": self.label,
            "lines": self.lines,
            "stmt_count": self.stmt_count,
        }


@dataclass
class TaintFlowEdge:
    edge_id: str
    from_node: str
    to_node: str
    sink: str
    severity: str
    source_expr: str
    sink_line: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "TaintFlowEdge",
            "edge_id": self.edge_id,
            "from": self.from_node,
            "to": self.to_node,
            "sink": self.sink,
            "severity": self.severity,
            "source_expr": self.source_expr,
            "sink_line": self.sink_line,
        }


@dataclass
class GraphEdge:
    edge_id: str
    edge_type: str
    from_node: str
    to_node: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "from": self.from_node,
            "to": self.to_node,
            "metadata": self.metadata,
        }


@dataclass
class ManifestRoot:
    source_name: str
    analysis_version: str
    timestamp: str
    ir_version: str = "1.0"
    verdict_hint: str = "UNSPECIFIED"
    functions: list[FunctionNode] = field(default_factory=list)
    loops: list[LoopNode] = field(default_factory=list)
    capabilities: list[CapabilityNode] = field(default_factory=list)
    cfg_blocks: list[CFGBlockNode] = field(default_factory=list)
    taint_flows: list[TaintFlowEdge] = field(default_factory=list)
    graph_edges: list[GraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": "ManifestRoot",
            "ir_version": self.ir_version,
            "source_name": self.source_name,
            "analysis_version": self.analysis_version,
            "timestamp": self.timestamp,
            "verdict_hint": self.verdict_hint,
            "nodes": {
                "functions": [n.to_dict() for n in self.functions],
                "loops": [n.to_dict() for n in self.loops],
                "capabilities": [n.to_dict() for n in self.capabilities],
                "cfg_blocks": [n.to_dict() for n in self.cfg_blocks],
            },
            "edges": {
                "taint_flows": [e.to_dict() for e in self.taint_flows],
                "graph": [e.to_dict() for e in self.graph_edges],
            },
            "metadata": self.metadata,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent, ensure_ascii=False)
