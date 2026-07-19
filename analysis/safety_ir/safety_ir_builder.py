"""Builder for compiler-inspired Safety IR focused on safety-relevant properties."""

from __future__ import annotations

import ast
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

from ._model import (
    CapabilityNode,
    CFGBlockNode,
    FunctionNode,
    GraphEdge,
    LoopNode,
    ManifestRoot,
    SourceRef,
    TaintFlowEdge,
)


IR_VERSION = "1.0"
DEFAULT_ANALYSIS_VERSION = "1.0.0"


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _hash_id(prefix: str, payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _contains_line(ref: SourceRef, line: int | None) -> bool:
    if line is None or ref.line is None:
        return False
    if ref.end_line is None:
        return line == ref.line
    return ref.line <= line <= ref.end_line


def _sorted_nodes(nodes: list[Any], *, key_fields: tuple[str, ...]) -> list[Any]:
    def key_fn(obj: Any) -> tuple[Any, ...]:
        d = obj.to_dict()
        return tuple(d.get(k) for k in key_fields)

    return sorted(nodes, key=key_fn)


class _ASTShapeCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]] = []
        self.loops: list[tuple[ast.stmt, int]] = []
        self._loop_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append((node, False))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append((node, True))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.loops.append((node, self._loop_depth))
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._loop_depth += 1
        self.loops.append((node, self._loop_depth))
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.loops.append((node, self._loop_depth))
        self.generic_visit(node)
        self._loop_depth -= 1


def _function_nodes(tree: ast.Module, resource_results: dict[str, Any]) -> list[FunctionNode]:
    recursive_flags = {
        f.get("evidence")
        for f in resource_results.get("flags", [])
        if f.get("kind") == "recursive_no_base"
    }

    collector = _ASTShapeCollector()
    collector.visit(tree)
    nodes: list[FunctionNode] = []

    for fn, is_async in collector.functions:
        src = SourceRef(
            line=getattr(fn, "lineno", None),
            col=getattr(fn, "col_offset", None),
            end_line=getattr(fn, "end_lineno", None),
            end_col=getattr(fn, "end_col_offset", None),
        )
        payload = {
            "name": fn.name,
            "line": src.line,
            "col": src.col,
            "end_line": src.end_line,
            "is_async": is_async,
        }
        node_id = _hash_id("fn", payload)
        nodes.append(
            FunctionNode(
                node_id=node_id,
                name=fn.name,
                is_async=is_async,
                source=src,
                recursion_suspected=fn.name in recursive_flags,
            )
        )

    return _sorted_nodes(nodes, key_fields=("name", "node_id"))


def _loop_nodes(tree: ast.Module, resource_results: dict[str, Any]) -> list[LoopNode]:
    unbounded_locations = {
        (f.get("line"), f.get("col"))
        for f in resource_results.get("flags", [])
        if f.get("kind") in {"while_true", "potentially_unbounded_loop"}
    }

    collector = _ASTShapeCollector()
    collector.visit(tree)

    out: list[LoopNode] = []
    for loop, depth in collector.loops:
        loop_kind = type(loop).__name__
        src = SourceRef(
            line=getattr(loop, "lineno", None),
            col=getattr(loop, "col_offset", None),
            end_line=getattr(loop, "end_lineno", None),
            end_col=getattr(loop, "end_col_offset", None),
        )
        payload = {
            "kind": loop_kind,
            "line": src.line,
            "col": src.col,
            "depth": depth,
            "test": _safe_unparse(loop.test) if isinstance(loop, ast.While) else None,
            "iter": _safe_unparse(loop.iter) if isinstance(loop, (ast.For, ast.AsyncFor)) else None,
        }
        node_id = _hash_id("loop", payload)
        out.append(
            LoopNode(
                node_id=node_id,
                loop_kind=loop_kind,
                nesting_depth=depth,
                source=src,
                potentially_unbounded=(src.line, src.col) in unbounded_locations,
            )
        )

    return sorted(
        out,
        key=lambda n: (
            n.source.line,
            n.source.col,
            n.nesting_depth,
            n.loop_kind,
            n.node_id,
        ),
    )


def _capability_nodes(capability_results: dict[str, Any]) -> list[CapabilityNode]:
    uses: list[dict[str, Any]] = []
    for cap, entries in capability_results.get("by_capability", {}).items():
        for e in entries:
            item = dict(e)
            item["capability_class"] = cap
            uses.append(item)

    uses = sorted(
        uses,
        key=lambda u: (
            u.get("capability_class"),
            u.get("severity"),
            u.get("kind"),
            u.get("symbol"),
            u.get("line"),
            u.get("col"),
        ),
    )

    nodes: list[CapabilityNode] = []
    for use in uses:
        src = SourceRef(line=use.get("line"), col=use.get("col"))
        payload = {
            "cap": use.get("capability_class"),
            "severity": use.get("severity"),
            "symbol": use.get("symbol"),
            "line": use.get("line"),
            "col": use.get("col"),
            "kind": use.get("kind"),
        }
        nodes.append(
            CapabilityNode(
                node_id=_hash_id("cap", payload),
                capability_class=str(use.get("capability_class")),
                severity=str(use.get("severity")),
                symbol=str(use.get("symbol")),
                use_kind=str(use.get("kind")),
                reason=str(use.get("reason", "")),
                source=src,
            )
        )

    return nodes


def _cfg_nodes(cfg_metadata: dict[str, Any]) -> tuple[list[CFGBlockNode], dict[int, str]]:
    raw_blocks = list(cfg_metadata.get("blocks", []))

    indexed: list[tuple[int, dict[str, Any]]] = []
    for b in raw_blocks:
        old_id = int(b.get("id", 0))
        indexed.append((old_id, b))

    # Deterministic order independent of original block ids.
    indexed.sort(
        key=lambda x: (
            x[1].get("kind"),
            x[1].get("label"),
            (x[1].get("lines") or {}).get("start"),
            (x[1].get("lines") or {}).get("end"),
            tuple(x[1].get("stmts", [])),
        )
    )

    nodes: list[CFGBlockNode] = []
    remap: dict[int, str] = {}

    for _, (old_id, block) in enumerate(indexed, start=1):
        lines = block.get("lines") or {}
        payload = {
            "kind": block.get("kind"),
            "label": block.get("label"),
            "start": lines.get("start"),
            "end": lines.get("end"),
            "stmts": block.get("stmts", []),
        }
        node_id = _hash_id("cfg", payload)
        remap[old_id] = node_id
        nodes.append(
            CFGBlockNode(
                node_id=node_id,
                block_kind=str(block.get("kind", "sequence")),
                label=str(block.get("label", "")),
                lines={
                    "start": lines.get("start"),
                    "end": lines.get("end"),
                },
                stmt_count=len(block.get("stmts", [])),
            )
        )

    nodes = sorted(nodes, key=lambda n: (n.block_kind, n.label, n.lines.get("start"), n.node_id))
    return nodes, remap


def _find_capability_sink_node(cap_nodes: list[CapabilityNode], sink: str, sink_line: int | None) -> str:
    for n in cap_nodes:
        if n.symbol == sink and n.source.line == sink_line:
            return n.node_id
    for n in cap_nodes:
        if n.symbol == sink:
            return n.node_id
    return "manifest_root"


def _best_function_for_line(functions: list[FunctionNode], line: int | None) -> str:
    for fn in functions:
        if _contains_line(fn.source, line):
            return fn.node_id
    return "manifest_root"


def _graph_edges(
    *,
    functions: list[FunctionNode],
    loops: list[LoopNode],
    capabilities: list[CapabilityNode],
    cfg_metadata: dict[str, Any],
    cfg_remap: dict[int, str],
) -> list[GraphEdge]:
    edges: list[GraphEdge] = []

    for fn in functions:
        edges.append(GraphEdge(
            edge_id=_hash_id("edge", {"t": "contains", "from": "manifest_root", "to": fn.node_id}),
            edge_type="contains",
            from_node="manifest_root",
            to_node=fn.node_id,
            metadata={},
        ))

    for lp in loops:
        owner = _best_function_for_line(functions, lp.source.line)
        edges.append(GraphEdge(
            edge_id=_hash_id("edge", {"t": "contains", "from": owner, "to": lp.node_id}),
            edge_type="contains",
            from_node=owner,
            to_node=lp.node_id,
            metadata={"relation": "function_loop"},
        ))

    for cap in capabilities:
        owner = _best_function_for_line(functions, cap.source.line)
        edges.append(GraphEdge(
            edge_id=_hash_id("edge", {"t": "observes", "from": owner, "to": cap.node_id}),
            edge_type="observes",
            from_node=owner,
            to_node=cap.node_id,
            metadata={"symbol": cap.symbol},
        ))

    for e in cfg_metadata.get("edges", []):
        from_old = int(e.get("from", -1))
        to_old = int(e.get("to", -1))
        if from_old not in cfg_remap or to_old not in cfg_remap:
            continue
        edges.append(GraphEdge(
            edge_id=_hash_id(
                "edge",
                {"t": "cfg_next", "from": cfg_remap[from_old], "to": cfg_remap[to_old], "label": e.get("label")},
            ),
            edge_type="cfg_next",
            from_node=cfg_remap[from_old],
            to_node=cfg_remap[to_old],
            metadata={"label": e.get("label", "")},
        ))

    return sorted(edges, key=lambda x: (x.edge_type, x.from_node, x.to_node, x.edge_id))


def _taint_edges(
    taint_results: dict[str, Any],
    functions: list[FunctionNode],
    capabilities: list[CapabilityNode],
) -> list[TaintFlowEdge]:
    edges: list[TaintFlowEdge] = []

    findings = list(taint_results.get("findings", []))
    findings = sorted(findings, key=lambda f: (f.get("severity"), f.get("sink"), (f.get("location") or {}).get("line")))

    for idx, finding in enumerate(findings, start=1):
        loc = finding.get("location") or {}
        sink = str(finding.get("sink", ""))
        sink_line = loc.get("line")
        to_node = _find_capability_sink_node(capabilities, sink, sink_line)

        for sidx, src in enumerate(sorted(finding.get("sources", []), key=lambda x: (x.get("kind"), x.get("line"), x.get("expr"))), start=1):
            from_node = _best_function_for_line(functions, src.get("line"))
            payload = {
                "i": idx,
                "j": sidx,
                "from": from_node,
                "to": to_node,
                "sink": sink,
                "severity": finding.get("severity"),
                "source_expr": src.get("expr"),
                "sink_line": sink_line,
            }
            edges.append(
                TaintFlowEdge(
                    edge_id=_hash_id("taint", payload),
                    from_node=from_node,
                    to_node=to_node,
                    sink=sink,
                    severity=str(finding.get("severity", "MEDIUM")),
                    source_expr=str(src.get("expr", "<unknown>")),
                    sink_line=sink_line,
                )
            )

    return sorted(edges, key=lambda e: (e.severity, e.sink, e.sink_line, e.edge_id))


def build_safety_ir(
    *,
    source: str,
    source_name: str,
    taint_results: dict[str, Any],
    capability_results: dict[str, Any],
    resource_results: dict[str, Any],
    cfg_metadata: dict[str, Any],
    execution_policy: ExecutionPolicy | dict[str, Any] | None = None,
    timestamp: str = "1970-01-01T00:00:00Z",
    analysis_version: str = DEFAULT_ANALYSIS_VERSION,
) -> ManifestRoot:
    tree = ast.parse(source, filename=source_name)

    function_nodes = _function_nodes(tree, resource_results)
    loop_nodes = _loop_nodes(tree, resource_results)
    capability_nodes = _capability_nodes(capability_results)
    cfg_nodes, cfg_remap = _cfg_nodes(cfg_metadata)

    taint_edges = _taint_edges(taint_results, function_nodes, capability_nodes)
    graph_edges = _graph_edges(
        functions=function_nodes,
        loops=loop_nodes,
        capabilities=capability_nodes,
        cfg_metadata=cfg_metadata,
        cfg_remap=cfg_remap,
    )

    policies = [ExternalAccessPolicy()]
    if execution_policy is not None:
        policy_obj = execution_policy if isinstance(execution_policy, ExecutionPolicy) else ExecutionPolicy.from_dict(execution_policy)
        policies.append(ExecutionPolicySafetyPolicy(policy_obj))

    decision = SafetyDecisionEngine(policies=policies).evaluate(
        taint_results=taint_results,
        capability_results=capability_results,
        resource_results=resource_results,
    )
    verdict_hint = decision.verdict

    return ManifestRoot(
        source_name=source_name,
        analysis_version=analysis_version,
        timestamp=timestamp,
        ir_version=IR_VERSION,
        verdict_hint=verdict_hint,
        functions=function_nodes,
        loops=loop_nodes,
        capabilities=capability_nodes,
        cfg_blocks=cfg_nodes,
        taint_flows=taint_edges,
        graph_edges=graph_edges,
        metadata={
            "modeling_scope": "safety_relevant_only",
            "full_python_semantics": False,
            "resource_risk": resource_results.get("risk_score", "LOW"),
            "taint_total": int(taint_results.get("total", 0)),
            "capability_total": int((capability_results.get("summary") or {}).get("total_uses", 0)),
            "decision_reasons": decision.reasons,
            "execution_policy": (
                execution_policy.to_dict()
                if isinstance(execution_policy, ExecutionPolicy)
                else execution_policy
            ),
            "cfg_summary": cfg_metadata.get("summary", {}),
        },
    )


def build_safety_ir_from_source(
    source: str,
    *,
    source_name: str = "<string>",
    execution_policy: ExecutionPolicy | dict[str, Any] | None = None,
    timestamp: str = "1970-01-01T00:00:00Z",
    analysis_version: str = DEFAULT_ANALYSIS_VERSION,
) -> ManifestRoot:
    taint_results = taint_to_dict(source)
    capability_results = capability_to_dict(source, name=source_name)
    resource_results = resource_to_dict(source, name=source_name)
    cfg_metadata = build_cfg(source=source, name=source_name).to_dict()

    return build_safety_ir(
        source=source,
        source_name=source_name,
        taint_results=taint_results,
        capability_results=capability_results,
        resource_results=resource_results,
        cfg_metadata=cfg_metadata,
        execution_policy=execution_policy,
        timestamp=timestamp,
        analysis_version=analysis_version,
    )


def safety_ir_to_json(ir: ManifestRoot, *, indent: int = 2) -> str:
    return ir.to_json(indent=indent)
