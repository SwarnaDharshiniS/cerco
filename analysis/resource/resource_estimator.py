"""
Static resource estimation engine using AST + CFG over-approximations.

The estimator intentionally uses conservative heuristics instead of symbolic
solving. Unknowns are treated as potentially expensive/unbounded where
appropriate.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

try:
    from cfg.cfg_builder import CFGBuilder
except Exception:  # pragma: no cover - optional runtime dependency path
    CFGBuilder = None  # type: ignore[assignment]

from ._model import ResourceFlag, ResourceReport, RiskLevel

LARGE_RANGE_THRESHOLD = 1_000_000
LARGE_ALLOCATION_THRESHOLD = 10_000_000


class ResourceEstimator:
    def __init__(self, source_name: str = "<string>") -> None:
        self._source_name = source_name

    def analyze(self, tree: ast.AST) -> ResourceReport:
        report = ResourceReport(source_name=self._source_name)

        func_defs = self._collect_functions(tree)
        call_graph = self._build_call_graph(func_defs)

        report.loop_nesting_depth = self._max_loop_depth(tree)

        cfg_loop_count = 0
        if CFGBuilder is not None and isinstance(tree, ast.Module):
            cfg_builder = CFGBuilder()
            module_cfg = cfg_builder.build_module(tree, name=self._source_name)
            cfg_loop_count = len(module_cfg.loops())

        recursion_nodes = self._recursive_nodes(call_graph)
        report.recursion_present = bool(recursion_nodes)

        call_depth = self._max_call_depth(call_graph, recursion_nodes)
        report.max_function_call_depth = call_depth

        unbounded = self._find_potentially_unbounded_loops(tree)
        report.potentially_unbounded_loops = bool(unbounded)
        report.flags.extend(unbounded)

        report.flags.extend(self._find_large_ranges(tree))
        report.flags.extend(self._find_suspicious_allocations(tree))

        for name, node in func_defs.items():
            if name in recursion_nodes and not self._has_obvious_base_condition(node):
                report.flags.append(ResourceFlag(
                    kind="recursive_no_base",
                    message=f"Recursive function '{name}' has no obvious base condition",
                    line=getattr(node, "lineno", None),
                    col=getattr(node, "col_offset", None),
                    evidence=name,
                ))

        report.complexity_heuristic = self._complexity_heuristic(
            loop_depth=report.loop_nesting_depth,
            recursion_present=report.recursion_present,
            recursion_without_base=any(f.kind == "recursive_no_base" for f in report.flags),
            cfg_loop_count=cfg_loop_count,
        )

        report.risk_score = self._risk_score(report)
        return report

    def analyze_source(self, source: str) -> ResourceReport:
        tree = ast.parse(source, filename=self._source_name)
        return self.analyze(tree)

    def analyze_file(self, path: str | Path) -> ResourceReport:
        source = Path(path).read_text(encoding="utf-8")
        return self.analyze_source(source)

    def analyze_to_dict(self, source: str) -> dict[str, Any]:
        return self.analyze_source(source).to_dict()

    @staticmethod
    def _collect_functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[node.name] = node
        return funcs

    @staticmethod
    def _build_call_graph(func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]) -> dict[str, set[str]]:
        graph: dict[str, set[str]] = {name: set() for name in func_defs}
        for name, fn in func_defs.items():
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    callee = ResourceEstimator._call_name(node)
                    if callee in func_defs:
                        graph[name].add(callee)
        return graph

    @staticmethod
    def _call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None

    @staticmethod
    def _recursive_nodes(graph: dict[str, set[str]]) -> set[str]:
        recursive: set[str] = set()

        def dfs(start: str, cur: str, seen: set[str]) -> bool:
            for nxt in graph.get(cur, set()):
                if nxt == start:
                    return True
                if nxt in seen:
                    continue
                if dfs(start, nxt, seen | {nxt}):
                    return True
            return False

        for fn in graph:
            if dfs(fn, fn, {fn}):
                recursive.add(fn)
        return recursive

    @staticmethod
    def _max_call_depth(graph: dict[str, set[str]], recursive_nodes: set[str]) -> int:
        memo: dict[str, int] = {}

        def depth(node: str, path: set[str]) -> int:
            if node in memo:
                return memo[node]
            max_child = 0
            for child in graph.get(node, set()):
                if child in path:
                    max_child = max(max_child, 50)
                    continue
                max_child = max(max_child, 1 + depth(child, path | {child}))
            memo[node] = max_child
            return max_child

        base = max((depth(n, {n}) for n in graph), default=0)
        if recursive_nodes:
            return max(base, 50)
        return base

    @staticmethod
    def _max_loop_depth(tree: ast.AST) -> int:
        max_depth = 0

        def walk(node: ast.AST, depth: int) -> None:
            nonlocal max_depth
            is_loop = isinstance(node, (ast.For, ast.AsyncFor, ast.While))
            next_depth = depth + 1 if is_loop else depth
            max_depth = max(max_depth, next_depth)
            for child in ast.iter_child_nodes(node):
                walk(child, next_depth)

        walk(tree, 0)
        return max_depth

    def _find_potentially_unbounded_loops(self, tree: ast.AST) -> list[ResourceFlag]:
        flags: list[ResourceFlag] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.While):
                continue

            if isinstance(node.test, ast.Constant) and node.test.value is True:
                flags.append(ResourceFlag(
                    kind="while_true",
                    message="Detected while True loop",
                    line=node.lineno,
                    col=node.col_offset,
                    evidence="while True",
                ))
                continue

            if not self._has_obvious_loop_bound(node):
                flags.append(ResourceFlag(
                    kind="potentially_unbounded_loop",
                    message="While loop may be unbounded",
                    line=node.lineno,
                    col=node.col_offset,
                    evidence=self._safe_unparse(node.test),
                ))
        return flags

    @staticmethod
    def _has_obvious_loop_bound(node: ast.While) -> bool:
        test = node.test
        if isinstance(test, ast.Compare):
            return any(isinstance(comp, ast.Constant) for comp in test.comparators)
        return False

    def _find_large_ranges(self, tree: ast.AST) -> list[ResourceFlag]:
        flags: list[ResourceFlag] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._call_name(node) == "range":
                if any(self._expr_large_constant(arg) for arg in node.args):
                    flags.append(ResourceFlag(
                        kind="large_range",
                        message=f"range() may iterate over very large bounds (>{LARGE_RANGE_THRESHOLD})",
                        line=node.lineno,
                        col=node.col_offset,
                        evidence=self._safe_unparse(node),
                    ))
        return flags

    def _find_suspicious_allocations(self, tree: ast.AST) -> list[ResourceFlag]:
        flags: list[ResourceFlag] = []
        alloc_calls = {
            "list", "dict", "set", "tuple", "bytearray", "bytes",
            "array", "numpy.zeros", "numpy.ones", "numpy.empty",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                qname = self._call_qname(node)
                if qname in alloc_calls and any(self._expr_huge_size(arg) for arg in node.args):
                    flags.append(ResourceFlag(
                        kind="suspicious_allocation",
                        message="Potential large allocation detected",
                        line=node.lineno,
                        col=node.col_offset,
                        evidence=self._safe_unparse(node),
                    ))
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                if self._is_large_replication(node):
                    flags.append(ResourceFlag(
                        kind="suspicious_allocation",
                        message="Large sequence/string replication may allocate excessive memory",
                        line=node.lineno,
                        col=node.col_offset,
                        evidence=self._safe_unparse(node),
                    ))

        return flags

    @staticmethod
    def _is_large_replication(node: ast.BinOp) -> bool:
        left_seq = isinstance(node.left, (ast.List, ast.Tuple, ast.Constant, ast.Set))
        right_seq = isinstance(node.right, (ast.List, ast.Tuple, ast.Constant, ast.Set))
        left_num = isinstance(node.left, ast.Constant) and isinstance(node.left.value, int)
        right_num = isinstance(node.right, ast.Constant) and isinstance(node.right.value, int)

        if left_seq and right_num and isinstance(node.right.value, int):
            return node.right.value >= LARGE_ALLOCATION_THRESHOLD
        if right_seq and left_num and isinstance(node.left.value, int):
            return node.left.value >= LARGE_ALLOCATION_THRESHOLD
        return False

    @staticmethod
    def _expr_large_constant(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, int) and node.value >= LARGE_RANGE_THRESHOLD

    @staticmethod
    def _expr_huge_size(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value >= LARGE_ALLOCATION_THRESHOLD
        if isinstance(node, ast.Tuple):
            prod = 1
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, int) and elt.value > 0:
                    prod *= elt.value
                    if prod >= LARGE_ALLOCATION_THRESHOLD:
                        return True
                else:
                    return False
        return False

    @staticmethod
    def _has_obvious_base_condition(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        arg_names = {a.arg for a in fn.args.args}
        if not arg_names:
            return False

        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            if not isinstance(node.test, ast.Compare):
                continue

            left_mentions_arg = any(isinstance(n, ast.Name) and n.id in arg_names for n in ast.walk(node.test.left))
            right_has_const = any(isinstance(comp, ast.Constant) for comp in node.test.comparators)
            has_return = any(isinstance(s, ast.Return) for s in node.body + node.orelse)
            if left_mentions_arg and right_has_const and has_return:
                return True

        return False

    @staticmethod
    def _complexity_heuristic(
        *,
        loop_depth: int,
        recursion_present: bool,
        recursion_without_base: bool,
        cfg_loop_count: int,
    ) -> str:
        if recursion_present and recursion_without_base:
            return "Potentially unbounded / exponential"
        if recursion_present and loop_depth >= 1:
            return "At least O(n^2) (recursion + loops)"
        if recursion_present:
            return "At least O(n) (recursive)"
        if loop_depth <= 0 and cfg_loop_count == 0:
            return "O(1)"
        if loop_depth == 1:
            return "O(n)"
        if loop_depth == 2:
            return "O(n^2)"
        return f"O(n^{loop_depth})"

    @staticmethod
    def _risk_score(report: ResourceReport) -> RiskLevel:
        score = 0
        score += 3 * sum(1 for f in report.flags if f.kind in {"while_true", "recursive_no_base"})
        score += 3 * sum(1 for f in report.flags if f.kind in {"large_range", "potentially_unbounded_loop"})
        score += 2 * sum(1 for f in report.flags if f.kind == "suspicious_allocation")

        if report.loop_nesting_depth >= 3:
            score += 2
        elif report.loop_nesting_depth == 2:
            score += 1

        if report.max_function_call_depth >= 20:
            score += 2
        elif report.max_function_call_depth >= 8:
            score += 1

        if score >= 8:
            return RiskLevel.HIGH
        if score >= 3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _call_qname(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
        ):
            return f"{func.value.value.id}.{func.value.attr}.{func.attr}"
        return None

    @staticmethod
    def _safe_unparse(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return type(node).__name__


def analyze_source(source: str, name: str = "<string>") -> ResourceReport:
    return ResourceEstimator(source_name=name).analyze_source(source)


def analyze_file(path: str | Path) -> ResourceReport:
    path = Path(path)
    return ResourceEstimator(source_name=str(path)).analyze_file(path)


def analyze_to_dict(source: str, name: str = "<string>") -> dict[str, Any]:
    return analyze_source(source, name=name).to_dict()
